package quic

import (
	"crypto/rand"
	"net"
	"slices"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type pathID int64

const invalidPathID pathID = -1

// Maximum number of paths to keep track of.
// If the peer probes another path (before the pathTimeout of an existing path expires),
// this probing attempt is ignored.
const maxPaths = 3

// If no packet is received for a path for pathTimeout,
// the path can be evicted when the peer probes another path.
// This prevents an attacker from churning through paths by duplicating packets and
// sending them with spoofed source addresses.
const pathTimeout = 5 * time.Second

type path struct {
	id             pathID
	addr           net.Addr
	lastPacketTime monotime.Time
	pathChallenges [][8]byte // length is implicitly limited by exponential backoff
	nextProbeTime  monotime.Time
	validated      bool
	rcvdNonProbing bool
}

type pathManager struct {
	nextPathID pathID
	// ordered by lastPacketTime, with the most recently used path at the end
	paths []*path

	getConnID    func(pathID) (_ protocol.ConnectionID, ok bool)
	retireConnID func(pathID)

	logger utils.Logger
}

func newPathManager(
	getConnID func(pathID) (_ protocol.ConnectionID, ok bool),
	retireConnID func(pathID),
	logger utils.Logger,
) *pathManager {
	return &pathManager{
		paths:        make([]*path, 0, maxPaths+1),
		getConnID:    getConnID,
		retireConnID: retireConnID,
		logger:       logger,
	}
}

// Returns a path challenge frame if one should be sent.
// May return nil.
func (pm *pathManager) HandlePacket(
	remoteAddr net.Addr,
	t monotime.Time,
	pathChallenge *wire.PathChallengeFrame, // may be nil if the packet didn't contain a PATH_CHALLENGE
	isNonProbing bool,
) (_ protocol.ConnectionID, _ []ackhandler.Frame, shouldSwitch bool) {
	var p *path
	for i, path := range pm.paths {
		if addrsEqual(path.addr, remoteAddr) {
			p = path
			p.lastPacketTime = t
			if isNonProbing {
				path.rcvdNonProbing = true
			}
			if pm.logger.Debug() {
				pm.logger.Debugf("received packet for path %s that was already probed, validated: %t", remoteAddr, path.validated)
			}
			shouldSwitch = path.validated && path.rcvdNonProbing
			if i != len(pm.paths)-1 {
				// move the path to the end of the list
				pm.paths = slices.Delete(pm.paths, i, i+1)
				pm.paths = append(pm.paths, p)
			}
			// Nothing to send:
			// * the packet didn't contain a PATH_CHALLENGE, and
			// * the path does not need a probe (already validated, or still inside the backoff).
			if pathChallenge == nil && (path.validated || t.Before(path.nextProbeTime)) {
				return protocol.ConnectionID{}, nil, shouldSwitch
			}
			break
		}
	}

	// new path while already at maxPaths
	if p == nil && len(pm.paths) >= maxPaths {
		// ignore it if the oldest path received a packet within pathTimeout
		if pm.paths[0].lastPacketTime.Add(pathTimeout).After(t) {
			if pm.logger.Debug() {
				pm.logger.Debugf("received packet for previously unseen path %s, but already have %d paths", remoteAddr, len(pm.paths))
			}
			return protocol.ConnectionID{}, nil, shouldSwitch
		}
		// evict the oldest path, if the last packet was received more than pathTimeout ago
		pm.retireConnID(pm.paths[0].id)
		pm.paths = pm.paths[1:]
	}

	var pathID pathID
	if p != nil {
		pathID = p.id
	} else {
		pathID = pm.nextPathID
	}

	connID, ok := pm.getConnID(pathID)
	if !ok {
		pm.logger.Debugf("skipping validation of new path %s since no connection ID is available", remoteAddr)
		return protocol.ConnectionID{}, nil, shouldSwitch
	}

	if p == nil {
		p = &path{
			id:             pm.nextPathID,
			addr:           remoteAddr,
			lastPacketTime: t,
			rcvdNonProbing: isNonProbing,
			nextProbeTime:  t,
			pathChallenges: make([][8]byte, 0, 2),
		}
		pm.nextPathID++
		pm.paths = append(pm.paths, p)
	}

	frames := make([]ackhandler.Frame, 0, 2)
	// Probe an unvalidated path with a new PATH_CHALLENGE:
	// * sent on the next packet once nextProbeTime has passed, and
	// * repeated until a PATH_RESPONSE arrives, ignoring ACKs and loss.
	if !p.validated && !t.Before(p.nextProbeTime) {
		backoffFactor := 1 << len(p.pathChallenges)
		p.nextProbeTime = t.Add(utils.DefaultInitialRTT * time.Duration(backoffFactor))
		var b [8]byte
		rand.Read(b[:])
		p.pathChallenges = append(p.pathChallenges, b)
		frames = append(frames, ackhandler.Frame{
			Frame:   &wire.PathChallengeFrame{Data: b},
			Handler: emptyHandler{},
		})
		pm.logger.Debugf("enqueueing PATH_CHALLENGE for new path %s", remoteAddr)
	}
	if pathChallenge != nil {
		frames = append(frames, ackhandler.Frame{
			Frame:   &wire.PathResponseFrame{Data: pathChallenge.Data},
			Handler: emptyHandler{},
		})
	}
	return connID, frames, shouldSwitch
}

func (pm *pathManager) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	for _, p := range pm.paths {
		if slices.Contains(p.pathChallenges, f.Data) {
			// path validated
			p.validated = true
			p.pathChallenges = nil
			pm.logger.Debugf("path %s validated", p.addr)
			break
		}
	}
}

// SwitchToPath is called when the connection switches to a new path
func (pm *pathManager) SwitchToPath(addr net.Addr) {
	// retire all other paths
	for _, path := range pm.paths {
		if addrsEqual(path.addr, addr) {
			pm.logger.Debugf("switching to path %d (%s)", path.id, addr)
			continue
		}
		pm.retireConnID(path.id)
	}
	clear(pm.paths)
	pm.paths = pm.paths[:0]
}

func addrsEqual(addr1, addr2 net.Addr) bool {
	if addr1 == nil || addr2 == nil {
		return false
	}
	a1, ok1 := addr1.(*net.UDPAddr)
	a2, ok2 := addr2.(*net.UDPAddr)
	if ok1 && ok2 {
		return a1.IP.Equal(a2.IP) && a1.Port == a2.Port
	}
	return addr1.String() == addr2.String()
}
