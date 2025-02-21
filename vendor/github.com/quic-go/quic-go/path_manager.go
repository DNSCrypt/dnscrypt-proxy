package quic

import (
	"crypto/rand"
	"net"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type pathID int64

const maxPaths = 3

type path struct {
	addr           net.Addr
	pathChallenge  [8]byte
	validated      bool
	rcvdNonProbing bool
}

type pathManager struct {
	nextPathID pathID
	paths      map[pathID]*path

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
		paths:        make(map[pathID]*path),
		getConnID:    getConnID,
		retireConnID: retireConnID,
		logger:       logger,
	}
}

// Returns a path challenge frame if one should be sent.
// May return nil.
func (pm *pathManager) HandlePacket(p receivedPacket, isNonProbing bool) (_ protocol.ConnectionID, _ ackhandler.Frame, shouldSwitch bool) {
	for _, path := range pm.paths {
		if addrsEqual(path.addr, p.remoteAddr) {
			// already sent a PATH_CHALLENGE for this path
			if isNonProbing {
				path.rcvdNonProbing = true
			}
			if pm.logger.Debug() {
				pm.logger.Debugf("received packet for path %s that was already probed, validated: %t", p.remoteAddr, path.validated)
			}
			return protocol.ConnectionID{}, ackhandler.Frame{}, path.validated && path.rcvdNonProbing
		}
	}

	if len(pm.paths) >= maxPaths {
		if pm.logger.Debug() {
			pm.logger.Debugf("received packet for previously unseen path %s, but already have %d paths", p.remoteAddr, len(pm.paths))
		}
		return protocol.ConnectionID{}, ackhandler.Frame{}, false
	}

	// previously unseen path, initiate path validation by sending a PATH_CHALLENGE
	connID, ok := pm.getConnID(pm.nextPathID)
	if !ok {
		pm.logger.Debugf("skipping validation of new path %s since no connection ID is available", p.remoteAddr)
		return protocol.ConnectionID{}, ackhandler.Frame{}, false
	}
	var b [8]byte
	rand.Read(b[:])
	pm.paths[pm.nextPathID] = &path{
		addr:           p.remoteAddr,
		pathChallenge:  b,
		rcvdNonProbing: isNonProbing,
	}
	pm.nextPathID++
	frame := ackhandler.Frame{
		Frame:   &wire.PathChallengeFrame{Data: b},
		Handler: (*pathManagerAckHandler)(pm),
	}
	pm.logger.Debugf("enqueueing PATH_CHALLENGE for new path %s", p.remoteAddr)
	return connID, frame, false
}

func (pm *pathManager) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	for _, p := range pm.paths {
		if f.Data == p.pathChallenge {
			// path validated
			p.validated = true
			pm.logger.Debugf("path %s validated", p.addr)
			break
		}
	}
}

// SwitchToPath is called when the connection switches to a new path
func (pm *pathManager) SwitchToPath(addr net.Addr) {
	// retire all other paths
	for id := range pm.paths {
		if addrsEqual(pm.paths[id].addr, addr) {
			pm.logger.Debugf("switching to path %d (%s)", id, addr)
			continue
		}
		pm.retireConnID(id)
	}
	clear(pm.paths)
}

type pathManagerAckHandler pathManager

var _ ackhandler.FrameHandler = &pathManagerAckHandler{}

// Acknowledging the frame doesn't validate the path, only receiving the PATH_RESPONSE does.
func (pm *pathManagerAckHandler) OnAcked(f wire.Frame) {}

func (pm *pathManagerAckHandler) OnLost(f wire.Frame) {
	// TODO: retransmit the packet the first time it is lost
	pc := f.(*wire.PathChallengeFrame)
	for id, path := range pm.paths {
		if path.pathChallenge == pc.Data {
			delete(pm.paths, id)
			pm.retireConnID(id)
			break
		}
	}
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
