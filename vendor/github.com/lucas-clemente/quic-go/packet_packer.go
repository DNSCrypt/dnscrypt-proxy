package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type packer interface {
	PackCoalescedPacket(onlyAck bool) (*coalescedPacket, error)
	PackPacket(onlyAck bool) (*packedPacket, error)
	MaybePackProbePacket(protocol.EncryptionLevel) (*packedPacket, error)
	PackConnectionClose(*qerr.TransportError) (*coalescedPacket, error)
	PackApplicationClose(*qerr.ApplicationError) (*coalescedPacket, error)

	SetMaxPacketSize(protocol.ByteCount)
	PackMTUProbePacket(ping ackhandler.Frame, size protocol.ByteCount) (*packedPacket, error)

	HandleTransportParameters(*wire.TransportParameters)
	SetToken([]byte)
}

type sealer interface {
	handshake.LongHeaderSealer
}

type payload struct {
	frames []ackhandler.Frame
	ack    *wire.AckFrame
	length protocol.ByteCount
}

type packedPacket struct {
	buffer *packetBuffer
	*packetContents
}

type packetContents struct {
	header *wire.ExtendedHeader
	ack    *wire.AckFrame
	frames []ackhandler.Frame

	length protocol.ByteCount

	isMTUProbePacket bool
}

type coalescedPacket struct {
	buffer  *packetBuffer
	packets []*packetContents
}

func (p *packetContents) EncryptionLevel() protocol.EncryptionLevel {
	if !p.header.IsLongHeader {
		return protocol.Encryption1RTT
	}
	//nolint:exhaustive // Will never be called for Retry packets (and they don't have encrypted data).
	switch p.header.Type {
	case protocol.PacketTypeInitial:
		return protocol.EncryptionInitial
	case protocol.PacketTypeHandshake:
		return protocol.EncryptionHandshake
	case protocol.PacketType0RTT:
		return protocol.Encryption0RTT
	default:
		panic("can't determine encryption level")
	}
}

func (p *packetContents) IsAckEliciting() bool {
	return ackhandler.HasAckElicitingFrames(p.frames)
}

func (p *packetContents) ToAckHandlerPacket(now time.Time, q *retransmissionQueue) *ackhandler.Packet {
	largestAcked := protocol.InvalidPacketNumber
	if p.ack != nil {
		largestAcked = p.ack.LargestAcked()
	}
	encLevel := p.EncryptionLevel()
	for i := range p.frames {
		if p.frames[i].OnLost != nil {
			continue
		}
		switch encLevel {
		case protocol.EncryptionInitial:
			p.frames[i].OnLost = q.AddInitial
		case protocol.EncryptionHandshake:
			p.frames[i].OnLost = q.AddHandshake
		case protocol.Encryption0RTT, protocol.Encryption1RTT:
			p.frames[i].OnLost = q.AddAppData
		}
	}

	ap := ackhandler.GetPacket()
	ap.PacketNumber = p.header.PacketNumber
	ap.LargestAcked = largestAcked
	ap.Frames = p.frames
	ap.Length = p.length
	ap.EncryptionLevel = encLevel
	ap.SendTime = now
	ap.IsPathMTUProbePacket = p.isMTUProbePacket
	return ap
}

func getMaxPacketSize(addr net.Addr) protocol.ByteCount {
	maxSize := protocol.ByteCount(protocol.MinInitialPacketSize)
	// If this is not a UDP address, we don't know anything about the MTU.
	// Use the minimum size of an Initial packet as the max packet size.
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if utils.IsIPv4(udpAddr.IP) {
			maxSize = protocol.InitialPacketSizeIPv4
		} else {
			maxSize = protocol.InitialPacketSizeIPv6
		}
	}
	return maxSize
}

type packetNumberManager interface {
	PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber
}

type sealingManager interface {
	GetInitialSealer() (handshake.LongHeaderSealer, error)
	GetHandshakeSealer() (handshake.LongHeaderSealer, error)
	Get0RTTSealer() (handshake.LongHeaderSealer, error)
	Get1RTTSealer() (handshake.ShortHeaderSealer, error)
}

type frameSource interface {
	HasData() bool
	AppendStreamFrames([]ackhandler.Frame, protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount)
	AppendControlFrames([]ackhandler.Frame, protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount)
}

type ackFrameSource interface {
	GetAckFrame(encLevel protocol.EncryptionLevel, onlyIfQueued bool) *wire.AckFrame
}

type packetPacker struct {
	srcConnID     protocol.ConnectionID
	getDestConnID func() protocol.ConnectionID

	perspective protocol.Perspective
	version     protocol.VersionNumber
	cryptoSetup sealingManager

	initialStream   cryptoStream
	handshakeStream cryptoStream

	token []byte

	pnManager           packetNumberManager
	framer              frameSource
	acks                ackFrameSource
	datagramQueue       *datagramQueue
	retransmissionQueue *retransmissionQueue

	maxPacketSize          protocol.ByteCount
	numNonAckElicitingAcks int
}

var _ packer = &packetPacker{}

func newPacketPacker(
	srcConnID protocol.ConnectionID,
	getDestConnID func() protocol.ConnectionID,
	initialStream cryptoStream,
	handshakeStream cryptoStream,
	packetNumberManager packetNumberManager,
	retransmissionQueue *retransmissionQueue,
	remoteAddr net.Addr, // only used for determining the max packet size
	cryptoSetup sealingManager,
	framer frameSource,
	acks ackFrameSource,
	datagramQueue *datagramQueue,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
) *packetPacker {
	return &packetPacker{
		cryptoSetup:         cryptoSetup,
		getDestConnID:       getDestConnID,
		srcConnID:           srcConnID,
		initialStream:       initialStream,
		handshakeStream:     handshakeStream,
		retransmissionQueue: retransmissionQueue,
		datagramQueue:       datagramQueue,
		perspective:         perspective,
		version:             version,
		framer:              framer,
		acks:                acks,
		pnManager:           packetNumberManager,
		maxPacketSize:       getMaxPacketSize(remoteAddr),
	}
}

// PackConnectionClose packs a packet that closes the connection with a transport error.
func (p *packetPacker) PackConnectionClose(e *qerr.TransportError) (*coalescedPacket, error) {
	var reason string
	// don't send details of crypto errors
	if !e.ErrorCode.IsCryptoError() {
		reason = e.ErrorMessage
	}
	return p.packConnectionClose(false, uint64(e.ErrorCode), e.FrameType, reason)
}

// PackApplicationClose packs a packet that closes the connection with an application error.
func (p *packetPacker) PackApplicationClose(e *qerr.ApplicationError) (*coalescedPacket, error) {
	return p.packConnectionClose(true, uint64(e.ErrorCode), 0, e.ErrorMessage)
}

func (p *packetPacker) packConnectionClose(
	isApplicationError bool,
	errorCode uint64,
	frameType uint64,
	reason string,
) (*coalescedPacket, error) {
	var sealers [4]sealer
	var hdrs [4]*wire.ExtendedHeader
	var payloads [4]*payload
	var size protocol.ByteCount
	var numPackets uint8
	encLevels := [4]protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT, protocol.Encryption1RTT}
	for i, encLevel := range encLevels {
		if p.perspective == protocol.PerspectiveServer && encLevel == protocol.Encryption0RTT {
			continue
		}
		ccf := &wire.ConnectionCloseFrame{
			IsApplicationError: isApplicationError,
			ErrorCode:          errorCode,
			FrameType:          frameType,
			ReasonPhrase:       reason,
		}
		// don't send application errors in Initial or Handshake packets
		if isApplicationError && (encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake) {
			ccf.IsApplicationError = false
			ccf.ErrorCode = uint64(qerr.ApplicationErrorErrorCode)
			ccf.ReasonPhrase = ""
		}
		payload := &payload{
			frames: []ackhandler.Frame{{Frame: ccf}},
			length: ccf.Length(p.version),
		}

		var sealer sealer
		var err error
		var keyPhase protocol.KeyPhaseBit // only set for 1-RTT
		switch encLevel {
		case protocol.EncryptionInitial:
			sealer, err = p.cryptoSetup.GetInitialSealer()
		case protocol.EncryptionHandshake:
			sealer, err = p.cryptoSetup.GetHandshakeSealer()
		case protocol.Encryption0RTT:
			sealer, err = p.cryptoSetup.Get0RTTSealer()
		case protocol.Encryption1RTT:
			var s handshake.ShortHeaderSealer
			s, err = p.cryptoSetup.Get1RTTSealer()
			if err == nil {
				keyPhase = s.KeyPhase()
			}
			sealer = s
		}
		if err == handshake.ErrKeysNotYetAvailable || err == handshake.ErrKeysDropped {
			continue
		}
		if err != nil {
			return nil, err
		}
		sealers[i] = sealer
		var hdr *wire.ExtendedHeader
		if encLevel == protocol.Encryption1RTT {
			hdr = p.getShortHeader(keyPhase)
		} else {
			hdr = p.getLongHeader(encLevel)
		}
		hdrs[i] = hdr
		payloads[i] = payload
		size += p.packetLength(hdr, payload) + protocol.ByteCount(sealer.Overhead())
		numPackets++
	}
	contents := make([]*packetContents, 0, numPackets)
	buffer := getPacketBuffer()
	for i, encLevel := range encLevels {
		if sealers[i] == nil {
			continue
		}
		var paddingLen protocol.ByteCount
		if encLevel == protocol.EncryptionInitial {
			paddingLen = p.initialPaddingLen(payloads[i].frames, size)
		}
		c, err := p.appendPacket(buffer, hdrs[i], payloads[i], paddingLen, encLevel, sealers[i], false)
		if err != nil {
			return nil, err
		}
		contents = append(contents, c)
	}
	return &coalescedPacket{buffer: buffer, packets: contents}, nil
}

// packetLength calculates the length of the serialized packet.
// It takes into account that packets that have a tiny payload need to be padded,
// such that len(payload) + packet number len >= 4 + AEAD overhead
func (p *packetPacker) packetLength(hdr *wire.ExtendedHeader, payload *payload) protocol.ByteCount {
	var paddingLen protocol.ByteCount
	pnLen := protocol.ByteCount(hdr.PacketNumberLen)
	if payload.length < 4-pnLen {
		paddingLen = 4 - pnLen - payload.length
	}
	return hdr.GetLength(p.version) + payload.length + paddingLen
}

// size is the expected size of the packet, if no padding was applied.
func (p *packetPacker) initialPaddingLen(frames []ackhandler.Frame, size protocol.ByteCount) protocol.ByteCount {
	// For the server, only ack-eliciting Initial packets need to be padded.
	if p.perspective == protocol.PerspectiveServer && !ackhandler.HasAckElicitingFrames(frames) {
		return 0
	}
	if size >= p.maxPacketSize {
		return 0
	}
	return p.maxPacketSize - size
}

// PackCoalescedPacket packs a new packet.
// It packs an Initial / Handshake if there is data to send in these packet number spaces.
// It should only be called before the handshake is confirmed.
func (p *packetPacker) PackCoalescedPacket(onlyAck bool) (*coalescedPacket, error) {
	maxPacketSize := p.maxPacketSize
	if p.perspective == protocol.PerspectiveClient {
		maxPacketSize = protocol.MinInitialPacketSize
	}
	var initialHdr, handshakeHdr, appDataHdr *wire.ExtendedHeader
	var initialPayload, handshakePayload, appDataPayload *payload
	var numPackets int
	// Try packing an Initial packet.
	initialSealer, err := p.cryptoSetup.GetInitialSealer()
	if err != nil && err != handshake.ErrKeysDropped {
		return nil, err
	}
	var size protocol.ByteCount
	if initialSealer != nil {
		initialHdr, initialPayload = p.maybeGetCryptoPacket(maxPacketSize-protocol.ByteCount(initialSealer.Overhead()), protocol.EncryptionInitial, onlyAck, true)
		if initialPayload != nil {
			size += p.packetLength(initialHdr, initialPayload) + protocol.ByteCount(initialSealer.Overhead())
			numPackets++
		}
	}

	// Add a Handshake packet.
	var handshakeSealer sealer
	if (onlyAck && size == 0) || (!onlyAck && size < maxPacketSize-protocol.MinCoalescedPacketSize) {
		var err error
		handshakeSealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if handshakeSealer != nil {
			handshakeHdr, handshakePayload = p.maybeGetCryptoPacket(maxPacketSize-size-protocol.ByteCount(handshakeSealer.Overhead()), protocol.EncryptionHandshake, onlyAck, size == 0)
			if handshakePayload != nil {
				s := p.packetLength(handshakeHdr, handshakePayload) + protocol.ByteCount(handshakeSealer.Overhead())
				size += s
				numPackets++
			}
		}
	}

	// Add a 0-RTT / 1-RTT packet.
	var appDataSealer sealer
	appDataEncLevel := protocol.Encryption1RTT
	if (onlyAck && size == 0) || (!onlyAck && size < maxPacketSize-protocol.MinCoalescedPacketSize) {
		var sErr error
		var oneRTTSealer handshake.ShortHeaderSealer
		oneRTTSealer, sErr = p.cryptoSetup.Get1RTTSealer()
		appDataSealer = oneRTTSealer
		if sErr != nil && p.perspective == protocol.PerspectiveClient {
			appDataSealer, sErr = p.cryptoSetup.Get0RTTSealer()
			appDataEncLevel = protocol.Encryption0RTT
		}
		if appDataSealer != nil && sErr == nil {
			//nolint:exhaustive // 0-RTT and 1-RTT are the only two application data encryption levels.
			switch appDataEncLevel {
			case protocol.Encryption0RTT:
				appDataHdr, appDataPayload = p.maybeGetAppDataPacketFor0RTT(appDataSealer, maxPacketSize-size)
			case protocol.Encryption1RTT:
				appDataHdr, appDataPayload = p.maybeGetShortHeaderPacket(oneRTTSealer, maxPacketSize-size, onlyAck, size == 0)
			}
			if appDataHdr != nil && appDataPayload != nil {
				size += p.packetLength(appDataHdr, appDataPayload) + protocol.ByteCount(appDataSealer.Overhead())
				numPackets++
			}
		}
	}

	if numPackets == 0 {
		return nil, nil
	}

	buffer := getPacketBuffer()
	packet := &coalescedPacket{
		buffer:  buffer,
		packets: make([]*packetContents, 0, numPackets),
	}
	if initialPayload != nil {
		padding := p.initialPaddingLen(initialPayload.frames, size)
		cont, err := p.appendPacket(buffer, initialHdr, initialPayload, padding, protocol.EncryptionInitial, initialSealer, false)
		if err != nil {
			return nil, err
		}
		packet.packets = append(packet.packets, cont)
	}
	if handshakePayload != nil {
		cont, err := p.appendPacket(buffer, handshakeHdr, handshakePayload, 0, protocol.EncryptionHandshake, handshakeSealer, false)
		if err != nil {
			return nil, err
		}
		packet.packets = append(packet.packets, cont)
	}
	if appDataPayload != nil {
		cont, err := p.appendPacket(buffer, appDataHdr, appDataPayload, 0, appDataEncLevel, appDataSealer, false)
		if err != nil {
			return nil, err
		}
		packet.packets = append(packet.packets, cont)
	}
	return packet, nil
}

// PackPacket packs a packet in the application data packet number space.
// It should be called after the handshake is confirmed.
func (p *packetPacker) PackPacket(onlyAck bool) (*packedPacket, error) {
	sealer, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return nil, err
	}
	hdr, payload := p.maybeGetShortHeaderPacket(sealer, p.maxPacketSize, onlyAck, true)
	if payload == nil {
		return nil, nil
	}
	buffer := getPacketBuffer()
	cont, err := p.appendPacket(buffer, hdr, payload, 0, protocol.Encryption1RTT, sealer, false)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		buffer:         buffer,
		packetContents: cont,
	}, nil
}

func (p *packetPacker) maybeGetCryptoPacket(maxPacketSize protocol.ByteCount, encLevel protocol.EncryptionLevel, onlyAck, ackAllowed bool) (*wire.ExtendedHeader, *payload) {
	if onlyAck {
		if ack := p.acks.GetAckFrame(encLevel, true); ack != nil {
			var payload payload
			payload.ack = ack
			payload.length = ack.Length(p.version)
			return p.getLongHeader(encLevel), &payload
		}
		return nil, nil
	}

	var s cryptoStream
	var hasRetransmission bool
	//nolint:exhaustive // Initial and Handshake are the only two encryption levels here.
	switch encLevel {
	case protocol.EncryptionInitial:
		s = p.initialStream
		hasRetransmission = p.retransmissionQueue.HasInitialData()
	case protocol.EncryptionHandshake:
		s = p.handshakeStream
		hasRetransmission = p.retransmissionQueue.HasHandshakeData()
	}

	hasData := s.HasData()
	var ack *wire.AckFrame
	if ackAllowed {
		ack = p.acks.GetAckFrame(encLevel, !hasRetransmission && !hasData)
	}
	if !hasData && !hasRetransmission && ack == nil {
		// nothing to send
		return nil, nil
	}

	var payload payload
	if ack != nil {
		payload.ack = ack
		payload.length = ack.Length(p.version)
		maxPacketSize -= payload.length
	}
	hdr := p.getLongHeader(encLevel)
	maxPacketSize -= hdr.GetLength(p.version)
	if hasRetransmission {
		for {
			var f wire.Frame
			//nolint:exhaustive // 0-RTT packets can't contain any retransmission.s
			switch encLevel {
			case protocol.EncryptionInitial:
				f = p.retransmissionQueue.GetInitialFrame(maxPacketSize)
			case protocol.EncryptionHandshake:
				f = p.retransmissionQueue.GetHandshakeFrame(maxPacketSize)
			}
			if f == nil {
				break
			}
			payload.frames = append(payload.frames, ackhandler.Frame{Frame: f})
			frameLen := f.Length(p.version)
			payload.length += frameLen
			maxPacketSize -= frameLen
		}
	} else if s.HasData() {
		cf := s.PopCryptoFrame(maxPacketSize)
		payload.frames = []ackhandler.Frame{{Frame: cf}}
		payload.length += cf.Length(p.version)
	}
	return hdr, &payload
}

func (p *packetPacker) maybeGetAppDataPacketFor0RTT(sealer sealer, maxPacketSize protocol.ByteCount) (*wire.ExtendedHeader, *payload) {
	if p.perspective != protocol.PerspectiveClient {
		return nil, nil
	}

	hdr := p.getLongHeader(protocol.Encryption0RTT)
	maxPayloadSize := maxPacketSize - hdr.GetLength(p.version) - protocol.ByteCount(sealer.Overhead())
	payload := p.maybeGetAppDataPacket(maxPayloadSize, false, false)
	return hdr, payload
}

func (p *packetPacker) maybeGetShortHeaderPacket(sealer handshake.ShortHeaderSealer, maxPacketSize protocol.ByteCount, onlyAck, ackAllowed bool) (*wire.ExtendedHeader, *payload) {
	hdr := p.getShortHeader(sealer.KeyPhase())
	maxPayloadSize := maxPacketSize - hdr.GetLength(p.version) - protocol.ByteCount(sealer.Overhead())
	payload := p.maybeGetAppDataPacket(maxPayloadSize, onlyAck, ackAllowed)
	return hdr, payload
}

func (p *packetPacker) maybeGetAppDataPacket(maxPayloadSize protocol.ByteCount, onlyAck, ackAllowed bool) *payload {
	payload := p.composeNextPacket(maxPayloadSize, onlyAck, ackAllowed)

	// check if we have anything to send
	if len(payload.frames) == 0 {
		if payload.ack == nil {
			return nil
		}
		// the packet only contains an ACK
		if p.numNonAckElicitingAcks >= protocol.MaxNonAckElicitingAcks {
			ping := &wire.PingFrame{}
			// don't retransmit the PING frame when it is lost
			payload.frames = append(payload.frames, ackhandler.Frame{Frame: ping, OnLost: func(wire.Frame) {}})
			payload.length += ping.Length(p.version)
			p.numNonAckElicitingAcks = 0
		} else {
			p.numNonAckElicitingAcks++
		}
	} else {
		p.numNonAckElicitingAcks = 0
	}
	return payload
}

func (p *packetPacker) composeNextPacket(maxFrameSize protocol.ByteCount, onlyAck, ackAllowed bool) *payload {
	if onlyAck {
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, true); ack != nil {
			payload := &payload{}
			payload.ack = ack
			payload.length += ack.Length(p.version)
			return payload
		}
		return &payload{}
	}

	payload := &payload{frames: make([]ackhandler.Frame, 0, 1)}

	hasData := p.framer.HasData()
	hasRetransmission := p.retransmissionQueue.HasAppData()

	var hasAck bool
	if ackAllowed {
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, !hasRetransmission && !hasData); ack != nil {
			payload.ack = ack
			payload.length += ack.Length(p.version)
			hasAck = true
		}
	}

	if p.datagramQueue != nil {
		if f := p.datagramQueue.Peek(); f != nil {
			size := f.Length(p.version)
			if size <= maxFrameSize-payload.length {
				payload.frames = append(payload.frames, ackhandler.Frame{
					Frame: f,
					// set it to a no-op. Then we won't set the default callback, which would retransmit the frame.
					OnLost: func(wire.Frame) {},
				})
				payload.length += size
				p.datagramQueue.Pop()
			}
		}
	}

	if hasAck && !hasData && !hasRetransmission {
		return payload
	}

	if hasRetransmission {
		for {
			remainingLen := maxFrameSize - payload.length
			if remainingLen < protocol.MinStreamFrameSize {
				break
			}
			f := p.retransmissionQueue.GetAppDataFrame(remainingLen)
			if f == nil {
				break
			}
			payload.frames = append(payload.frames, ackhandler.Frame{Frame: f})
			payload.length += f.Length(p.version)
		}
	}

	if hasData {
		var lengthAdded protocol.ByteCount
		payload.frames, lengthAdded = p.framer.AppendControlFrames(payload.frames, maxFrameSize-payload.length)
		payload.length += lengthAdded

		payload.frames, lengthAdded = p.framer.AppendStreamFrames(payload.frames, maxFrameSize-payload.length)
		payload.length += lengthAdded
	}
	return payload
}

func (p *packetPacker) MaybePackProbePacket(encLevel protocol.EncryptionLevel) (*packedPacket, error) {
	var hdr *wire.ExtendedHeader
	var payload *payload
	var sealer sealer
	//nolint:exhaustive // Probe packets are never sent for 0-RTT.
	switch encLevel {
	case protocol.EncryptionInitial:
		var err error
		sealer, err = p.cryptoSetup.GetInitialSealer()
		if err != nil {
			return nil, err
		}
		hdr, payload = p.maybeGetCryptoPacket(p.maxPacketSize-protocol.ByteCount(sealer.Overhead()), protocol.EncryptionInitial, false, true)
	case protocol.EncryptionHandshake:
		var err error
		sealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil {
			return nil, err
		}
		hdr, payload = p.maybeGetCryptoPacket(p.maxPacketSize-protocol.ByteCount(sealer.Overhead()), protocol.EncryptionHandshake, false, true)
	case protocol.Encryption1RTT:
		oneRTTSealer, err := p.cryptoSetup.Get1RTTSealer()
		if err != nil {
			return nil, err
		}
		sealer = oneRTTSealer
		hdr = p.getShortHeader(oneRTTSealer.KeyPhase())
		payload = p.maybeGetAppDataPacket(p.maxPacketSize-protocol.ByteCount(sealer.Overhead())-hdr.GetLength(p.version), false, true)
	default:
		panic("unknown encryption level")
	}
	if payload == nil {
		return nil, nil
	}
	size := p.packetLength(hdr, payload) + protocol.ByteCount(sealer.Overhead())
	var padding protocol.ByteCount
	if encLevel == protocol.EncryptionInitial {
		padding = p.initialPaddingLen(payload.frames, size)
	}
	buffer := getPacketBuffer()
	cont, err := p.appendPacket(buffer, hdr, payload, padding, encLevel, sealer, false)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		buffer:         buffer,
		packetContents: cont,
	}, nil
}

func (p *packetPacker) PackMTUProbePacket(ping ackhandler.Frame, size protocol.ByteCount) (*packedPacket, error) {
	payload := &payload{
		frames: []ackhandler.Frame{ping},
		length: ping.Length(p.version),
	}
	buffer := getPacketBuffer()
	sealer, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return nil, err
	}
	hdr := p.getShortHeader(sealer.KeyPhase())
	padding := size - p.packetLength(hdr, payload) - protocol.ByteCount(sealer.Overhead())
	contents, err := p.appendPacket(buffer, hdr, payload, padding, protocol.Encryption1RTT, sealer, true)
	if err != nil {
		return nil, err
	}
	contents.isMTUProbePacket = true
	return &packedPacket{
		buffer:         buffer,
		packetContents: contents,
	}, nil
}

func (p *packetPacker) getShortHeader(kp protocol.KeyPhaseBit) *wire.ExtendedHeader {
	pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
	hdr := &wire.ExtendedHeader{}
	hdr.PacketNumber = pn
	hdr.PacketNumberLen = pnLen
	hdr.DestConnectionID = p.getDestConnID()
	hdr.KeyPhase = kp
	return hdr
}

func (p *packetPacker) getLongHeader(encLevel protocol.EncryptionLevel) *wire.ExtendedHeader {
	pn, pnLen := p.pnManager.PeekPacketNumber(encLevel)
	hdr := &wire.ExtendedHeader{
		PacketNumber:    pn,
		PacketNumberLen: pnLen,
	}
	hdr.IsLongHeader = true
	hdr.Version = p.version
	hdr.SrcConnectionID = p.srcConnID
	hdr.DestConnectionID = p.getDestConnID()

	//nolint:exhaustive // 1-RTT packets are not long header packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		hdr.Type = protocol.PacketTypeInitial
		hdr.Token = p.token
	case protocol.EncryptionHandshake:
		hdr.Type = protocol.PacketTypeHandshake
	case protocol.Encryption0RTT:
		hdr.Type = protocol.PacketType0RTT
	}
	return hdr
}

func (p *packetPacker) appendPacket(buffer *packetBuffer, header *wire.ExtendedHeader, payload *payload, padding protocol.ByteCount, encLevel protocol.EncryptionLevel, sealer sealer, isMTUProbePacket bool) (*packetContents, error) {
	var paddingLen protocol.ByteCount
	pnLen := protocol.ByteCount(header.PacketNumberLen)
	if payload.length < 4-pnLen {
		paddingLen = 4 - pnLen - payload.length
	}
	paddingLen += padding
	if header.IsLongHeader {
		header.Length = pnLen + protocol.ByteCount(sealer.Overhead()) + payload.length + paddingLen
	}

	hdrOffset := buffer.Len()
	buf := bytes.NewBuffer(buffer.Data)
	if err := header.Write(buf, p.version); err != nil {
		return nil, err
	}
	payloadOffset := buf.Len()
	raw := buffer.Data[:payloadOffset]

	if payload.ack != nil {
		var err error
		raw, err = payload.ack.Append(raw, p.version)
		if err != nil {
			return nil, err
		}
	}
	if paddingLen > 0 {
		raw = append(raw, make([]byte, paddingLen)...)
	}
	for _, frame := range payload.frames {
		var err error
		raw, err = frame.Append(raw, p.version)
		if err != nil {
			return nil, err
		}
	}

	if payloadSize := protocol.ByteCount(len(raw)-payloadOffset) - paddingLen; payloadSize != payload.length {
		return nil, fmt.Errorf("PacketPacker BUG: payload size inconsistent (expected %d, got %d bytes)", payload.length, payloadSize)
	}
	if !isMTUProbePacket {
		if size := protocol.ByteCount(len(raw) + sealer.Overhead()); size > p.maxPacketSize {
			return nil, fmt.Errorf("PacketPacker BUG: packet too large (%d bytes, allowed %d bytes)", size, p.maxPacketSize)
		}
	}

	// encrypt the packet
	_ = sealer.Seal(raw[payloadOffset:payloadOffset], raw[payloadOffset:], header.PacketNumber, raw[hdrOffset:payloadOffset])
	raw = raw[0 : len(raw)+sealer.Overhead()]
	// apply header protection
	pnOffset := payloadOffset - int(header.PacketNumberLen)
	sealer.EncryptHeader(raw[pnOffset+4:pnOffset+4+16], &raw[hdrOffset], raw[pnOffset:payloadOffset])
	buffer.Data = raw

	num := p.pnManager.PopPacketNumber(encLevel)
	if num != header.PacketNumber {
		return nil, errors.New("packetPacker BUG: Peeked and Popped packet numbers do not match")
	}
	return &packetContents{
		header: header,
		ack:    payload.ack,
		frames: payload.frames,
		length: buffer.Len() - hdrOffset,
	}, nil
}

func (p *packetPacker) SetToken(token []byte) {
	p.token = token
}

// When a higher MTU is discovered, use it.
func (p *packetPacker) SetMaxPacketSize(s protocol.ByteCount) {
	p.maxPacketSize = s
}

// If the peer sets a max_packet_size that's smaller than the size we're currently using,
// we need to reduce the size of packets we send.
func (p *packetPacker) HandleTransportParameters(params *wire.TransportParameters) {
	if params.MaxUDPPayloadSize != 0 {
		p.maxPacketSize = utils.Min(p.maxPacketSize, params.MaxUDPPayloadSize)
	}
}
