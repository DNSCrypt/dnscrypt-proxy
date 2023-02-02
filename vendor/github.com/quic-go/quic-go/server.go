package quic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
)

// ErrServerClosed is returned by the Listener or EarlyListener's Accept method after a call to Close.
var ErrServerClosed = errors.New("quic: Server closed")

// packetHandler handles packets
type packetHandler interface {
	handlePacket(*receivedPacket)
	shutdown()
	destroy(error)
	getPerspective() protocol.Perspective
}

type unknownPacketHandler interface {
	handlePacket(*receivedPacket)
	setCloseError(error)
}

type packetHandlerManager interface {
	AddWithConnID(protocol.ConnectionID, protocol.ConnectionID, func() packetHandler) bool
	Destroy() error
	connRunner
	SetServer(unknownPacketHandler)
	CloseServer()
}

type quicConn interface {
	EarlyConnection
	earlyConnReady() <-chan struct{}
	handlePacket(*receivedPacket)
	GetVersion() protocol.VersionNumber
	getPerspective() protocol.Perspective
	run() error
	destroy(error)
	shutdown()
}

// A Listener of QUIC
type baseServer struct {
	mutex sync.Mutex

	acceptEarlyConns bool

	tlsConf *tls.Config
	config  *Config

	conn rawConn
	// If the server is started with ListenAddr, we create a packet conn.
	// If it is started with Listen, we take a packet conn as a parameter.
	createdPacketConn bool

	tokenGenerator *handshake.TokenGenerator

	connHandler packetHandlerManager

	receivedPackets chan *receivedPacket

	// set as a member, so they can be set in the tests
	newConn func(
		sendConn,
		connRunner,
		protocol.ConnectionID, /* original dest connection ID */
		*protocol.ConnectionID, /* retry src connection ID */
		protocol.ConnectionID, /* client dest connection ID */
		protocol.ConnectionID, /* destination connection ID */
		protocol.ConnectionID, /* source connection ID */
		protocol.StatelessResetToken,
		*Config,
		*tls.Config,
		*handshake.TokenGenerator,
		bool, /* client address validated by an address validation token */
		logging.ConnectionTracer,
		uint64,
		utils.Logger,
		protocol.VersionNumber,
	) quicConn

	serverError error
	errorChan   chan struct{}
	closed      bool
	running     chan struct{} // closed as soon as run() returns

	connQueue    chan quicConn
	connQueueLen int32 // to be used as an atomic

	logger utils.Logger
}

var (
	_ Listener             = &baseServer{}
	_ unknownPacketHandler = &baseServer{}
)

type earlyServer struct{ *baseServer }

var _ EarlyListener = &earlyServer{}

func (s *earlyServer) Accept(ctx context.Context) (EarlyConnection, error) {
	return s.baseServer.accept(ctx)
}

// ListenAddr creates a QUIC server listening on a given address.
// The tls.Config must not be nil and must contain a certificate configuration.
// The quic.Config may be nil, in that case the default values will be used.
func ListenAddr(addr string, tlsConf *tls.Config, config *Config) (Listener, error) {
	return listenAddr(addr, tlsConf, config, false)
}

// ListenAddrEarly works like ListenAddr, but it returns connections before the handshake completes.
func ListenAddrEarly(addr string, tlsConf *tls.Config, config *Config) (EarlyListener, error) {
	s, err := listenAddr(addr, tlsConf, config, true)
	if err != nil {
		return nil, err
	}
	return &earlyServer{s}, nil
}

func listenAddr(addr string, tlsConf *tls.Config, config *Config, acceptEarly bool) (*baseServer, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	serv, err := listen(conn, tlsConf, config, acceptEarly)
	if err != nil {
		return nil, err
	}
	serv.createdPacketConn = true
	return serv, nil
}

// Listen listens for QUIC connections on a given net.PacketConn. If the
// PacketConn satisfies the OOBCapablePacketConn interface (as a net.UDPConn
// does), ECN and packet info support will be enabled. In this case, ReadMsgUDP
// and WriteMsgUDP will be used instead of ReadFrom and WriteTo to read/write
// packets. A single net.PacketConn only be used for a single call to Listen.
// The PacketConn can be used for simultaneous calls to Dial. QUIC connection
// IDs are used for demultiplexing the different connections. The tls.Config
// must not be nil and must contain a certificate configuration. The
// tls.Config.CipherSuites allows setting of TLS 1.3 cipher suites. Furthermore,
// it must define an application control (using NextProtos). The quic.Config may
// be nil, in that case the default values will be used.
func Listen(conn net.PacketConn, tlsConf *tls.Config, config *Config) (Listener, error) {
	return listen(conn, tlsConf, config, false)
}

// ListenEarly works like Listen, but it returns connections before the handshake completes.
func ListenEarly(conn net.PacketConn, tlsConf *tls.Config, config *Config) (EarlyListener, error) {
	s, err := listen(conn, tlsConf, config, true)
	if err != nil {
		return nil, err
	}
	return &earlyServer{s}, nil
}

func listen(conn net.PacketConn, tlsConf *tls.Config, config *Config, acceptEarly bool) (*baseServer, error) {
	if tlsConf == nil {
		return nil, errors.New("quic: tls.Config not set")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	config = populateServerConfig(config)
	for _, v := range config.Versions {
		if !protocol.IsValidVersion(v) {
			return nil, fmt.Errorf("%s is not a valid QUIC version", v)
		}
	}

	connHandler, err := getMultiplexer().AddConn(conn, config.ConnectionIDGenerator.ConnectionIDLen(), config.StatelessResetKey, config.Tracer)
	if err != nil {
		return nil, err
	}
	tokenGenerator, err := handshake.NewTokenGenerator(rand.Reader)
	if err != nil {
		return nil, err
	}
	c, err := wrapConn(conn)
	if err != nil {
		return nil, err
	}
	s := &baseServer{
		conn:             c,
		tlsConf:          tlsConf,
		config:           config,
		tokenGenerator:   tokenGenerator,
		connHandler:      connHandler,
		connQueue:        make(chan quicConn),
		errorChan:        make(chan struct{}),
		running:          make(chan struct{}),
		receivedPackets:  make(chan *receivedPacket, protocol.MaxServerUnprocessedPackets),
		newConn:          newConnection,
		logger:           utils.DefaultLogger.WithPrefix("server"),
		acceptEarlyConns: acceptEarly,
	}
	go s.run()
	connHandler.SetServer(s)
	s.logger.Debugf("Listening for %s connections on %s", conn.LocalAddr().Network(), conn.LocalAddr().String())
	return s, nil
}

func (s *baseServer) run() {
	defer close(s.running)
	for {
		select {
		case <-s.errorChan:
			return
		default:
		}
		select {
		case <-s.errorChan:
			return
		case p := <-s.receivedPackets:
			if bufferStillInUse := s.handlePacketImpl(p); !bufferStillInUse {
				p.buffer.Release()
			}
		}
	}
}

// Accept returns connections that already completed the handshake.
// It is only valid if acceptEarlyConns is false.
func (s *baseServer) Accept(ctx context.Context) (Connection, error) {
	return s.accept(ctx)
}

func (s *baseServer) accept(ctx context.Context) (quicConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case conn := <-s.connQueue:
		atomic.AddInt32(&s.connQueueLen, -1)
		return conn, nil
	case <-s.errorChan:
		return nil, s.serverError
	}
}

// Close the server
func (s *baseServer) Close() error {
	s.mutex.Lock()
	if s.closed {
		s.mutex.Unlock()
		return nil
	}
	if s.serverError == nil {
		s.serverError = ErrServerClosed
	}
	// If the server was started with ListenAddr, we created the packet conn.
	// We need to close it in order to make the go routine reading from that conn return.
	createdPacketConn := s.createdPacketConn
	s.closed = true
	close(s.errorChan)
	s.mutex.Unlock()

	<-s.running
	s.connHandler.CloseServer()
	if createdPacketConn {
		return s.connHandler.Destroy()
	}
	return nil
}

func (s *baseServer) setCloseError(e error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.serverError = e
	close(s.errorChan)
}

// Addr returns the server's network address
func (s *baseServer) Addr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *baseServer) handlePacket(p *receivedPacket) {
	select {
	case s.receivedPackets <- p:
	default:
		s.logger.Debugf("Dropping packet from %s (%d bytes). Server receive queue full.", p.remoteAddr, p.Size())
		if s.config.Tracer != nil {
			s.config.Tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropDOSPrevention)
		}
	}
}

func (s *baseServer) handlePacketImpl(p *receivedPacket) bool /* is the buffer still in use? */ {
	if wire.IsVersionNegotiationPacket(p.data) {
		s.logger.Debugf("Dropping Version Negotiation packet.")
		if s.config.Tracer != nil {
			s.config.Tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeVersionNegotiation, p.Size(), logging.PacketDropUnexpectedPacket)
		}
		return false
	}
	// Short header packets should never end up here in the first place
	if !wire.IsLongHeaderPacket(p.data[0]) {
		panic(fmt.Sprintf("misrouted packet: %#v", p.data))
	}
	v, err := wire.ParseVersion(p.data)
	// send a Version Negotiation Packet if the client is speaking a different protocol version
	if err != nil || !protocol.IsSupportedVersion(s.config.Versions, v) {
		if err != nil || p.Size() < protocol.MinUnknownVersionPacketSize {
			s.logger.Debugf("Dropping a packet with an unknown version that is too small (%d bytes)", p.Size())
			if s.config.Tracer != nil {
				s.config.Tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropUnexpectedPacket)
			}
			return false
		}
		_, src, dest, err := wire.ParseArbitraryLenConnectionIDs(p.data)
		if err != nil { // should never happen
			s.logger.Debugf("Dropping a packet with an unknown version for which we failed to parse connection IDs")
			if s.config.Tracer != nil {
				s.config.Tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropUnexpectedPacket)
			}
			return false
		}
		if !s.config.DisableVersionNegotiationPackets {
			go s.sendVersionNegotiationPacket(p.remoteAddr, src, dest, p.info.OOB())
		}
		return false
	}
	// If we're creating a new connection, the packet will be passed to the connection.
	// The header will then be parsed again.
	hdr, _, _, err := wire.ParsePacket(p.data)
	if err != nil {
		if s.config.Tracer != nil {
			s.config.Tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropHeaderParseError)
		}
		s.logger.Debugf("Error parsing packet: %s", err)
		return false
	}
	if hdr.Type == protocol.PacketTypeInitial && p.Size() < protocol.MinInitialPacketSize {
		s.logger.Debugf("Dropping a packet that is too small to be a valid Initial (%d bytes)", p.Size())
		if s.config.Tracer != nil {
			s.config.Tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeInitial, p.Size(), logging.PacketDropUnexpectedPacket)
		}
		return false
	}

	if hdr.Type != protocol.PacketTypeInitial {
		// Drop long header packets.
		// There's little point in sending a Stateless Reset, since the client
		// might not have received the token yet.
		s.logger.Debugf("Dropping long header packet of type %s (%d bytes)", hdr.Type, len(p.data))
		if s.config.Tracer != nil {
			s.config.Tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeFromHeader(hdr), p.Size(), logging.PacketDropUnexpectedPacket)
		}
		return false
	}

	s.logger.Debugf("<- Received Initial packet.")

	if err := s.handleInitialImpl(p, hdr); err != nil {
		s.logger.Errorf("Error occurred handling initial packet: %s", err)
	}
	// Don't put the packet buffer back.
	// handleInitialImpl deals with the buffer.
	return true
}

// validateToken returns false if:
//   - address is invalid
//   - token is expired
//   - token is null
func (s *baseServer) validateToken(token *handshake.Token, addr net.Addr) bool {
	if token == nil {
		return false
	}
	if !token.ValidateRemoteAddr(addr) {
		return false
	}
	if !token.IsRetryToken && time.Since(token.SentTime) > s.config.MaxTokenAge {
		return false
	}
	if token.IsRetryToken && time.Since(token.SentTime) > s.config.MaxRetryTokenAge {
		return false
	}
	return true
}

func (s *baseServer) handleInitialImpl(p *receivedPacket, hdr *wire.Header) error {
	if len(hdr.Token) == 0 && hdr.DestConnectionID.Len() < protocol.MinConnectionIDLenInitial {
		p.buffer.Release()
		if s.config.Tracer != nil {
			s.config.Tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeInitial, p.Size(), logging.PacketDropUnexpectedPacket)
		}
		return errors.New("too short connection ID")
	}

	var (
		token          *handshake.Token
		retrySrcConnID *protocol.ConnectionID
	)
	origDestConnID := hdr.DestConnectionID
	if len(hdr.Token) > 0 {
		tok, err := s.tokenGenerator.DecodeToken(hdr.Token)
		if err == nil {
			if tok.IsRetryToken {
				origDestConnID = tok.OriginalDestConnectionID
				retrySrcConnID = &tok.RetrySrcConnectionID
			}
			token = tok
		}
	}

	clientAddrIsValid := s.validateToken(token, p.remoteAddr)

	if token != nil && !clientAddrIsValid {
		// For invalid and expired non-retry tokens, we don't send an INVALID_TOKEN error.
		// We just ignore them, and act as if there was no token on this packet at all.
		// This also means we might send a Retry later.
		if !token.IsRetryToken {
			token = nil
		} else {
			// For Retry tokens, we send an INVALID_ERROR if
			// * the token is too old, or
			// * the token is invalid, in case of a retry token.
			go func() {
				defer p.buffer.Release()
				if err := s.maybeSendInvalidToken(p, hdr); err != nil {
					s.logger.Debugf("Error sending INVALID_TOKEN error: %s", err)
				}
			}()
			return nil
		}
	}
	if token == nil && s.config.RequireAddressValidation(p.remoteAddr) {
		go func() {
			defer p.buffer.Release()
			if err := s.sendRetry(p.remoteAddr, hdr, p.info); err != nil {
				s.logger.Debugf("Error sending Retry: %s", err)
			}
		}()
		return nil
	}

	if queueLen := atomic.LoadInt32(&s.connQueueLen); queueLen >= protocol.MaxAcceptQueueSize {
		s.logger.Debugf("Rejecting new connection. Server currently busy. Accept queue length: %d (max %d)", queueLen, protocol.MaxAcceptQueueSize)
		go func() {
			defer p.buffer.Release()
			if err := s.sendConnectionRefused(p.remoteAddr, hdr, p.info); err != nil {
				s.logger.Debugf("Error rejecting connection: %s", err)
			}
		}()
		return nil
	}

	connID, err := s.config.ConnectionIDGenerator.GenerateConnectionID()
	if err != nil {
		return err
	}
	s.logger.Debugf("Changing connection ID to %s.", connID)
	var conn quicConn
	tracingID := nextConnTracingID()
	if added := s.connHandler.AddWithConnID(hdr.DestConnectionID, connID, func() packetHandler {
		var tracer logging.ConnectionTracer
		if s.config.Tracer != nil {
			// Use the same connection ID that is passed to the client's GetLogWriter callback.
			connID := hdr.DestConnectionID
			if origDestConnID.Len() > 0 {
				connID = origDestConnID
			}
			tracer = s.config.Tracer.TracerForConnection(
				context.WithValue(context.Background(), ConnectionTracingKey, tracingID),
				protocol.PerspectiveServer,
				connID,
			)
		}
		conn = s.newConn(
			newSendConn(s.conn, p.remoteAddr, p.info),
			s.connHandler,
			origDestConnID,
			retrySrcConnID,
			hdr.DestConnectionID,
			hdr.SrcConnectionID,
			connID,
			s.connHandler.GetStatelessResetToken(connID),
			s.config,
			s.tlsConf,
			s.tokenGenerator,
			clientAddrIsValid,
			tracer,
			tracingID,
			s.logger,
			hdr.Version,
		)
		conn.handlePacket(p)
		return conn
	}); !added {
		return nil
	}
	go conn.run()
	go s.handleNewConn(conn)
	if conn == nil {
		p.buffer.Release()
		return nil
	}
	return nil
}

func (s *baseServer) handleNewConn(conn quicConn) {
	connCtx := conn.Context()
	if s.acceptEarlyConns {
		// wait until the early connection is ready (or the handshake fails)
		select {
		case <-conn.earlyConnReady():
		case <-connCtx.Done():
			return
		}
	} else {
		// wait until the handshake is complete (or fails)
		select {
		case <-conn.HandshakeComplete().Done():
		case <-connCtx.Done():
			return
		}
	}

	atomic.AddInt32(&s.connQueueLen, 1)
	select {
	case s.connQueue <- conn:
		// blocks until the connection is accepted
	case <-connCtx.Done():
		atomic.AddInt32(&s.connQueueLen, -1)
		// don't pass connections that were already closed to Accept()
	}
}

func (s *baseServer) sendRetry(remoteAddr net.Addr, hdr *wire.Header, info *packetInfo) error {
	// Log the Initial packet now.
	// If no Retry is sent, the packet will be logged by the connection.
	(&wire.ExtendedHeader{Header: *hdr}).Log(s.logger)
	srcConnID, err := s.config.ConnectionIDGenerator.GenerateConnectionID()
	if err != nil {
		return err
	}
	token, err := s.tokenGenerator.NewRetryToken(remoteAddr, hdr.DestConnectionID, srcConnID)
	if err != nil {
		return err
	}
	replyHdr := &wire.ExtendedHeader{}
	replyHdr.Type = protocol.PacketTypeRetry
	replyHdr.Version = hdr.Version
	replyHdr.SrcConnectionID = srcConnID
	replyHdr.DestConnectionID = hdr.SrcConnectionID
	replyHdr.Token = token
	if s.logger.Debug() {
		s.logger.Debugf("Changing connection ID to %s.", srcConnID)
		s.logger.Debugf("-> Sending Retry")
		replyHdr.Log(s.logger)
	}

	buf := getPacketBuffer()
	defer buf.Release()
	buf.Data, err = replyHdr.Append(buf.Data, hdr.Version)
	if err != nil {
		return err
	}
	// append the Retry integrity tag
	tag := handshake.GetRetryIntegrityTag(buf.Data, hdr.DestConnectionID, hdr.Version)
	buf.Data = append(buf.Data, tag[:]...)
	if s.config.Tracer != nil {
		s.config.Tracer.SentPacket(remoteAddr, &replyHdr.Header, protocol.ByteCount(len(buf.Data)), nil)
	}
	_, err = s.conn.WritePacket(buf.Data, remoteAddr, info.OOB())
	return err
}

func (s *baseServer) maybeSendInvalidToken(p *receivedPacket, hdr *wire.Header) error {
	// Only send INVALID_TOKEN if we can unprotect the packet.
	// This makes sure that we won't send it for packets that were corrupted.
	sealer, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, hdr.Version)
	data := p.data[:hdr.ParsedLen()+hdr.Length]
	extHdr, err := unpackLongHeader(opener, hdr, data, hdr.Version)
	if err != nil {
		if s.config.Tracer != nil {
			s.config.Tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeInitial, p.Size(), logging.PacketDropHeaderParseError)
		}
		// don't return the error here. Just drop the packet.
		return nil
	}
	hdrLen := extHdr.ParsedLen()
	if _, err := opener.Open(data[hdrLen:hdrLen], data[hdrLen:], extHdr.PacketNumber, data[:hdrLen]); err != nil {
		// don't return the error here. Just drop the packet.
		if s.config.Tracer != nil {
			s.config.Tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeInitial, p.Size(), logging.PacketDropPayloadDecryptError)
		}
		return nil
	}
	if s.logger.Debug() {
		s.logger.Debugf("Client sent an invalid retry token. Sending INVALID_TOKEN to %s.", p.remoteAddr)
	}
	return s.sendError(p.remoteAddr, hdr, sealer, qerr.InvalidToken, p.info)
}

func (s *baseServer) sendConnectionRefused(remoteAddr net.Addr, hdr *wire.Header, info *packetInfo) error {
	sealer, _ := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, hdr.Version)
	return s.sendError(remoteAddr, hdr, sealer, qerr.ConnectionRefused, info)
}

// sendError sends the error as a response to the packet received with header hdr
func (s *baseServer) sendError(remoteAddr net.Addr, hdr *wire.Header, sealer handshake.LongHeaderSealer, errorCode qerr.TransportErrorCode, info *packetInfo) error {
	b := getPacketBuffer()
	defer b.Release()

	ccf := &wire.ConnectionCloseFrame{ErrorCode: uint64(errorCode)}

	replyHdr := &wire.ExtendedHeader{}
	replyHdr.Type = protocol.PacketTypeInitial
	replyHdr.Version = hdr.Version
	replyHdr.SrcConnectionID = hdr.DestConnectionID
	replyHdr.DestConnectionID = hdr.SrcConnectionID
	replyHdr.PacketNumberLen = protocol.PacketNumberLen4
	replyHdr.Length = 4 /* packet number len */ + ccf.Length(hdr.Version) + protocol.ByteCount(sealer.Overhead())
	var err error
	b.Data, err = replyHdr.Append(b.Data, hdr.Version)
	if err != nil {
		return err
	}
	payloadOffset := len(b.Data)

	b.Data, err = ccf.Append(b.Data, hdr.Version)
	if err != nil {
		return err
	}

	_ = sealer.Seal(b.Data[payloadOffset:payloadOffset], b.Data[payloadOffset:], replyHdr.PacketNumber, b.Data[:payloadOffset])
	b.Data = b.Data[0 : len(b.Data)+sealer.Overhead()]

	pnOffset := payloadOffset - int(replyHdr.PacketNumberLen)
	sealer.EncryptHeader(
		b.Data[pnOffset+4:pnOffset+4+16],
		&b.Data[0],
		b.Data[pnOffset:payloadOffset],
	)

	replyHdr.Log(s.logger)
	wire.LogFrame(s.logger, ccf, true)
	if s.config.Tracer != nil {
		s.config.Tracer.SentPacket(remoteAddr, &replyHdr.Header, protocol.ByteCount(len(b.Data)), []logging.Frame{ccf})
	}
	_, err = s.conn.WritePacket(b.Data, remoteAddr, info.OOB())
	return err
}

func (s *baseServer) sendVersionNegotiationPacket(remote net.Addr, src, dest protocol.ArbitraryLenConnectionID, oob []byte) {
	s.logger.Debugf("Client offered version %s, sending Version Negotiation")

	data := wire.ComposeVersionNegotiation(dest, src, s.config.Versions)
	if s.config.Tracer != nil {
		s.config.Tracer.SentVersionNegotiationPacket(remote, src, dest, s.config.Versions)
	}
	if _, err := s.conn.WritePacket(data, remote, oob); err != nil {
		s.logger.Debugf("Error sending Version Negotiation: %s", err)
	}
}
