package quic

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/logging"
)

// rawConn is a connection that allow reading of a receivedPacket.
type rawConn interface {
	ReadPacket() (*receivedPacket, error)
	WritePacket(b []byte, addr net.Addr, oob []byte) (int, error)
	LocalAddr() net.Addr
	io.Closer
}

type closePacket struct {
	payload []byte
	addr    net.Addr
	info    *packetInfo
}

// The packetHandlerMap stores packetHandlers, identified by connection ID.
// It is used:
// * by the server to store connections
// * when multiplexing outgoing connections to store clients
type packetHandlerMap struct {
	mutex sync.Mutex

	conn      rawConn
	connIDLen int

	closeQueue chan closePacket

	handlers          map[protocol.ConnectionID]packetHandler
	resetTokens       map[protocol.StatelessResetToken] /* stateless reset token */ packetHandler
	server            unknownPacketHandler
	numZeroRTTEntries int

	listening chan struct{} // is closed when listen returns
	closed    bool

	deleteRetiredConnsAfter time.Duration
	zeroRTTQueueDuration    time.Duration

	statelessResetEnabled bool
	statelessResetMutex   sync.Mutex
	statelessResetHasher  hash.Hash

	tracer logging.Tracer
	logger utils.Logger
}

var _ packetHandlerManager = &packetHandlerMap{}

func setReceiveBuffer(c net.PacketConn, logger utils.Logger) error {
	conn, ok := c.(interface{ SetReadBuffer(int) error })
	if !ok {
		return errors.New("connection doesn't allow setting of receive buffer size. Not a *net.UDPConn?")
	}
	size, err := inspectReadBuffer(c)
	if err != nil {
		return fmt.Errorf("failed to determine receive buffer size: %w", err)
	}
	if size >= protocol.DesiredReceiveBufferSize {
		logger.Debugf("Conn has receive buffer of %d kiB (wanted: at least %d kiB)", size/1024, protocol.DesiredReceiveBufferSize/1024)
		return nil
	}
	if err := conn.SetReadBuffer(protocol.DesiredReceiveBufferSize); err != nil {
		return fmt.Errorf("failed to increase receive buffer size: %w", err)
	}
	newSize, err := inspectReadBuffer(c)
	if err != nil {
		return fmt.Errorf("failed to determine receive buffer size: %w", err)
	}
	if newSize == size {
		return fmt.Errorf("failed to increase receive buffer size (wanted: %d kiB, got %d kiB)", protocol.DesiredReceiveBufferSize/1024, newSize/1024)
	}
	if newSize < protocol.DesiredReceiveBufferSize {
		return fmt.Errorf("failed to sufficiently increase receive buffer size (was: %d kiB, wanted: %d kiB, got: %d kiB)", size/1024, protocol.DesiredReceiveBufferSize/1024, newSize/1024)
	}
	logger.Debugf("Increased receive buffer size to %d kiB", newSize/1024)
	return nil
}

// only print warnings about the UDP receive buffer size once
var receiveBufferWarningOnce sync.Once

func newPacketHandlerMap(
	c net.PacketConn,
	connIDLen int,
	statelessResetKey *StatelessResetKey,
	tracer logging.Tracer,
	logger utils.Logger,
) (packetHandlerManager, error) {
	if err := setReceiveBuffer(c, logger); err != nil {
		if !strings.Contains(err.Error(), "use of closed network connection") {
			receiveBufferWarningOnce.Do(func() {
				if disable, _ := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING")); disable {
					return
				}
				log.Printf("%s. See https://github.com/lucas-clemente/quic-go/wiki/UDP-Receive-Buffer-Size for details.", err)
			})
		}
	}
	conn, err := wrapConn(c)
	if err != nil {
		return nil, err
	}
	m := &packetHandlerMap{
		conn:                    conn,
		connIDLen:               connIDLen,
		listening:               make(chan struct{}),
		handlers:                make(map[protocol.ConnectionID]packetHandler),
		resetTokens:             make(map[protocol.StatelessResetToken]packetHandler),
		deleteRetiredConnsAfter: protocol.RetiredConnectionIDDeleteTimeout,
		zeroRTTQueueDuration:    protocol.Max0RTTQueueingDuration,
		closeQueue:              make(chan closePacket, 4),
		statelessResetEnabled:   statelessResetKey != nil,
		tracer:                  tracer,
		logger:                  logger,
	}
	if m.statelessResetEnabled {
		m.statelessResetHasher = hmac.New(sha256.New, statelessResetKey[:])
	}
	go m.listen()
	go m.runCloseQueue()

	if logger.Debug() {
		go m.logUsage()
	}
	return m, nil
}

func (h *packetHandlerMap) logUsage() {
	ticker := time.NewTicker(2 * time.Second)
	var printedZero bool
	for {
		select {
		case <-h.listening:
			return
		case <-ticker.C:
		}

		h.mutex.Lock()
		numHandlers := len(h.handlers)
		numTokens := len(h.resetTokens)
		h.mutex.Unlock()
		// If the number tracked handlers and tokens is zero, only print it a single time.
		hasZero := numHandlers == 0 && numTokens == 0
		if !hasZero || (hasZero && !printedZero) {
			h.logger.Debugf("Tracking %d connection IDs and %d reset tokens.\n", numHandlers, numTokens)
			printedZero = false
			if hasZero {
				printedZero = true
			}
		}
	}
}

func (h *packetHandlerMap) Add(id protocol.ConnectionID, handler packetHandler) bool /* was added */ {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if _, ok := h.handlers[id]; ok {
		h.logger.Debugf("Not adding connection ID %s, as it already exists.", id)
		return false
	}
	h.handlers[id] = handler
	h.logger.Debugf("Adding connection ID %s.", id)
	return true
}

func (h *packetHandlerMap) AddWithConnID(clientDestConnID, newConnID protocol.ConnectionID, fn func() packetHandler) bool {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	var q *zeroRTTQueue
	if handler, ok := h.handlers[clientDestConnID]; ok {
		q, ok = handler.(*zeroRTTQueue)
		if !ok {
			h.logger.Debugf("Not adding connection ID %s for a new connection, as it already exists.", clientDestConnID)
			return false
		}
		q.retireTimer.Stop()
		h.numZeroRTTEntries--
		if h.numZeroRTTEntries < 0 {
			panic("number of 0-RTT queues < 0")
		}
	}
	conn := fn()
	if q != nil {
		q.EnqueueAll(conn)
	}
	h.handlers[clientDestConnID] = conn
	h.handlers[newConnID] = conn
	h.logger.Debugf("Adding connection IDs %s and %s for a new connection.", clientDestConnID, newConnID)
	return true
}

func (h *packetHandlerMap) Remove(id protocol.ConnectionID) {
	h.mutex.Lock()
	delete(h.handlers, id)
	h.mutex.Unlock()
	h.logger.Debugf("Removing connection ID %s.", id)
}

func (h *packetHandlerMap) Retire(id protocol.ConnectionID) {
	h.logger.Debugf("Retiring connection ID %s in %s.", id, h.deleteRetiredConnsAfter)
	time.AfterFunc(h.deleteRetiredConnsAfter, func() {
		h.mutex.Lock()
		delete(h.handlers, id)
		h.mutex.Unlock()
		h.logger.Debugf("Removing connection ID %s after it has been retired.", id)
	})
}

// ReplaceWithClosed is called when a connection is closed.
// Depending on which side closed the connection, we need to:
// * remote close: absorb delayed packets
// * local close: retransmit the CONNECTION_CLOSE packet, in case it was lost
func (h *packetHandlerMap) ReplaceWithClosed(ids []protocol.ConnectionID, pers protocol.Perspective, connClosePacket []byte) {
	var handler packetHandler
	if connClosePacket != nil {
		handler = newClosedLocalConn(
			func(addr net.Addr, info *packetInfo) {
				select {
				case h.closeQueue <- closePacket{payload: connClosePacket, addr: addr, info: info}:
				default:
					// Oops, we're backlogged.
					// Just drop the packet, sending CONNECTION_CLOSE copies is best effort anyway.
				}
			},
			pers,
			h.logger,
		)
	} else {
		handler = newClosedRemoteConn(pers)
	}

	h.mutex.Lock()
	for _, id := range ids {
		h.handlers[id] = handler
	}
	h.mutex.Unlock()
	h.logger.Debugf("Replacing connection for connection IDs %s with a closed connection.", ids)

	time.AfterFunc(h.deleteRetiredConnsAfter, func() {
		h.mutex.Lock()
		handler.shutdown()
		for _, id := range ids {
			delete(h.handlers, id)
		}
		h.mutex.Unlock()
		h.logger.Debugf("Removing connection IDs %s for a closed connection after it has been retired.", ids)
	})
}

func (h *packetHandlerMap) runCloseQueue() {
	for {
		select {
		case <-h.listening:
			return
		case p := <-h.closeQueue:
			h.conn.WritePacket(p.payload, p.addr, p.info.OOB())
		}
	}
}

func (h *packetHandlerMap) AddResetToken(token protocol.StatelessResetToken, handler packetHandler) {
	h.mutex.Lock()
	h.resetTokens[token] = handler
	h.mutex.Unlock()
}

func (h *packetHandlerMap) RemoveResetToken(token protocol.StatelessResetToken) {
	h.mutex.Lock()
	delete(h.resetTokens, token)
	h.mutex.Unlock()
}

func (h *packetHandlerMap) SetServer(s unknownPacketHandler) {
	h.mutex.Lock()
	h.server = s
	h.mutex.Unlock()
}

func (h *packetHandlerMap) CloseServer() {
	h.mutex.Lock()
	if h.server == nil {
		h.mutex.Unlock()
		return
	}
	h.server = nil
	var wg sync.WaitGroup
	for _, handler := range h.handlers {
		if handler.getPerspective() == protocol.PerspectiveServer {
			wg.Add(1)
			go func(handler packetHandler) {
				// blocks until the CONNECTION_CLOSE has been sent and the run-loop has stopped
				handler.shutdown()
				wg.Done()
			}(handler)
		}
	}
	h.mutex.Unlock()
	wg.Wait()
}

// Destroy closes the underlying connection and waits until listen() has returned.
// It does not close active connections.
func (h *packetHandlerMap) Destroy() error {
	if err := h.conn.Close(); err != nil {
		return err
	}
	<-h.listening // wait until listening returns
	return nil
}

func (h *packetHandlerMap) close(e error) error {
	h.mutex.Lock()
	if h.closed {
		h.mutex.Unlock()
		return nil
	}

	var wg sync.WaitGroup
	for _, handler := range h.handlers {
		wg.Add(1)
		go func(handler packetHandler) {
			handler.destroy(e)
			wg.Done()
		}(handler)
	}

	if h.server != nil {
		h.server.setCloseError(e)
	}
	h.closed = true
	h.mutex.Unlock()
	wg.Wait()
	return getMultiplexer().RemoveConn(h.conn)
}

func (h *packetHandlerMap) listen() {
	defer close(h.listening)
	for {
		p, err := h.conn.ReadPacket()
		//nolint:staticcheck // SA1019 ignore this!
		// TODO: This code is used to ignore wsa errors on Windows.
		// Since net.Error.Temporary is deprecated as of Go 1.18, we should find a better solution.
		// See https://github.com/lucas-clemente/quic-go/issues/1737 for details.
		if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
			h.logger.Debugf("Temporary error reading from conn: %w", err)
			continue
		}
		if err != nil {
			h.close(err)
			return
		}
		h.handlePacket(p)
	}
}

func (h *packetHandlerMap) handlePacket(p *receivedPacket) {
	connID, err := wire.ParseConnectionID(p.data, h.connIDLen)
	if err != nil {
		h.logger.Debugf("error parsing connection ID on packet from %s: %s", p.remoteAddr, err)
		if h.tracer != nil {
			h.tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropHeaderParseError)
		}
		p.buffer.MaybeRelease()
		return
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	if isStatelessReset := h.maybeHandleStatelessReset(p.data); isStatelessReset {
		return
	}

	if handler, ok := h.handlers[connID]; ok {
		if ha, ok := handler.(*zeroRTTQueue); ok { // only enqueue 0-RTT packets in the 0-RTT queue
			if wire.Is0RTTPacket(p.data) {
				ha.handlePacket(p)
				return
			}
		} else { // existing connection
			handler.handlePacket(p)
			return
		}
	}
	if !wire.IsLongHeaderPacket(p.data[0]) {
		go h.maybeSendStatelessReset(p, connID)
		return
	}
	if h.server == nil { // no server set
		h.logger.Debugf("received a packet with an unexpected connection ID %s", connID)
		return
	}
	if wire.Is0RTTPacket(p.data) {
		if h.numZeroRTTEntries >= protocol.Max0RTTQueues {
			return
		}
		h.numZeroRTTEntries++
		queue := &zeroRTTQueue{queue: make([]*receivedPacket, 0, 8)}
		h.handlers[connID] = queue
		queue.retireTimer = time.AfterFunc(h.zeroRTTQueueDuration, func() {
			h.mutex.Lock()
			defer h.mutex.Unlock()
			// The entry might have been replaced by an actual connection.
			// Only delete it if it's still a 0-RTT queue.
			if handler, ok := h.handlers[connID]; ok {
				if q, ok := handler.(*zeroRTTQueue); ok {
					delete(h.handlers, connID)
					h.numZeroRTTEntries--
					if h.numZeroRTTEntries < 0 {
						panic("number of 0-RTT queues < 0")
					}
					q.Clear()
					if h.logger.Debug() {
						h.logger.Debugf("Removing 0-RTT queue for %s.", connID)
					}
				}
			}
		})
		queue.handlePacket(p)
		return
	}
	h.server.handlePacket(p)
}

func (h *packetHandlerMap) maybeHandleStatelessReset(data []byte) bool {
	// stateless resets are always short header packets
	if wire.IsLongHeaderPacket(data[0]) {
		return false
	}
	if len(data) < 17 /* type byte + 16 bytes for the reset token */ {
		return false
	}

	var token protocol.StatelessResetToken
	copy(token[:], data[len(data)-16:])
	if sess, ok := h.resetTokens[token]; ok {
		h.logger.Debugf("Received a stateless reset with token %#x. Closing connection.", token)
		go sess.destroy(&StatelessResetError{Token: token})
		return true
	}
	return false
}

func (h *packetHandlerMap) GetStatelessResetToken(connID protocol.ConnectionID) protocol.StatelessResetToken {
	var token protocol.StatelessResetToken
	if !h.statelessResetEnabled {
		// Return a random stateless reset token.
		// This token will be sent in the server's transport parameters.
		// By using a random token, an off-path attacker won't be able to disrupt the connection.
		rand.Read(token[:])
		return token
	}
	h.statelessResetMutex.Lock()
	h.statelessResetHasher.Write(connID.Bytes())
	copy(token[:], h.statelessResetHasher.Sum(nil))
	h.statelessResetHasher.Reset()
	h.statelessResetMutex.Unlock()
	return token
}

func (h *packetHandlerMap) maybeSendStatelessReset(p *receivedPacket, connID protocol.ConnectionID) {
	defer p.buffer.Release()
	if !h.statelessResetEnabled {
		return
	}
	// Don't send a stateless reset in response to very small packets.
	// This includes packets that could be stateless resets.
	if len(p.data) <= protocol.MinStatelessResetSize {
		return
	}
	token := h.GetStatelessResetToken(connID)
	h.logger.Debugf("Sending stateless reset to %s (connection ID: %s). Token: %#x", p.remoteAddr, connID, token)
	data := make([]byte, protocol.MinStatelessResetSize-16, protocol.MinStatelessResetSize)
	rand.Read(data)
	data[0] = (data[0] & 0x7f) | 0x40
	data = append(data, token[:]...)
	if _, err := h.conn.WritePacket(data, p.remoteAddr, p.info.OOB()); err != nil {
		h.logger.Debugf("Error sending Stateless Reset: %s", err)
	}
}
