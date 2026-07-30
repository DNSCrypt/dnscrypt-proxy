package quic

import (
	"errors"
	"fmt"
	"sync"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
)

type connectionFlowController struct {
	receiveFlowController

	// Protects send-side state, which TryWriteAll can access from application goroutines.
	sendMutex     sync.Mutex
	bytesSent     protocol.ByteCount
	sendWindow    protocol.ByteCount
	lastBlockedAt protocol.ByteCount
}

// newConnectionFlowController gets a new flow controller for the connection.
// It is created before we receive the peer's transport parameters, thus it starts with a sendWindow of 0.
func newConnectionFlowController(
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	allowWindowIncrease func(size protocol.ByteCount) bool,
	rttStats *utils.RTTStats,
	logger utils.Logger,
) *connectionFlowController {
	return &connectionFlowController{
		receiveFlowController: receiveFlowController{
			rttStats:             rttStats,
			receiveWindow:        receiveWindow,
			receiveWindowSize:    receiveWindow,
			maxReceiveWindowSize: maxReceiveWindow,
			allowWindowIncrease:  allowWindowIncrease,
			logger:               logger,
		},
	}
}

// IncrementHighestReceived adds an increment to the highestReceived value
func (c *connectionFlowController) IncrementHighestReceived(increment protocol.ByteCount, now monotime.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// If this is the first frame received on this connection, start flow-control auto-tuning.
	if c.highestReceived == 0 {
		c.startNewAutoTuningEpoch(now)
	}
	c.highestReceived += increment

	if c.checkFlowControlViolation() {
		return &qerr.TransportError{
			ErrorCode:    qerr.FlowControlError,
			ErrorMessage: fmt.Sprintf("received %d bytes for the connection, allowed %d bytes", c.highestReceived, c.receiveWindow),
		}
	}
	return nil
}

func (c *connectionFlowController) AddBytesRead(n protocol.ByteCount) (hasWindowUpdate bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.addBytesRead(n)
	return c.hasWindowUpdate()
}

// TryAddBytesSent adds n bytes if sufficient connection-level send credit is available.
func (c *connectionFlowController) TryAddBytesSent(n protocol.ByteCount) bool {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()

	if c.bytesSent > c.sendWindow || n > c.sendWindow-c.bytesSent {
		return false
	}
	c.bytesSent += n
	return true
}

// AddBytesSentWithLimiter adds the limiter-approved portion of the available connection-level send credit.
func (c *connectionFlowController) AddBytesSentWithLimiter(
	n protocol.ByteCount,
	limiter func(int) int,
) (protocol.ByteCount, bool) {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()

	if c.bytesSent >= c.sendWindow {
		return 0, false
	}
	n = min(n, c.sendWindow-c.bytesSent)
	added := min(
		max(protocol.ByteCount(limiter(int(n))), 0),
		n,
	)
	c.bytesSent += added
	return added, added < n
}

// UpdateSendWindow is called after receiving a MAX_DATA frame.
func (c *connectionFlowController) UpdateSendWindow(offset protocol.ByteCount) (updated bool) {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()

	if offset > c.sendWindow {
		c.sendWindow = offset
		return true
	}
	return false
}

func (c *connectionFlowController) SendWindowSize() protocol.ByteCount {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()

	return c.sendWindow - c.bytesSent
}

// IsNewlyBlocked says if it is newly blocked by connection flow control.
// For every offset, it only returns true once.
// If it is blocked, the offset is returned.
func (c *connectionFlowController) IsNewlyBlocked() (bool, protocol.ByteCount) {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()

	if c.bytesSent < c.sendWindow || c.sendWindow == c.lastBlockedAt {
		return false, 0
	}
	c.lastBlockedAt = c.sendWindow
	return true, c.sendWindow
}

func (c *connectionFlowController) GetWindowUpdate(now monotime.Time) protocol.ByteCount {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	oldWindowSize := c.receiveWindowSize
	offset := c.getWindowUpdate(now)
	if c.logger.Debug() && oldWindowSize < c.receiveWindowSize {
		c.logger.Debugf("Increasing receive flow control window for the connection to %d kB", c.receiveWindowSize/(1<<10))
	}
	return offset
}

// EnsureMinimumWindowSize sets a minimum window size
// it should make sure that the connection-level window is increased when a stream-level window grows
func (c *connectionFlowController) EnsureMinimumWindowSize(inc protocol.ByteCount, now monotime.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if inc <= c.receiveWindowSize {
		return
	}
	newSize := min(inc, c.maxReceiveWindowSize)
	if delta := newSize - c.receiveWindowSize; delta > 0 && c.allowWindowIncrease(delta) {
		c.receiveWindowSize = newSize
		if c.logger.Debug() {
			c.logger.Debugf("Increasing receive flow control window for the connection to %d, in response to stream flow control window increase", newSize)
		}
	}
	c.startNewAutoTuningEpoch(now)
}

// Reset rests the flow controller. This happens when 0-RTT is rejected.
// All stream data is invalidated, it's as if we had never opened a stream and never sent any data.
// At that point, we only have sent stream data, but we didn't have the keys to open 1-RTT keys yet.
func (c *connectionFlowController) Reset() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.bytesRead > 0 || c.highestReceived > 0 || !c.epochStartTime.IsZero() {
		return errors.New("flow controller reset after reading data")
	}
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()

	c.bytesSent = 0
	c.lastBlockedAt = 0
	c.sendWindow = 0
	return nil
}
