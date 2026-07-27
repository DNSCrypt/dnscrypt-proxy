package quic

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
)

type streamFlowController struct {
	receiveFlowController

	bytesSent     protocol.ByteCount
	sendWindow    protocol.ByteCount
	lastBlockedAt protocol.ByteCount

	streamID protocol.StreamID

	connection *connectionFlowController

	receivedFinalOffset bool
}

// newStreamFlowController gets a new flow controller for a stream.
func newStreamFlowController(
	streamID protocol.StreamID,
	cfc *connectionFlowController,
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	initialSendWindow protocol.ByteCount,
	rttStats *utils.RTTStats,
	logger utils.Logger,
) *streamFlowController {
	return &streamFlowController{
		streamID:   streamID,
		connection: cfc,
		sendWindow: initialSendWindow,
		receiveFlowController: receiveFlowController{
			rttStats:             rttStats,
			receiveWindow:        receiveWindow,
			receiveWindowSize:    receiveWindow,
			maxReceiveWindowSize: maxReceiveWindow,
			logger:               logger,
		},
	}
}

// UpdateHighestReceived updates the highestReceived value, if the offset is higher.
func (c *streamFlowController) UpdateHighestReceived(offset protocol.ByteCount, final bool, now monotime.Time) error {
	// If the final offset for this stream is already known, check for consistency.
	if c.receivedFinalOffset {
		// If we receive another final offset, check that it's the same.
		if final && offset != c.highestReceived {
			return &qerr.TransportError{
				ErrorCode:    qerr.FinalSizeError,
				ErrorMessage: fmt.Sprintf("received inconsistent final offset for stream %d (old: %d, new: %d bytes)", c.streamID, c.highestReceived, offset),
			}
		}
		// Check that the offset is below the final offset.
		if offset > c.highestReceived {
			return &qerr.TransportError{
				ErrorCode:    qerr.FinalSizeError,
				ErrorMessage: fmt.Sprintf("received offset %d for stream %d, but final offset was already received at %d", offset, c.streamID, c.highestReceived),
			}
		}
	}

	if final {
		c.receivedFinalOffset = true
	}
	if offset == c.highestReceived {
		return nil
	}
	// A higher offset was received before. This can happen due to reordering.
	if offset < c.highestReceived {
		if final {
			return &qerr.TransportError{
				ErrorCode:    qerr.FinalSizeError,
				ErrorMessage: fmt.Sprintf("received final offset %d for stream %d, but already received offset %d before", offset, c.streamID, c.highestReceived),
			}
		}
		return nil
	}

	// If this is the first frame received for this stream, start flow-control auto-tuning.
	if c.highestReceived == 0 {
		c.startNewAutoTuningEpoch(now)
	}
	increment := offset - c.highestReceived
	c.highestReceived = offset

	if c.checkFlowControlViolation() {
		return &qerr.TransportError{
			ErrorCode:    qerr.FlowControlError,
			ErrorMessage: fmt.Sprintf("received %d bytes on stream %d, allowed %d bytes", offset, c.streamID, c.receiveWindow),
		}
	}
	return c.connection.IncrementHighestReceived(increment, now)
}

func (c *streamFlowController) AddBytesRead(n protocol.ByteCount) (hasStreamWindowUpdate, hasConnWindowUpdate bool) {
	c.mutex.Lock()
	c.addBytesRead(n)
	hasStreamWindowUpdate = c.shouldQueueWindowUpdate()
	c.mutex.Unlock()
	hasConnWindowUpdate = c.connection.AddBytesRead(n)
	return
}

func (c *streamFlowController) Abandon() {
	c.mutex.Lock()
	unread := c.highestReceived - c.bytesRead
	c.bytesRead = c.highestReceived
	c.mutex.Unlock()
	if unread > 0 {
		c.connection.AddBytesRead(unread)
	}
}

func (c *streamFlowController) UpdateSendWindow(offset protocol.ByteCount) (updated bool) {
	if offset > c.sendWindow {
		c.sendWindow = offset
		return true
	}
	return false
}

// TryAddBytesSent adds n bytes if sufficient stream- and connection-level send credit is available.
func (c *streamFlowController) TryAddBytesSent(n protocol.ByteCount) bool {
	if c.bytesSent > c.sendWindow || n > c.sendWindow-c.bytesSent {
		return false
	}
	if !c.connection.TryAddBytesSent(n) {
		return false
	}
	c.bytesSent += n
	return true
}

// AddBytesSentWithLimiter adds the limiter-approved portion of the available stream- and connection-level send credit.
func (c *streamFlowController) AddBytesSentWithLimiter(
	n protocol.ByteCount,
	limiter func(int) int,
) (protocol.ByteCount, bool) {
	if c.bytesSent >= c.sendWindow {
		return 0, false
	}
	n = min(n, c.sendWindow-c.bytesSent)
	added, limited := c.connection.AddBytesSentWithLimiter(n, limiter)
	c.bytesSent += added
	return added, limited
}

func (c *streamFlowController) SendWindowSize() protocol.ByteCount {
	return min(c.sendWindow-c.bytesSent, c.connection.SendWindowSize())
}

func (c *streamFlowController) IsNewlyBlocked() bool {
	blocked, _ := c.isNewlyBlocked()
	return blocked
}

func (c *streamFlowController) isNewlyBlocked() (bool, protocol.ByteCount) {
	if c.bytesSent < c.sendWindow || c.sendWindow == c.lastBlockedAt {
		return false, 0
	}
	c.lastBlockedAt = c.sendWindow
	return true, c.sendWindow
}

func (c *streamFlowController) shouldQueueWindowUpdate() bool {
	return !c.receivedFinalOffset && c.hasWindowUpdate()
}

func (c *streamFlowController) GetWindowUpdate(now monotime.Time) protocol.ByteCount {
	// If we already received the final offset for this stream, the peer won't need any additional flow control credit.
	if c.receivedFinalOffset {
		return 0
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	oldWindowSize := c.receiveWindowSize
	offset := c.getWindowUpdate(now)
	if c.receiveWindowSize > oldWindowSize { // auto-tuning enlarged the window size
		c.logger.Debugf("Increasing receive flow control window for stream %d to %d", c.streamID, c.receiveWindowSize)
		c.connection.EnsureMinimumWindowSize(
			protocol.ByteCount(float64(c.receiveWindowSize)*protocol.ConnectionFlowControlMultiplier),
			now,
		)
	}
	return offset
}
