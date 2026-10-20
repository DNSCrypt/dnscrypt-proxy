package quic

import (
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type receiveFlowController struct {
	//nolint:structcheck // The mutex is used both by the stream and the connection flow controller
	mutex                sync.Mutex
	bytesRead            protocol.ByteCount
	highestReceived      protocol.ByteCount
	receiveWindow        protocol.ByteCount
	receiveWindowSize    protocol.ByteCount
	maxReceiveWindowSize protocol.ByteCount

	allowWindowIncrease func(size protocol.ByteCount) bool

	epochStartTime   monotime.Time
	epochStartOffset protocol.ByteCount
	rttStats         *utils.RTTStats

	logger utils.Logger
}

// needs to be called with locked mutex
func (c *receiveFlowController) addBytesRead(n protocol.ByteCount) {
	c.bytesRead += n
}

func (c *receiveFlowController) hasWindowUpdate() bool {
	bytesRemaining := c.receiveWindow - c.bytesRead
	// update the window when more than the threshold was consumed
	return bytesRemaining <= protocol.ByteCount(float64(c.receiveWindowSize)*(1-protocol.WindowUpdateThreshold))
}

// getWindowUpdate updates the receive window, if necessary
// it returns the new offset
func (c *receiveFlowController) getWindowUpdate(now monotime.Time) protocol.ByteCount {
	if !c.hasWindowUpdate() {
		return 0
	}

	c.maybeAdjustWindowSize(now)
	c.receiveWindow = c.bytesRead + c.receiveWindowSize
	return c.receiveWindow
}

// maybeAdjustWindowSize increases the receiveWindowSize if we're sending updates too often.
// For details about auto-tuning, see https://docs.google.com/document/d/1SExkMmGiz8VYzV3s9E35JQlJ73vhzCekKkDi85F1qCE/edit?usp=sharing.
func (c *receiveFlowController) maybeAdjustWindowSize(now monotime.Time) {
	bytesReadInEpoch := c.bytesRead - c.epochStartOffset
	// don't do anything if less than half the window has been consumed
	if bytesReadInEpoch <= c.receiveWindowSize/2 {
		return
	}
	rtt := c.rttStats.SmoothedRTT()
	if rtt == 0 {
		return
	}

	fraction := float64(bytesReadInEpoch) / float64(c.receiveWindowSize)
	if now.Sub(c.epochStartTime) < time.Duration(4*fraction*float64(rtt)) {
		// window is consumed too fast, try to increase the window size
		newSize := min(2*c.receiveWindowSize, c.maxReceiveWindowSize)
		if newSize > c.receiveWindowSize && (c.allowWindowIncrease == nil || c.allowWindowIncrease(newSize-c.receiveWindowSize)) {
			c.receiveWindowSize = newSize
		}
	}
	c.startNewAutoTuningEpoch(now)
}

func (c *receiveFlowController) startNewAutoTuningEpoch(now monotime.Time) {
	c.epochStartTime = now
	c.epochStartOffset = c.bytesRead
}

func (c *receiveFlowController) checkFlowControlViolation() bool {
	return c.highestReceived > c.receiveWindow
}
