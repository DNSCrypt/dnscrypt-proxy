package main

import (
	"sync"

	"github.com/VividCortex/ewma"
)

const (
	SizeEstimatorEwmaDecay = 100.0
)

type QuestionSizeEstimator struct {
	sync.RWMutex
	minQuestionSize int
	ewma            ewma.MovingAverage
}

func NewQuestionSizeEstimator() QuestionSizeEstimator {
	return QuestionSizeEstimator{minQuestionSize: InitialMinQuestionSize, ewma: ewma.NewMovingAverage(SizeEstimatorEwmaDecay)}
}

func (questionSizeEstimator *QuestionSizeEstimator) MinQuestionSize() int {
	questionSizeEstimator.RLock()
	minQuestionSize := questionSizeEstimator.minQuestionSize
	questionSizeEstimator.RUnlock()
	return minQuestionSize
}

func (questionSizeEstimator *QuestionSizeEstimator) blindAdjust() {
	questionSizeEstimator.Lock()
	if MaxDNSUDPPacketSize-questionSizeEstimator.minQuestionSize < questionSizeEstimator.minQuestionSize {
		questionSizeEstimator.minQuestionSize = MaxDNSUDPPacketSize
	} else {
		questionSizeEstimator.minQuestionSize *= 2
	}
	questionSizeEstimator.ewma.Set(float64(questionSizeEstimator.minQuestionSize))
	questionSizeEstimator.Unlock()
}

func (questionSizeEstimator *QuestionSizeEstimator) adjust(packetSize int) {
	questionSizeEstimator.Lock()
	questionSizeEstimator.ewma.Add(float64(packetSize))
	ma, minQuestionSize := int(questionSizeEstimator.ewma.Value()), questionSizeEstimator.minQuestionSize
	if ma > InitialMinQuestionSize && ma < minQuestionSize/2 {
		questionSizeEstimator.minQuestionSize = Max(InitialMinQuestionSize, minQuestionSize/2)
	}
	questionSizeEstimator.Unlock()
}
