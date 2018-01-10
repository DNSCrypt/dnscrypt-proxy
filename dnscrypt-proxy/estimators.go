package main

import "sync"

type QuestionSizeEstimator struct {
	sync.RWMutex
	minQuestionSize int
}

func NewQuestionSizeEstimator() QuestionSizeEstimator {
	return QuestionSizeEstimator{minQuestionSize: InitialMinQuestionSize}
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
	questionSizeEstimator.Unlock()
}
