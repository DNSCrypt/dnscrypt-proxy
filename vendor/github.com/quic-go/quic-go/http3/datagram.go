package http3

import (
	"context"
	"sync"
)

const maxQuarterStreamID = 1<<60 - 1

const streamDatagramQueueLen = 32

type datagrammer struct {
	sendDatagram func([]byte) error

	hasData chan struct{}
	queue   [][]byte // TODO: use a ring buffer

	mx         sync.Mutex
	sendErr    error
	receiveErr error
}

func newDatagrammer(sendDatagram func([]byte) error) *datagrammer {
	return &datagrammer{
		sendDatagram: sendDatagram,
		hasData:      make(chan struct{}, 1),
	}
}

func (d *datagrammer) SetReceiveError(err error) {
	d.mx.Lock()
	defer d.mx.Unlock()

	d.receiveErr = err
	d.signalHasData()
}

func (d *datagrammer) SetSendError(err error) {
	d.mx.Lock()
	defer d.mx.Unlock()

	d.sendErr = err
}

func (d *datagrammer) Send(b []byte) error {
	d.mx.Lock()
	sendErr := d.sendErr
	d.mx.Unlock()
	if sendErr != nil {
		return sendErr
	}

	return d.sendDatagram(b)
}

func (d *datagrammer) signalHasData() {
	select {
	case d.hasData <- struct{}{}:
	default:
	}
}

func (d *datagrammer) enqueue(data []byte) {
	d.mx.Lock()
	defer d.mx.Unlock()

	if d.receiveErr != nil {
		return
	}
	if len(d.queue) >= streamDatagramQueueLen {
		return
	}
	d.queue = append(d.queue, data)
	d.signalHasData()
}

func (d *datagrammer) Receive(ctx context.Context) ([]byte, error) {
start:
	d.mx.Lock()
	if len(d.queue) >= 1 {
		data := d.queue[0]
		d.queue = d.queue[1:]
		d.mx.Unlock()
		return data, nil
	}
	if receiveErr := d.receiveErr; receiveErr != nil {
		d.mx.Unlock()
		return nil, receiveErr
	}
	d.mx.Unlock()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-d.hasData:
	}
	goto start
}
