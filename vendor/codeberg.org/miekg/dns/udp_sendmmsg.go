//go:build unix

package dns

import (
	"net"
	"runtime"

	"codeberg.org/miekg/dns/pkg/pool"
	"golang.org/x/net/ipv4"
)

// udpWriter writes the replies for a UDP socket from a single goroutine. A handler hands its reply over with
// write and continues. The goroutine takes a reply plus whatever other replies are already waiting and
// writes them with one sendmmsg(2). So it never waits to fill a batch: under load replies queue up while
// the previous write is busy, otherwise each reply is written on its own.
type udpWriter struct {
	xpc    *ipv4.PacketConn
	pool   pool.Pooler
	ch     chan udpReply
	exited chan struct{}
}

type udpReply struct {
	data []byte // a buffer from pool
	oob  []byte
	addr net.Addr
}

// write hands a copy of data over as the reply for sess. It returns false when too many replies are waiting,
// the caller must then write data itself.
func (w *udpWriter) write(sess *Session, data []byte) bool {
	r := udpReply{append(w.pool.Get()[:0], data...), sourceFromOOB(sess.OOB), sess.Addr}
	select {
	case w.ch <- r:
		return true
	default:
		w.pool.Put(r.data)
		return false
	}
}

func (w *udpWriter) serve() {
	msgs := make([]ipv4.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
	}
	for {
		var r udpReply
		select {
		case r = <-w.ch:
		case <-w.exited:
			return
		}
		runtime.Gosched() // Let the handler goroutines that are already runnable finish and queue theirs, so the drain below finds them.
		n := 0
	Fill: // r, and what else is already waiting
		for {
			msgs[n].Buffers[0], msgs[n].OOB, msgs[n].Addr = r.data, r.oob, r.addr
			if n++; n == len(msgs) {
				break
			}
			select {
			case r = <-w.ch:
			default:
				break Fill
			}
		}
		for off := 0; off < n; {
			k, err := w.xpc.WriteBatch(msgs[off:n], 0)
			if err != nil || k == 0 {
				break // as with a failed write, these replies are lost
			}
			off += k
		}
		for i := range msgs[:n] {
			w.pool.Put(msgs[i].Buffers[0])
		}
	}
}
