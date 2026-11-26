//go:build unix

package dns

import (
	"net"
	"sync"

	"codeberg.org/miekg/dns/internal/udpoob"
	"golang.org/x/net/ipv4"
)

// listenUDP starts a UDP listener for the server.
func (srv *Server) listenUDP(pc net.PacketConn) {
	if f := srv.NotifyStartedFunc; f != nil {
		f(srv.ctx)
	}

	var wg sync.WaitGroup
	xpc := ipv4.NewPacketConn(pc) // suspect this somehow works on Linux, but not other OSes.

	slab := make([]byte, BatchSize*srv.UDPSize)

	bufs := make([][]byte, BatchSize)
	msgs := make([]ipv4.Message, BatchSize)

	for i := range BatchSize {
		start := i * srv.UDPSize

		bufs[i] = slab[start : start+srv.UDPSize]
		msgs[i].Buffers = [][]byte{bufs[i]}

		msgs[i].OOB = make([]byte, udpoob.Size)
	}

	udpConn := pc.(*net.UDPConn)
	writer := &udpWriter{xpc: xpc, pool: srv.MsgPool, ch: make(chan udpReply, 4*BatchSize), exited: make(chan struct{})}
	go writer.serve()

	for {
		select {
		case <-srv.shutdown:
			pc.Close()
			wg.Wait()
			close(writer.exited)
			close(srv.exited)
			return
		default:
		}

		// If we set the read deadline is will timeout every ReadTimeout and reallocate the msgs, we are
		// also a server, so just wait for incoming messages.

		n, err := xpc.ReadBatch(msgs, 0)
		if err != nil {
			continue
		}

		wg.Add(n)
		for i := range msgs[:n] {
			r := &Msg{Data: srv.MsgPool.Get()}
			copy(r.Data, msgs[i].Buffers[0][:msgs[i].N])
			r.Data = r.Data[:msgs[i].N]

			oob := make([]byte, msgs[i].NN)
			copy(oob, msgs[i].OOB[:msgs[i].NN])

			w := &response{conn: udpConn, sess: &Session{Addr: msgs[i].Addr.(*net.UDPAddr), OOB: oob, writer: writer}}
			go func() {
				srv.serveDNS(w, r)
				wg.Done()
			}()
		}
	}
}
