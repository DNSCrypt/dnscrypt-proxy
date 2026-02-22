//go:build unix

package dns

import (
	"net"
	"sync"

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

		msgs[i].OOB = make([]byte, oobSize)
	}

	udpConn := pc.(*net.UDPConn)
Read:
	for {
		select {
		default:
			// If we set the read deadline is will timeout every ReadTimeout and reallocate the msgs, we are
			// also a server, so just wait for incoming messages.

			n, err := xpc.ReadBatch(msgs, 0)
			if err != nil {
				continue Read
			}
			_ = msgs[:n] // eliminate further bounds checking

			for i := range msgs[:n] {
				r := &Msg{Data: srv.MsgPool.Get()}
				copy(r.Data, msgs[i].Buffers[0][:msgs[i].N])
				r.Data = r.Data[:msgs[i].N]

				oob := make([]byte, oobSize)
				copy(oob, msgs[i].OOB[:msgs[i].NN])

				w := &response{conn: udpConn, session: &Session{msgs[i].Addr.(*net.UDPAddr), oob}}
				wg.Add(1) // no wg.Go to prevent defer usage
				go func() {
					srv.serveDNS(w, r)
					wg.Done()
				}()

				bufs[i] = bufs[i][:0]
			}
		case <-srv.shutdown:
			pc.Close()
			wg.Wait()
			srv.once.Do(func() { close(srv.exited) })
			return
		}
	}
}
