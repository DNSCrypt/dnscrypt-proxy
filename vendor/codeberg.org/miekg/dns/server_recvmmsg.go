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

	bufs := make([][]byte, srv.BatchSize)
	msgs := make([]ipv4.Message, srv.BatchSize)
	for i := range srv.BatchSize {
		bufs[i] = make([]byte, srv.UDPSize)
		msgs[i].Buffers = [][]byte{bufs[i]}
		msgs[i].OOB = make([]byte, oobSize)
	}

Read:
	for {
		select {
		case <-srv.shutdown:
			pc.Close()
			wg.Wait()
			srv.once.Do(func() { close(srv.exited) })
			return
		default:

			// if we set the read deadline is will timeout every ReadTimeout and reallocate the msgs, we are
			// also a server, so just wait for incoming messages.

			n, err := xpc.ReadBatch(msgs, 0)
			if err != nil {
				continue Read
			}
			for _, msg := range msgs[:n] {

				r := &Msg{Data: srv.MsgPool.Get()}
				copy(r.Data, msg.Buffers[0][:msg.N])
				r.Data = r.Data[:msg.N]

				oob := make([]byte, oobSize)
				copy(oob, msg.OOB[:msg.NN])

				w := &response{conn: pc.(*net.UDPConn), session: &Session{msg.Addr.(*net.UDPAddr), oob}}
				wg.Add(1) // no wg.Go to prevent defer usage
				go func() {
					srv.serveDNS(w, r)
					wg.Done()
				}()
			}
		}
	}
}
