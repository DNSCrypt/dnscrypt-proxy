//go:build windows

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
	xpc := ipv4.NewPacketConn(pc)

Read:
	for {
		select {
		default:
			r := &Msg{Data: srv.MsgPool.Get()}
			n, _, src, err := xpc.ReadFrom(r.Data)
			r.Data = r.Data[:n]
			if err != nil {
				// here we can call MsgInvalidFunc, as we have one message, in case of ReadBatch we can't
				// really, so also don't do that here.
				srv.MsgPool.Put(r.Data)
				continue Read
			}
			w := &response{conn: pc.(*net.UDPConn), session: &Session{src.(*net.UDPAddr), nil}}
			wg.Add(1) // no wg.Go to prevent defer usage
			go func() {
				srv.serveDNS(w, r)
				wg.Done()
			}()
		case <-srv.shutdown:
			pc.Close()
			wg.Wait()
			srv.once.Do(func() { close(srv.exited) })
			return
		}
	}
}
