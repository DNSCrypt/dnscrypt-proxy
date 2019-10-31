// +build !android

package dnscrypt

import (
	"fmt"
	"io"
	"net"

	"github.com/coreos/go-systemd/activation"
	"github.com/jedisct1/dlog"
)

type multiCloser []io.Closer

func (mc multiCloser) Close() (err error) {
	for _, c := range mc {
		err = c.Close()
	}
	return err
}

func (proxy *Proxy) SystemDListeners() (io.Closer, error) {
	files := activation.Files(true)

	if len(files) > 0 {
		if len(proxy.userName) > 0 || proxy.child {
			dlog.Fatal("Systemd activated sockets are incompatible with privilege dropping. Remove activated sockets and fill `listen_addresses` in the dnscrypt-proxy configuration file instead.")
		}
		dlog.Warn("Systemd sockets are untested and unsupported - use at your own risk")
	}
	var mc multiCloser
	for i, file := range files {
		defer file.Close()
		ok := false
		if listener, err := net.FileListener(file); err == nil {
			dlog.Noticef("Wiring systemd TCP socket #%d, %s, %s", i, file.Name(), listener.Addr())
			ok = true
			mc = append(mc, listener)
			go proxy.tcpListener(listener.(*net.TCPListener))
		} else if pc, err := net.FilePacketConn(file); err == nil {
			dlog.Noticef("Wiring systemd UDP socket #%d, %s, %s", i, file.Name(), pc.LocalAddr())
			ok = true
			mc = append(mc, pc)
			go proxy.udpListener(pc.(*net.UDPConn))
		}
		if !ok {
			return nil, fmt.Errorf("Could not wire systemd socket #%d, %s", i, file.Name())
		}
	}

	return mc, nil
}
