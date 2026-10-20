//go:build go1.27

package handshake

import (
	"crypto/tls"
	"net"
)

func setupConfigForClient(conf *tls.Config) *tls.Config {
	return conf
}

func setupConfigForServer(conf *tls.Config, _, _ net.Addr) *tls.Config {
	return conf
}

func getQUICConfig(tlsConf *tls.Config, localAddr, remoteAddr net.Addr) *tls.QUICConfig {
	return &tls.QUICConfig{
		TLSConfig:           tlsConf,
		EnableSessionEvents: true,
		ClientHelloInfoConn: &conn{localAddr: localAddr, remoteAddr: remoteAddr},
	}
}
