package main

import (
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/jedisct1/dlog"
)

type localDoHHandler struct {
	proxy *Proxy
}

func (handler localDoHHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	proxy := handler.proxy
	dataType := "application/dns-message"
	writer.Header().Set("Server", "dnscrypt-proxy")
	if request.URL.Path != proxy.localDoHPath {
		writer.WriteHeader(404)
		return
	}
	if request.Header.Get("Content-Type") != dataType {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(400)
		writer.Write([]byte("dnscrypt-proxy local DoH server\n"))
		return
	}
	start := time.Now()
	clientAddr, err := net.ResolveTCPAddr("tcp", request.RemoteAddr)
	if err != nil {
		dlog.Errorf("Unable to get the client address: [%v]", err)
		return
	}
	xClientAddr := net.Addr(clientAddr)
	packet, err := ioutil.ReadAll(io.LimitReader(request.Body, MaxHTTPBodyLength))
	if err != nil {
		dlog.Warnf("No body in a local DoH query")
		return
	}
	response := proxy.processIncomingQuery(proxy.serversInfo.getOne(), "local_doh", proxy.mainProto, packet, &xClientAddr, nil, start)
	if len(response) == 0 {
		writer.WriteHeader(500)
		return
	}
	writer.Header().Set("Content-Type", dataType)
	writer.WriteHeader(200)
	writer.Write(response)
}

func (proxy *Proxy) localDoHListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()
	noh2 := make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpServer := &http.Server{
		ReadTimeout:  proxy.timeout,
		WriteTimeout: proxy.timeout,
		TLSNextProto: noh2,
		Handler:      localDoHHandler{proxy: proxy},
	}
	httpServer.SetKeepAlivesEnabled(true)
	if err := httpServer.ServeTLS(acceptPc, proxy.localDoHCertFile, proxy.localDoHCertKeyFile); err != nil {
		dlog.Fatal(err)
	}
}
