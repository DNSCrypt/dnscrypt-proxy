package main

import (
	"net"
	"net/http"

	"github.com/jedisct1/dlog"
)

type localDoHHandler struct {
}

func (handler localDoHHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	dataType := "application/dns-message"
	if request.Header.Get("Content-Type") != dataType {
		writer.WriteHeader(400)
		return
	}
	writer.WriteHeader(200)
	writer.Header().Add("Server", "dnscrypt-proxy")
	writer.Header().Add("Content-Type", "application/dns-message")
	writer.Write([]byte("OK\n"))
}

func (proxy *Proxy) localDoHListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()
	httpServer := &http.Server{ReadTimeout: proxy.timeout, WriteTimeout: proxy.timeout, Handler: localDoHHandler{}}
	if err := httpServer.Serve(acceptPc); err != nil {
		dlog.Fatal(err)
	}
}
