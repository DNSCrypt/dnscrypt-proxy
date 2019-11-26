package main

import (
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
	dataType := "application/dns-message"
	if request.Header.Get("Content-Type") != dataType {
		writer.WriteHeader(400)
		return
	}
	proxy := handler.proxy
	start := time.Now()
	clientAddr, err := net.ResolveTCPAddr("tcp", request.RemoteAddr)
	if err != nil {
		dlog.Errorf("Unable to get the client address: [%v]", err)
		return
	}
	xClientAddr := net.Addr(clientAddr)
	packet, err := ioutil.ReadAll(request.Body)
	if err != nil {
		dlog.Warnf("No body in a local DoH query")
		return
	}
	response := proxy.processIncomingQuery(proxy.serversInfo.getOne(), "tcp", "tcp", packet, &xClientAddr, nil, start)
	if len(response) == 0 {
		writer.WriteHeader(500)
		return
	}
	writer.WriteHeader(200)
	writer.Header().Add("Server", "dnscrypt-proxy")
	writer.Header().Add("Content-Type", "application/dns-message")
	writer.Write(response)
}

func (proxy *Proxy) localDoHListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()
	httpServer := &http.Server{
		ReadTimeout:  proxy.timeout,
		WriteTimeout: proxy.timeout,
		Handler:      localDoHHandler{proxy: proxy},
	}
	if err := httpServer.Serve(acceptPc); err != nil {
		dlog.Fatal(err)
	}
}
