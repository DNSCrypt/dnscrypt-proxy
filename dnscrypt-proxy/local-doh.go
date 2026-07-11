package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

type localDoHHandler struct {
	proxy *Proxy
}

func (handler localDoHHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	proxy := handler.proxy
	if !proxy.clientsCountInc() {
		dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
		return
	}
	defer proxy.clientsCountDec()
	dataType := "application/dns-message"
	writer.Header().Set("Server", "dnscrypt-proxy")
	if request.URL.Path != proxy.localDoHPath {
		writer.WriteHeader(404)
		return
	}
	packet := []byte{}
	var err error
	start := time.Now()
	if request.Method == "POST" &&
		request.Header.Get("Content-Type") == dataType {
		packet, err = io.ReadAll(io.LimitReader(request.Body, int64(MaxDNSPacketSize)))
		if err != nil {
			dlog.Warnf("No body in a local DoH query")
			return
		}
	} else if request.Method == "GET" && request.Header.Get("Accept") == dataType {
		encodedPacket := request.URL.Query().Get("dns")
		if len(encodedPacket) >= MinDNSPacketSize*4/3 && len(encodedPacket) <= MaxDNSPacketSize*4/3 {
			packet, err = base64.RawURLEncoding.DecodeString(encodedPacket)
			if err != nil {
				dlog.Warnf("Invalid base64 in a local DoH query")
				return
			}
		}
	}
	if len(packet) < MinDNSPacketSize {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(400)
		writer.Write([]byte("dnscrypt-proxy local DoH server\n"))
		return
	}
	clientAddr, err := net.ResolveTCPAddr("tcp", request.RemoteAddr)
	if err != nil {
		dlog.Errorf("Unable to get the client address: [%v]", err)
		return
	}
	xClientAddr := net.Addr(clientAddr)
	hasEDNS0Padding, err := hasEDNS0Padding(packet)
	if err != nil {
		writer.WriteHeader(400)
		return
	}
	response := proxy.processIncomingQuery("local_doh", proxy.xTransport.mainProto, packet, &xClientAddr, nil, start, false)
	if len(response) == 0 {
		writer.WriteHeader(500)
		return
	}
	msg := dns.Msg{Data: response}
	if err := msg.Unpack(); err != nil {
		writer.WriteHeader(400)
		return
	}
	if hasEDNS0Padding {
		response, err = addLocalDoHResponsePadding(&msg)
		if err != nil {
			dlog.Critical(err)
			writer.WriteHeader(500)
			return
		}
	} else {
		responseLen := len(response)
		padLen := dohPaddedLen(responseLen) - responseLen
		pad := strings.Repeat("X", padLen)
		writer.Header().Set("X-Pad", pad)
	}
	writer.Header().Set("Content-Type", dataType)
	writer.Header().Set("Content-Length", fmt.Sprint(len(response)))
	writer.WriteHeader(200)
	writer.Write(response)
}

func addLocalDoHResponsePadding(msg *dns.Msg) ([]byte, error) {
	original := append([]byte(nil), msg.Data...)
	if msg.UDPSize == 0 {
		msg.UDPSize = uint16(MaxDNSPacketSize)
	}
	var paddingRR *dns.PADDING
	for _, rr := range msg.Pseudo {
		if padding, ok := rr.(*dns.PADDING); ok {
			paddingRR = padding
			paddingRR.Padding = ""
			break
		}
	}
	if paddingRR == nil {
		paddingRR = &dns.PADDING{}
		msg.Pseudo = append(msg.Pseudo, paddingRR)
	}
	if err := msg.Pack(); err != nil {
		return nil, err
	}
	if len(msg.Data) > MaxDNSPacketSize {
		return original, nil
	}
	paddingLen := dohPaddedLen(len(msg.Data)) - len(msg.Data)
	paddingRR.Padding = strings.Repeat("58", paddingLen)
	if err := msg.Pack(); err != nil {
		return nil, err
	}
	return msg.Data, nil
}

func (proxy *Proxy) localDoHListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()
	if len(proxy.localDoHCertFile) == 0 || len(proxy.localDoHCertKeyFile) == 0 {
		dlog.Fatal("A certificate and a key are required to start a local DoH service")
	}
	httpServer := &http.Server{
		ReadTimeout:  proxy.timeout,
		WriteTimeout: proxy.timeout,
		Handler:      localDoHHandler{proxy: proxy},
	}
	httpServer.SetKeepAlivesEnabled(true)
	if err := httpServer.ServeTLS(acceptPc, proxy.localDoHCertFile, proxy.localDoHCertKeyFile); err != nil {
		dlog.Fatal(err)
	}
}

func dohPaddedLen(unpaddedLen int) int {
	boundaries := [...]int{
		64,
		128,
		192,
		256,
		320,
		384,
		512,
		704,
		768,
		896,
		960,
		1024,
		1088,
		1152,
		2688,
		4080,
		MaxDNSPacketSize,
	}
	for _, boundary := range boundaries {
		if boundary >= unpaddedLen {
			return boundary
		}
	}
	return unpaddedLen
}
