package main

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

const dohMediaType = "application/dns-message"

var xPadHeaderCache sync.Map // map[int]string

type localDoHHandler struct {
	proxy *Proxy
}

func (h localDoHHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxy := h.proxy
	if proxy == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if !proxy.clientsCountInc() {
		dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
		http.Error(w, "too many incoming connections", http.StatusServiceUnavailable)
		return
	}
	defer proxy.clientsCountDec()

	w.Header().Set("Server", "dnscrypt-proxy")

	if r.URL.Path != proxy.localDoHPath {
		http.NotFound(w, r)
		return
	}

	packet, start, err := readDoHPacket(r)
	if err != nil {
		// Keep responses simple and standards-friendly.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clientAddr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		dlog.Errorf("Unable to get the client address: [%v]", err)
		http.Error(w, "bad client address", http.StatusBadRequest)
		return
	}
	xClientAddr := net.Addr(clientAddr)

	msg := dns.Msg{Data: packet}
	if err := msg.Unpack(); err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}

	hadPadding, err := hasEDNS0PaddingInMsg(&msg)
	if err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}

	response := proxy.processIncomingQuery(
		"local_doh",
		proxy.xTransport.mainProto,
		packet,
		&xClientAddr,
		nil,
		start,
		false,
	)
	if len(response) == 0 {
		http.Error(w, "upstream failure", http.StatusInternalServerError)
		return
	}

	response, err = applyDoHPadding(w, &msg, response, hadPadding)
	if err != nil {
		dlog.Critical(err)
		http.Error(w, "padding failure", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", dohMediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func readDoHPacket(r *http.Request) (packet []byte, start time.Time, err error) {
	start = time.Now()

	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != dohMediaType {
			return nil, start, errors.New("invalid content type")
		}
		packet, err = io.ReadAll(io.LimitReader(r.Body, int64(MaxDNSPacketSize)))
		if err != nil {
			return nil, start, errors.New("unable to read body")
		}

	case http.MethodGet:
		if r.Header.Get("Accept") != dohMediaType {
			return nil, start, errors.New("invalid accept header")
		}
		encoded := r.URL.Query().Get("dns")
		if len(encoded) < MinDNSPacketSize*4/3 || len(encoded) > MaxDNSPacketSize*4/3 {
			return nil, start, errors.New("missing or invalid dns parameter")
		}
		packet, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, start, errors.New("invalid base64")
		}

	default:
		return nil, start, errors.New("method not allowed")
	}

	if len(packet) < MinDNSPacketSize {
		return nil, start, errors.New("dns message too short")
	}

	return packet, start, nil
}

func applyDoHPadding(w http.ResponseWriter, q *dns.Msg, response []byte, clientHadPadding bool) ([]byte, error) {
	responseLen := len(response)
	paddedLen := dohPaddedLen(responseLen)
	padLen := paddedLen - responseLen
	if padLen <= 0 {
		return response, nil
	}

	if clientHadPadding {
		return addEDNS0PaddingIfNoneFound(q, response, padLen)
	}

	// If the client didn't send padding, mimic previous behavior: use a header.
	w.Header().Set("X-Pad", xPadHeader(padLen))
	return response, nil
}

func hasEDNS0PaddingInMsg(msg *dns.Msg) (bool, error) {
	if msg == nil {
		return false, errors.New("nil DNS message")
	}
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.PADDING); ok {
			return true, nil
		}
	}
	return false, nil
}

func xPadHeader(padLen int) string {
	if padLen <= 0 {
		return ""
	}
	if v, ok := xPadHeaderCache.Load(padLen); ok {
		// Cache values are only stored by xPadHeader and are always strings.
		return v.(string)
	}
	val := strings.Repeat("X", padLen)
	xPadHeaderCache.Store(padLen, val)
	return val
}

func (proxy *Proxy) localDoHListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()

	if proxy == nil {
		dlog.Fatal("Proxy is nil")
	}
	if proxy.localDoHCertFile == "" || proxy.localDoHCertKeyFile == "" {
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
