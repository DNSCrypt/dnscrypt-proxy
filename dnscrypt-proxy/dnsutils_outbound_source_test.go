package main

import (
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestDNSExchangeOutboundSource(t *testing.T) {
	sourceIP := usableNonLoopbackIPv4(t)
	policy, err := parseOutboundSourcePolicy(sourceIP.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &Proxy{timeout: 2 * time.Second, outboundSource: policy}
	proxy.xTransport = NewXTransport(&proxy.outboundSource)

	for _, proto := range []string{"udp", "tcp"} {
		for _, relayed := range []bool{false, true} {
			name := proto + "-direct"
			if relayed {
				name = proto + "-relayed"
			}
			t.Run(name, func(t *testing.T) {
				serverAddress, relayAddress, peerCh, closeServer := startSourceObservingDNSServer(t, proto, sourceIP, relayed)
				defer closeServer()
				var relay *DNSCryptRelay
				if relayed {
					relay = &DNSCryptRelay{}
					if proto == "udp" {
						relay.RelayUDPAddr = relayAddress.(*net.UDPAddr)
					} else {
						relay.RelayTCPAddr = relayAddress.(*net.TCPAddr)
					}
				}
				query := dns.NewMsg("example.org.", dns.TypeA)
				response := _dnsExchange(proxy, proto, query, serverAddress, relay, 0)
				if response.err != nil {
					t.Fatal(response.err)
				}
				peer := <-peerCh
				if !peer.Equal(sourceIP) {
					t.Fatalf("peer source = %s, want %s", peer, sourceIP)
				}
			})
		}
	}
}

func startSourceObservingDNSServer(t *testing.T, proto string, destinationIP net.IP, relayed bool) (string, net.Addr, <-chan net.IP, func()) {
	t.Helper()
	peerCh := make(chan net.IP, 1)
	if proto == "udp" {
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			packet := make([]byte, MaxDNSPacketSize)
			length, peer, err := listener.ReadFromUDP(packet)
			if err != nil {
				return
			}
			peerCh <- peer.IP
			if relayed {
				packet = packet[anonymizedDNSHeaderSize:]
				length -= anonymizedDNSHeaderSize
			}
			msg := dns.Msg{Data: packet[:length]}
			if msg.Unpack() != nil {
				return
			}
			msg.Response = true
			if msg.Pack() != nil {
				return
			}
			_, _ = listener.WriteToUDP(msg.Data, peer)
		}()
		port := listener.LocalAddr().(*net.UDPAddr).Port
		relayAddress := &net.UDPAddr{IP: destinationIP, Port: port}
		if !relayed {
			return relayAddress.String(), relayAddress, peerCh, func() { _ = listener.Close() }
		}
		return "9.9.9.9:53", relayAddress, peerCh, func() { _ = listener.Close() }
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		defer conn.Close()
		peerCh <- conn.RemoteAddr().(*net.TCPAddr).IP
		packet, err := ReadPrefixed(conn)
		if err != nil {
			return
		}
		if relayed {
			packet = packet[anonymizedDNSHeaderSize:]
		}
		msg := dns.Msg{Data: packet}
		if msg.Unpack() != nil {
			return
		}
		msg.Response = true
		if msg.Pack() != nil {
			return
		}
		packet, err = PrefixWithSize(msg.Data)
		if err == nil {
			_, _ = conn.Write(packet)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	relayAddress := &net.TCPAddr{IP: destinationIP, Port: port}
	if !relayed {
		return relayAddress.String(), relayAddress, peerCh, func() { _ = listener.Close() }
	}
	return "9.9.9.9:53", relayAddress, peerCh, func() { _ = listener.Close() }
}
