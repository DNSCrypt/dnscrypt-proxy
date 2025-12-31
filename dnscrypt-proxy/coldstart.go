package main

import (
    "bufio"
    "errors"
    "fmt"
    "net"
    "net/netip"
    "os"
    "strings"
    "sync"

    "codeberg.org/miekg/dns"
    "codeberg.org/miekg/dns/rdata"
    "github.com/jedisct1/dlog"
)

// Use netip.Addr for zero-allocation IP storage
type CaptivePortalEntryIPs []netip.Addr

type CaptivePortalMap map[string]CaptivePortalEntryIPs

type CaptivePortalHandler struct {
    wg    sync.WaitGroup
    mu    sync.Mutex
    conns []*net.UDPConn
}

func (h *CaptivePortalHandler) Stop() {
    h.mu.Lock()
    for _, conn := range h.conns {
        // Closing the connection will cause ReadFrom to return an error,
        // unblocking the listener goroutines immediately.
        conn.Close()
    }
    h.conns = nil
    h.mu.Unlock()
    h.wg.Wait()
}

func (ipsMap *CaptivePortalMap) GetEntry(msg *dns.Msg) (dns.RR, *CaptivePortalEntryIPs) {
    if len(msg.Question) != 1 {
        return nil, nil
    }
    question := msg.Question[0]
    hdr := question.Header()
    name, err := NormalizeQName(hdr.Name)
    if err != nil {
        return nil, nil
    }
    ips, ok := (*ipsMap)[name]
    if !ok {
        return nil, nil
    }
    if hdr.Class != dns.ClassINET {
        return nil, nil
    }
    return question, &ips
}

func HandleCaptivePortalQuery(msg *dns.Msg, question dns.RR, ips *CaptivePortalEntryIPs) *dns.Msg {
    respMsg := EmptyResponseFromMessage(msg)
    ttl := uint32(1)
    hdr := question.Header()
    qtype := dns.RRToType(question)

    if qtype == dns.TypeA {
        for _, ip := range *ips {
            if ip.Is4() {
                rr := new(dns.A)
                rr.Hdr = dns.Header{Name: hdr.Name, Class: dns.ClassINET, TTL: ttl}
                rr.A = rdata.A{Addr: ip}
                respMsg.Answer = append(respMsg.Answer, rr)
            }
        }
    } else if qtype == dns.TypeAAAA {
        for _, ip := range *ips {
            if ip.Is6() {
                rr := new(dns.AAAA)
                rr.Hdr = dns.Header{Name: hdr.Name, Class: dns.ClassINET, TTL: ttl}
                rr.AAAA = rdata.AAAA{Addr: ip}
                respMsg.Answer = append(respMsg.Answer, rr)
            }
        }
    }

    qTypeStr, ok := dns.TypeToString[qtype]
    if !ok {
        qTypeStr = fmt.Sprint(qtype)
    }
    // Use Debugf instead of Infof for hot paths to avoid log spam affecting performance
    dlog.Debugf("Query for captive portal detection: [%v] (%v)", hdr.Name, qTypeStr)
    return respMsg
}

func addColdStartListener(
    ipsMap *CaptivePortalMap,
    listenAddrStr string,
    h *CaptivePortalHandler,
) error {
    network := "udp"
    if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
        network = "udp4"
    }
    listenUDPAddr, err := net.ResolveUDPAddr(network, listenAddrStr)
    if err != nil {
        return err
    }
    clientPc, err := net.ListenUDP(network, listenUDPAddr)
    if err != nil {
        return err
    }

    h.mu.Lock()
    h.conns = append(h.conns, clientPc)
    h.mu.Unlock()

    h.wg.Add(1)
    go func() {
        defer h.wg.Done()
        
        // Allocating buffer once outside the loop reuses memory for all packets
        buffer := make([]byte, MaxDNSPacketSize)
        
        for {
            // No SetDeadline needed; Close() handles unblocking
            length, clientAddr, err := clientPc.ReadFrom(buffer)
            if err != nil {
                // Check if error is due to socket closing
                if errors.Is(err, net.ErrClosed) {
                    return
                }
                dlog.Warn(err)
                continue
            }

            packet := buffer[:length]
            msg := &dns.Msg{}
            // unpack directly from the reused buffer
            if err := msg.Unpack(packet); err != nil {
                continue
            }

            question, ips := ipsMap.GetEntry(msg)
            if ips == nil {
                continue
            }

            respMsg := HandleCaptivePortalQuery(msg, question, ips)
            if respMsg == nil {
                continue
            }

            if packed, err := respMsg.Pack(); err == nil {
                clientPc.WriteTo(packed, clientAddr)
            }
        }
    }()
    return nil
}

func ColdStart(proxy *Proxy) (*CaptivePortalHandler, error) {
    if len(proxy.captivePortalMapFile) == 0 {
        return nil, nil
    }

    // Use bufio.Scanner for efficient file reading
    file, err := os.Open(proxy.captivePortalMapFile)
    if err != nil {
        dlog.Warn(err)
        return nil, err
    }
    defer file.Close()

    ipsMap := make(CaptivePortalMap)
    scanner := bufio.NewScanner(file)
    lineNo := 0

    for scanner.Scan() {
        lineNo++
        line := scanner.Text()
        line = TrimAndStripInlineComments(line)
        if len(line) == 0 {
            continue
        }
        name, ipsStr, ok := StringTwoFields(line)
        if !ok {
            return nil, fmt.Errorf(
                "Syntax error for a captive portal rule at line %d",
                lineNo,
            )
        }
        name, err = NormalizeQName(name)
        if err != nil {
            continue
        }
        if strings.Contains(ipsStr, "*") {
            return nil, fmt.Errorf(
                "A captive portal rule must use an exact host name at line %d",
                lineNo,
            )
        }

        var ips []netip.Addr
        for _, ipStr := range strings.Split(ipsStr, ",") {
            ipStr = strings.TrimSpace(ipStr)
            if ip, err := netip.ParseAddr(ipStr); err == nil {
                ips = append(ips, ip)
            } else {
                return nil, fmt.Errorf(
                    "Syntax error for a captive portal rule at line %d",
                    lineNo,
                )
            }
        }
        ipsMap[name] = ips
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    handler := &CaptivePortalHandler{}
    
    ok := false
    for _, listenAddrStr := range proxy.listenAddresses {
        if err := addColdStartListener(&ipsMap, listenAddrStr, handler); err == nil {
            ok = true
        }
    }

    if ok {
        proxy.captivePortalMap = &ipsMap
        return handler, nil
    }
    
    // If no listeners started, clean up any that might have
    handler.Stop()
    return handler, err
}
