package main

import (
    "context"
    "errors"
    "fmt"
    "math/rand"
    "net"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "codeberg.org/miekg/dns"
    "github.com/jedisct1/dlog"
    "github.com/lifenjoiner/dhcpdns"
)

type SearchSequenceItemType int

const (
    Explicit SearchSequenceItemType = iota
    Bootstrap
    DHCP
)

type SearchSequenceItem struct {
    typ     SearchSequenceItemType
    servers []string
}

type PluginForwardEntry struct {
    domain   string
    sequence []SearchSequenceItem
}

type forwardRules struct {
    bySuffix map[string][]SearchSequenceItem
}

type PluginForward struct {
    bootstrapResolvers []string
    dhcpdns            []*dhcpdns.Detector

    configFile    string
    configWatcher *ConfigWatcher

    proxy *Proxy

    rules        atomic.Value
    stagingRules *forwardRules

    udpClient dns.Client
    tcpClient dns.Client

    tcpPoolsMu sync.Mutex
    tcpPools   map[string]chan net.Conn

    dhcpCache atomic.Value

    rngSeed uint64
    rngPool sync.Pool
}

func (plugin *PluginForward) Name() string {
    return "forward"
}

func (plugin *PluginForward) Description() string {
    return "Route queries matching specific domains to a dedicated set of servers"
}

func (plugin *PluginForward) Init(proxy *Proxy) error {
    plugin.proxy = proxy
    plugin.configFile = proxy.forwardFile
    dlog.Noticef("Loading the set of forwarding rules from [%s]", plugin.configFile)

    if proxy.xTransport != nil {
        plugin.bootstrapResolvers = proxy.xTransport.bootstrapResolvers
    }

    plugin.udpClient = dns.Client{}
    plugin.tcpClient = dns.Client{}
    plugin.tcpPools = make(map[string]chan net.Conn)

    plugin.rngPool.New = func() any {
        seed := int64(atomic.AddUint64(&plugin.rngSeed, 1) ^ uint64(time.Now().UnixNano()))
        return rand.New(rand.NewSource(seed))
    }

    lines, err := ReadTextFile(plugin.configFile)
    if err != nil {
        return err
    }

    requiresDHCP, forwardMap, err := plugin.parseForwardFile(lines)
    if err != nil {
        return err
    }

    rules := plugin.buildRules(forwardMap)
    plugin.rules.Store(rules)

    if requiresDHCP {
        plugin.ensureDHCPDetectors()
        plugin.startDHCPCacheRefresher()
    }

    return nil
}

func (plugin *PluginForward) Drop() error {
    if plugin.configWatcher != nil {
        plugin.configWatcher.RemoveFile(plugin.configFile)
    }
    plugin.closeAllTCPPools()
    return nil
}

func (plugin *PluginForward) GetConfigPath() string {
    return plugin.configFile
}

func (plugin *PluginForward) SetConfigWatcher(watcher *ConfigWatcher) {
    plugin.configWatcher = watcher
}

func (plugin *PluginForward) PrepareReload() error {
    lines, err := SafeReadTextFile(plugin.configFile)
    if err != nil {
        return fmt.Errorf("error reading config file during reload preparation: %w", err)
    }

    requiresDHCP, forwardMap, err := plugin.parseForwardFile(lines)
    if err != nil {
        return fmt.Errorf("error parsing config during reload preparation: %w", err)
    }

    plugin.stagingRules = plugin.buildRules(forwardMap)

    if requiresDHCP {
        plugin.ensureDHCPDetectors()
        plugin.startDHCPCacheRefresher()
    }

    return nil
}

func (plugin *PluginForward) ApplyReload() error {
    if plugin.stagingRules == nil {
        return errors.New("no staged configuration to apply")
    }

    plugin.rules.Store(plugin.stagingRules)
    plugin.stagingRules = nil

    dlog.Noticef("Applied new configuration for plugin [%s]", plugin.Name())
    return nil
}

func (plugin *PluginForward) CancelReload() {
    plugin.stagingRules = nil
}

func (plugin *PluginForward) Reload() error {
    dlog.Noticef("Reloading configuration for plugin [%s]", plugin.Name())

    if err := plugin.PrepareReload(); err != nil {
        plugin.CancelReload()
        return err
    }

    return plugin.ApplyReload()
}

func (plugin *PluginForward) buildRules(forwardMap []PluginForwardEntry) *forwardRules {
    r := &forwardRules{
        bySuffix: make(map[string][]SearchSequenceItem, len(forwardMap)),
    }
    for _, e := range forwardMap {
        r.bySuffix[e.domain] = e.sequence
    }
    return r
}

func (plugin *PluginForward) lookupSequence(qName string) []SearchSequenceItem {
    v := plugin.rules.Load()
    if v == nil {
        return nil
    }
    rules := v.(*forwardRules)

    name := strings.TrimSuffix(strings.ToLower(qName), ".")
    if name == "" {
        name = "."
    }

    for {
        if seq, ok := rules.bySuffix[name]; ok {
            return seq
        }
        if name == "." {
            break
        }
        if i := strings.IndexByte(name, '.'); i >= 0 {
            name = name[i+1:]
            if name == "" {
                name = "."
            }
            continue
        }
        name = "."
    }
    return nil
}

func (plugin *PluginForward) ensureDHCPDetectors() {
    if len(plugin.dhcpdns) > 0 {
        return
    }
    if len(plugin.proxy.userName) > 0 {
        dlog.Warn("DHCP/DNS detection may not work when 'user_name' is set or when starting as a non-root user")
    }
    if plugin.proxy.SourceIPv6 {
        dlog.Notice("Starting a DHCP/DNS detector for IPv6")
        d6 := &dhcpdns.Detector{RemoteIPPort: "[2001:DB8::53]:80"}
        go d6.Serve(9, 10)
        plugin.dhcpdns = append(plugin.dhcpdns, d6)
    }
    if plugin.proxy.SourceIPv4 {
        dlog.Notice("Starting a DHCP/DNS detector for IPv4")
        d4 := &dhcpdns.Detector{RemoteIPPort: "192.0.2.53:80"}
        go d4.Serve(9, 10)
        plugin.dhcpdns = append(plugin.dhcpdns, d4)
    }
}

func (plugin *PluginForward) startDHCPCacheRefresher() {
    if len(plugin.dhcpdns) == 0 {
        return
    }
    if plugin.dhcpCache.Load() != nil {
        return
    }
    plugin.dhcpCache.Store([]string{})

    go func() {
        ticker := time.NewTicker(2 * time.Second)
        defer ticker.Stop()

        for range ticker.C {
            servers := plugin.collectDHCPServers()
            plugin.dhcpCache.Store(servers)
        }
    }()
}

func (plugin *PluginForward) collectDHCPServers() []string {
    seen := make(map[string]struct{})
    out := make([]string, 0, 4)

    for _, det := range plugin.dhcpdns {
        _, _, dhcpDNS, err := det.Status()
        if err != nil {
            continue
        }
        for _, ip := range dhcpDNS {
            s := net.JoinHostPort(ip.String(), "53")
            if _, ok := seen[s]; ok {
                continue
            }
            seen[s] = struct{}{}
            out = append(out, s)
        }
    }
    return out
}

func (plugin *PluginForward) getRand() *rand.Rand {
    return plugin.rngPool.Get().(*rand.Rand)
}

func (plugin *PluginForward) putRand(r *rand.Rand) {
    plugin.rngPool.Put(r)
}

func (plugin *PluginForward) getTCPPool(server string) chan net.Conn {
    plugin.tcpPoolsMu.Lock()
    defer plugin.tcpPoolsMu.Unlock()

    pool, ok := plugin.tcpPools[server]
    if ok {
        return pool
    }
    pool = make(chan net.Conn, 16)
    plugin.tcpPools[server] = pool
    return pool
}

func (plugin *PluginForward) closeAllTCPPools() {
    plugin.tcpPoolsMu.Lock()
    pools := plugin.tcpPools
    plugin.tcpPools = make(map[string]chan net.Conn)
    plugin.tcpPoolsMu.Unlock()

    for _, ch := range pools {
        close(ch)
        for conn := range ch {
            _ = conn.Close()
        }
    }
}

func (plugin *PluginForward) exchangeUpstream(ctx context.Context, msg *dns.Msg, network, server string) (*dns.Msg, error) {
    if network != "tcp" {
        resp, _, err := plugin.udpClient.Exchange(ctx, msg, network, server)
        return resp, err
    }

    pool := plugin.getTCPPool(server)

    var conn net.Conn
    select {
    case conn = <-pool:
    default:
        d := net.Dialer{}
        c, err := d.DialContext(ctx, "tcp", server)
        if err != nil {
            return nil, err
        }
        conn = c
    }

    if deadline, ok := ctx.Deadline(); ok {
        _ = conn.SetDeadline(deadline)
    }

    resp, _, err := plugin.tcpClient.ExchangeWithConn(ctx, msg, conn)
    if err != nil {
        _ = conn.Close()
        return nil, err
    }

    select {
    case pool <- conn:
    default:
        _ = conn.Close()
    }

    return resp, nil
}

func (plugin *PluginForward) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
    qName := pluginsState.qName
    sequence := plugin.lookupSequence(qName)
    if len(sequence) == 0 {
        return nil
    }

    forwardMsg := msg.Copy()
    forwardMsg.Extra = nil
    forwardMsg.Data = nil

    tries := 4
    var err error

    for _, item := range sequence {
        if tries == 0 {
            break
        }

        var server string

        r := plugin.getRand()
        switch item.typ {
        case Explicit:
            if len(item.servers) == 0 {
                plugin.putRand(r)
                continue
            }
            server = item.servers[r.Intn(len(item.servers))]
        case Bootstrap:
            if len(plugin.bootstrapResolvers) == 0 {
                plugin.putRand(r)
                continue
            }
            server = plugin.bootstrapResolvers[r.Intn(len(plugin.bootstrapResolvers))]
        case DHCP:
            cached := plugin.dhcpCache.Load()
            var servers []string
            if cached != nil {
                servers, _ = cached.([]string)
            }
            if len(servers) == 0 {
                dlog.Infof("DHCP didn't provide any DNS server to forward [%s]", qName)
                plugin.putRand(r)
                continue
            }
            server = servers[r.Intn(len(servers))]
        default:
            plugin.putRand(r)
            continue
        }
        plugin.putRand(r)

        if server == "" {
            continue
        }

        tries--
        pluginsState.serverName = server
        dlog.Debugf("Forwarding [%s] to [%s]", qName, server)

        ctx, cancel := context.WithTimeout(context.Background(), pluginsState.timeout)
        respMsg, exErr := plugin.exchangeUpstream(ctx, forwardMsg, pluginsState.serverProto, server)
        if exErr != nil {
            cancel()
            err = exErr
            continue
        }

        if respMsg != nil && respMsg.Truncated {
            respMsg, exErr = plugin.exchangeUpstream(ctx, forwardMsg, "tcp", server)
            if exErr != nil {
                cancel()
                err = exErr
                continue
            }
        }
        cancel()

        if respMsg == nil {
            continue
        }

        if !respMsg.Security {
            respMsg.AuthenticatedData = false
        }
        respMsg.ID = msg.ID

        pluginsState.synthResponse = respMsg
        pluginsState.action = PluginsActionSynth
        pluginsState.returnCode = PluginsReturnCodeForward

        switch respMsg.Rcode {
        case dns.RcodeNameError, dns.RcodeRefused, dns.RcodeNotAuth:
            continue
        }

        return nil
    }

    return err
}

// parseForwardFile parses forward rules from text
func (plugin *PluginForward) parseForwardFile(lines string) (bool, []PluginForwardEntry, error) {
    requiresDHCP := false
    forwardMap := []PluginForwardEntry{}

    for lineNo, line := range strings.Split(lines, "
") {
        line = TrimAndStripInlineComments(line)
        if len(line) == 0 {
            continue
        }

        domain, serversStr, ok := StringTwoFields(line)
        domain = strings.TrimPrefix(domain, "*.")
        if strings.Contains(domain, "*") {
            ok = false
        }
        if !ok {
            return false, nil, fmt.Errorf(
                "Syntax error for a forwarding rule at line %d. Expected syntax: example.com 9.9.9.9,8.8.8.8",
                1+lineNo,
            )
        }

        domain = strings.ToLower(domain)

        var sequence []SearchSequenceItem
        explicitIdx := -1

        for _, server := range strings.Split(serversStr, ",") {
            server = strings.TrimSpace(server)
            switch server {
            case "$BOOTSTRAP":
                if len(plugin.bootstrapResolvers) == 0 {
                    return false, nil, fmt.Errorf(
                        "Syntax error for a forwarding rule at line %d. No bootstrap resolvers available",
                        1+lineNo,
                    )
                }
                if len(sequence) > 0 && sequence[len(sequence)-1].typ == Bootstrap {
                    continue
                }
                sequence = append(sequence, SearchSequenceItem{typ: Bootstrap})
                dlog.Infof("Forwarding [%s] to the bootstrap servers", domain)

            case "$DHCP":
                if len(sequence) > 0 && sequence[len(sequence)-1].typ == DHCP {
                    continue
                }
                sequence = append(sequence, SearchSequenceItem{typ: DHCP})
                dlog.Infof("Forwarding [%s] to the DHCP servers", domain)
                requiresDHCP = true

            default:
                if strings.HasPrefix(server, "$") {
                    dlog.Criticalf("Unknown keyword [%s] at line %d", server, 1+lineNo)
                    continue
                }
                normalized, err := normalizeIPAndOptionalPort(server, "53")
                if err != nil {
                    dlog.Criticalf("Syntax error for a forwarding rule at line %d: %s", 1+lineNo, err)
                    continue
                }

                if explicitIdx == -1 {
                    sequence = append(sequence, SearchSequenceItem{typ: Explicit, servers: []string{normalized}})
                    explicitIdx = len(sequence) - 1
                } else {
                    sequence[explicitIdx].servers = append(sequence[explicitIdx].servers, normalized)
                }
                dlog.Infof("Forwarding [%s] to [%s]", domain, normalized)
            }
        }

        forwardMap = append(forwardMap, PluginForwardEntry{
            domain:   domain,
            sequence: sequence,
        })
    }

    return requiresDHCP, forwardMap, nil
}

func normalizeIPAndOptionalPort(addr string, defaultPort string) (string, error) {
    var host, port string
    var err error

    if strings.HasPrefix(addr, "[") {
        if !strings.Contains(addr, "]:") {
            if addr[len(addr)-1] != ']' {
                return "", fmt.Errorf("invalid IPv6 format: missing closing ']'")
            }
            host = addr[1 : len(addr)-1]
            port = defaultPort
        } else {
            host, port, err = net.SplitHostPort(addr)
            if err != nil {
                return "", err
            }
        }
    } else {
        host, port, err = net.SplitHostPort(addr)
        if err != nil {
            host = addr
            port = defaultPort
        }
    }

    ip := net.ParseIP(host)
    if ip == nil {
        return "", fmt.Errorf("invalid IP address: [%s]", host)
    }
    if ip.To4() != nil {
        return fmt.Sprintf("%s:%s", ip.String(), port), nil
    }
    return fmt.Sprintf("[%s]:%s", ip.String(), port), nil
}
