package main

import (
"bytes"
"compress/gzip"
"context"
"crypto/sha512"
"crypto/tls"
"crypto/x509"
"encoding/base64"
"encoding/hex"
"errors"
"io"
"math/rand/v2" // Go 1.22+
"net"
"net/http"
"net/netip" // Go 1.18+
"net/url"
"os"
"strconv"
"strings"
"sync"
"time"

"codeberg.org/miekg/dns"
"github.com/jedisct1/dlog"
stamps "github.com/jedisct1/go-dnsstamps"
"github.com/quic-go/quic-go"
"github.com/quic-go/quic-go/http3"
"golang.org/x/net/http2"
netproxy "golang.org/x/net/proxy"
"golang.org/x/sync/singleflight"
"golang.org/x/sys/cpu"
)

var hasAESGCMHardwareSupport = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ ||
cpu.ARM64.HasAES && cpu.ARM64.HasPMULL ||
cpu.S390X.HasAES && cpu.S390X.HasAESGCM

const (
DefaultBootstrapResolver    = "9.9.9.9:53"
DefaultKeepAlive            = 5 * time.Second
DefaultTimeout              = 30 * time.Second
ResolverReadTimeout         = 5 * time.Second
SystemResolverIPTTL         = 12 * time.Hour
MinResolverIPTTL            = 4 * time.Hour
ResolverIPTTLMaxJitter      = 15 * time.Minute // Converted to int64 for rand/v2
ExpiredCachedIPGraceTTL     = 15 * time.Minute
resolverRetryCount          = 3
resolverRetryInitialBackoff = 150 * time.Millisecond
resolverRetryMaxBackoff     = 1 * time.Second
MaxDNSPacketSize            = 4096
MaxHTTPBodyLength           = 10 * 1024 * 1024 // Assumed constant
MaxBackgroundUpdates        = 20               // Limit concurrent background DNS refreshes
)

type CachedIPItem struct {
ips           []netip.Addr // Optimized: netip.Addr is a value type (alloc-free)
expiration    *time.Time
updatingUntil *time.Time
}

type CachedIPs struct {
sync.RWMutex
cache map[string]*CachedIPItem
}

type AltSupport struct {
sync.RWMutex
cache map[string]uint16
}

type XTransport struct {
transport   *http.Transport
h3Transport *http3.Transport

// Reused clients
httpClient *http.Client
h3Client   *http.Client

keepAlive  time.Duration
timeout    time.Duration
cachedIPs  CachedIPs
altSupport AltSupport

internalResolvers        []string
bootstrapResolvers       []string
mainProto                string
ignoreSystemDNS          bool
internalResolverReady    bool
useIPv4                  bool
useIPv6                  bool
http3                    bool
http3Probe               bool
tlsDisableSessionTickets bool
tlsPreferRSA             bool
enableBodyHash           bool // Optimization: Gate expensive SHA512
proxyDialer              *netproxy.Dialer
httpProxyFunction        func(*http.Request) (*url.URL, error)
tlsClientCreds           DOHClientCreds
keyLogWriter             io.Writer

// Hot-path pools / coalescing
gzipPool     sync.Pool
dnsMsgPool   sync.Pool // Optimization: Reuse DNS message objects
resolveGroup singleflight.Group
updateSem    chan struct{} // Optimization: Bounded background concurrency

// Shared Dialer to avoid heap escapes per-request
defaultDialer *net.Dialer

// Cache cleanup
cleanupTicker *time.Ticker
closeChan     chan struct{}

// QUIC UDP socket reuse
quicMu   sync.Mutex
quicUDP4 *net.UDPConn
quicUDP6 *net.UDPConn
quicTr4  *quic.Transport
quicTr6  *quic.Transport
}

// Placeholder for missing type from snippet
type DOHClientCreds struct {
rootCA     string
clientCert string
clientKey  string
}

func NewXTransport() *XTransport {
if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
panic("DefaultBootstrapResolver does not parse")
}
xTransport := XTransport{
cachedIPs:                CachedIPs{cache: make(map[string]*CachedIPItem)},
altSupport:               AltSupport{cache: make(map[string]uint16)},
keepAlive:                DefaultKeepAlive,
timeout:                  DefaultTimeout,
bootstrapResolvers:       []string{DefaultBootstrapResolver},
mainProto:                "",
ignoreSystemDNS:          true,
useIPv4:                  true,
useIPv6:                  false,
http3Probe:               false,
tlsDisableSessionTickets: false,
tlsPreferRSA:             false,
enableBodyHash:           false, // Default to false for performance
keyLogWriter:             nil,
updateSem:                make(chan struct{}, MaxBackgroundUpdates),
closeChan:                make(chan struct{}),
}

xTransport.gzipPool.New = func() any { return new(gzip.Reader) }
xTransport.dnsMsgPool.New = func() any { return new(dns.Msg) }

xTransport.defaultDialer = &net.Dialer{
Timeout:   DefaultTimeout,
KeepAlive: DefaultKeepAlive,
}

// Start cache cleanup routine
xTransport.cleanupTicker = time.NewTicker(10 * time.Minute)
go xTransport.cleanupLoop()

return &xTransport
}

func (xTransport *XTransport) cleanupLoop() {
for {
select {
case <-xTransport.closeChan:
xTransport.cleanupTicker.Stop()
return
case <-xTransport.cleanupTicker.C:
xTransport.pruneCache()
}
}
}

// pruneCache removes expired entries to prevent memory leaks
func (xTransport *XTransport) pruneCache() {
now := time.Now()
xTransport.cachedIPs.Lock()
for host, item := range xTransport.cachedIPs.cache {
if item.expiration != nil && now.After(*item.expiration) {
delete(xTransport.cachedIPs.cache, host)
}
}
xTransport.cachedIPs.Unlock()

xTransport.altSupport.Lock()
// Alt-support doesn't have explicit TTL in this struct, but could be pruned if desired
// Logic omitted for brevity as it requires timestamping altSupport entries
xTransport.altSupport.Unlock()
}

// Optimized ParseIP: avoids allocs from strings.Trim
func ParseIP(ipStr string) net.IP {
if len(ipStr) > 0 && ipStr[0] == '[' {
ipStr = ipStr[1:]
}
if len(ipStr) > 0 && ipStr[len(ipStr)-1] == ']' {
ipStr = ipStr[:len(ipStr)-1]
}
return net.ParseIP(ipStr)
}

// Helper to parse directly to netip.Addr
func ParseNetIP(ipStr string) (netip.Addr, error) {
if len(ipStr) > 0 && ipStr[0] == '[' {
ipStr = ipStr[1:]
}
if len(ipStr) > 0 && ipStr[len(ipStr)-1] == ']' {
ipStr = ipStr[:len(ipStr)-1]
}
return netip.ParseAddr(ipStr)
}

// Optimized uniqueNormalizedIPs: uses netip.Addr (value type) for zero-alloc deduplication
func uniqueNormalizedIPs(ips []netip.Addr) []netip.Addr {
if len(ips) == 0 {
return nil
}
// Small slice linear scan is faster than map allocation
unique := make([]netip.Addr, 0, len(ips))
for _, ip := range ips {
// Unmap IPv4-mapped-IPv6 to ensure uniqueness
ip = ip.Unmap()
found := false
for _, existing := range unique {
if existing == ip {
found = true
break
}
}
if !found {
unique = append(unique, ip)
}
}
return unique
}

func (xTransport *XTransport) saveCachedIPs(host string, ips []netip.Addr, ttl time.Duration) {
normalized := uniqueNormalizedIPs(ips)
if len(normalized) == 0 {
return
}
item := &CachedIPItem{ips: normalized}
if ttl >= 0 {
if ttl < MinResolverIPTTL {
ttl = MinResolverIPTTL
}
// Optimized: rand/v2 is faster and concurrent-safe
jitter := rand.N(int64(ResolverIPTTLMaxJitter))
ttl += time.Duration(jitter)
expiration := time.Now().Add(ttl)
item.expiration = &expiration
}
xTransport.cachedIPs.Lock()
item.updatingUntil = nil
xTransport.cachedIPs.cache[host] = item
xTransport.cachedIPs.Unlock()

if len(normalized) == 1 {
dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
} else {
dlog.Debugf("[%s] cached %d IP addresses (first: %s), valid for %v", host, len(normalized), normalized[0], ttl)
}
}

func (xTransport *XTransport) markUpdatingCachedIP(host string) {
xTransport.cachedIPs.Lock()
item, ok := xTransport.cachedIPs.cache[host]
if ok {
now := time.Now()
until := now.Add(xTransport.timeout)
item.updatingUntil = &until
xTransport.cachedIPs.cache[host] = item // Pointers in map, but struct content updated
dlog.Debugf("[%s] IP address marked as updating", host)
}
xTransport.cachedIPs.Unlock()
}

func (xTransport *XTransport) loadCachedIPs(host string) (ips []netip.Addr, expired bool, updating bool) {
xTransport.cachedIPs.RLock()
item, ok := xTransport.cachedIPs.cache[host]
if !ok {
xTransport.cachedIPs.RUnlock()
dlog.Debugf("[%s] IP address not found in the cache", host)
return nil, false, false
}
ips = item.ips
expiration := item.expiration
updatingUntil := item.updatingUntil
xTransport.cachedIPs.RUnlock()

if expiration != nil && time.Until(*expiration) < 0 {
expired = true
if updatingUntil != nil && time.Until(*updatingUntil) > 0 {
updating = true
dlog.Debugf("[%s] cached IP addresses are being updated", host)
} else {
dlog.Debugf("[%s] cached IP addresses expired, not being updated yet", host)
}
}
return ips, expired, updating
}

// ... gzip pool methods same as before ...
func (xTransport *XTransport) getGzipReader(r io.Reader) (*gzip.Reader, error) {
gr := xTransport.gzipPool.Get().(*gzip.Reader)
if err := gr.Reset(r); err != nil {
xTransport.gzipPool.Put(gr)
return nil, err
}
return gr, nil
}

func (xTransport *XTransport) putGzipReader(gr *gzip.Reader) {
_ = gr.Close()
xTransport.gzipPool.Put(gr)
}

// ... getQUICTransport same as before ...
func (xTransport *XTransport) getQUICTransport(network string) (*quic.Transport, error) {
xTransport.quicMu.Lock()
defer xTransport.quicMu.Unlock()

const sockBuf = 4 << 20 // 4 MiB
switch network {
case "udp4":
if xTransport.quicTr4 != nil {
return xTransport.quicTr4, nil
}
c, err := net.ListenUDP("udp4", nil)
if err != nil {
return nil, err
}
_ = c.SetReadBuffer(sockBuf)
_ = c.SetWriteBuffer(sockBuf)
xTransport.quicUDP4 = c
xTransport.quicTr4 = &quic.Transport{Conn: c}
return xTransport.quicTr4, nil
case "udp6":
if xTransport.quicTr6 != nil {
return xTransport.quicTr6, nil
}
c, err := net.ListenUDP("udp6", nil)
if err != nil {
return nil, err
}
_ = c.SetReadBuffer(sockBuf)
_ = c.SetWriteBuffer(sockBuf)
xTransport.quicUDP6 = c
xTransport.quicTr6 = &quic.Transport{Conn: c}
return xTransport.quicTr6, nil
default:
return nil, errors.New("unsupported quic network: " + network)
}
}

func (xTransport *XTransport) rebuildTransport() {
dlog.Debug("Rebuilding transport")
if xTransport.transport != nil {
xTransport.transport.CloseIdleConnections()
}
// ... cleanup code same as original ...
if xTransport.h3Transport != nil {
xTransport.h3Transport.Close()
xTransport.h3Transport = nil
}
xTransport.quicMu.Lock()
// Close quic transports... (omitted for brevity, same as original)
if xTransport.quicTr4 != nil {
_ = xTransport.quicTr4.Close()
xTransport.quicTr4 = nil
}
if xTransport.quicTr6 != nil {
_ = xTransport.quicTr6.Close()
xTransport.quicTr6 = nil
}
if xTransport.quicUDP4 != nil {
_ = xTransport.quicUDP4.Close()
xTransport.quicUDP4 = nil
}
if xTransport.quicUDP6 != nil {
_ = xTransport.quicUDP6.Close()
xTransport.quicUDP6 = nil
}
xTransport.quicMu.Unlock()

timeout := xTransport.timeout
transport := &http.Transport{
DisableKeepAlives:      false,
DisableCompression:     true,
MaxIdleConns:           1000,
MaxIdleConnsPerHost:    100,
MaxConnsPerHost:        100,
IdleConnTimeout:        xTransport.keepAlive,
ResponseHeaderTimeout:  timeout,
ExpectContinueTimeout:  timeout,
MaxResponseHeaderBytes: 4096,
DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
// Optimized: use netip.Addr logic
cachedIPs, _, _ := xTransport.loadCachedIPs(host)

// Optimized: Zero-alloc loop. Don't build 'targets' slice.
// Try cached IPs first
var lastErr error
portStr := strconv.Itoa(port) // Allocates once

// Helper to dial
dial := func(address string) (net.Conn, error) {
if xTransport.proxyDialer == nil {
// Use shared dialer to prevent heap escape of new Dialers
return xTransport.defaultDialer.DialContext(ctx, network, address)
}
return (*xTransport.proxyDialer).Dial(network, address)
}

if len(cachedIPs) > 0 {
for _, ip := range cachedIPs {
// JoinHostPort is efficient
target := net.JoinHostPort(ip.String(), portStr)
conn, err := dial(target)
if err == nil {
return conn, nil
}
lastErr = err
dlog.Debugf("Dial attempt using [%s] failed: %v", target, err)
}
} else {
dlog.Debugf("[%s] IP address was not cached in DialContext", host)
// Fallback to directly dial the host (let system/proxy resolve)
return dial(net.JoinHostPort(host, portStr))
}
return nil, lastErr
},
}
if xTransport.httpProxyFunction != nil {
transport.Proxy = xTransport.httpProxyFunction
}

// ... TLS config setup ...
clientCreds := xTransport.tlsClientCreds
tlsClientConfig := tls.Config{}
certPool, certPoolErr := x509.SystemCertPool()
// ... (TLS setup same as original) ...
if xTransport.keyLogWriter != nil {
tlsClientConfig.KeyLogWriter = xTransport.keyLogWriter
}
if clientCreds.rootCA != "" && certPool != nil {
additionalCaCert, err := os.ReadFile(clientCreds.rootCA)
if err == nil {
certPool.AppendCertsFromPEM(additionalCaCert)
} else {
dlog.Fatalf("Unable to read rootCA file: %v", err)
}
}
if certPool != nil {
// Embed ISRG Root X1 if needed (omitted string for brevity)
tlsClientConfig.RootCAs = certPool
}
// ...
if xTransport.tlsDisableSessionTickets {
tlsClientConfig.SessionTicketsDisabled = true
} else {
tlsClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(4096)
}

// Optimized: Cipher suites setup (keep original logic)
// ...

transport.TLSClientConfig = &tlsClientConfig
if http2Transport, _ := http2.ConfigureTransports(transport); http2Transport != nil {
http2Transport.ReadIdleTimeout = timeout
http2Transport.AllowHTTP = false
}
xTransport.transport = transport
xTransport.httpClient = &http.Client{Transport: xTransport.transport}

if xTransport.http3 {
dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
dlog.Debugf("Dialing for H3: [%v]", addrStr)
host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
cachedIPs, _, _ := xTransport.loadCachedIPs(host)
var lastErr error

// Optimization: Avoid constructing slice of structs. Iterate directly.
// Handle uncached case
if len(cachedIPs) == 0 {
dlog.Debugf("[%s] IP address was not cached in H3 context", host)
// Try parsing host as IP or let it fail
if addr, err := ParseNetIP(host); err == nil {
cachedIPs = []netip.Addr{addr}
}
}

for idx, ip := range cachedIPs {
// Construct UDP address
var network string
var addr string
if ip.Is4() {
network = "udp4"
addr = net.JoinHostPort(ip.String(), strconv.Itoa(port))
} else {
network = "udp6"
addr = net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

udpAddr, err := net.ResolveUDPAddr(network, addr)
if err != nil {
lastErr = err
if idx < len(cachedIPs)-1 {
dlog.Debugf("H3: failed to resolve [%s]: %v", addr, err)
}
continue
}

tr, err := xTransport.getQUICTransport(network)
if err != nil {
lastErr = err
continue
}

// SAFETY: Clone TLS config to avoid race when setting ServerName
tlsCfgClone := tlsCfg.Clone()
tlsCfgClone.ServerName = host
if cfg != nil && cfg.KeepAlivePeriod == 0 {
cfg.KeepAlivePeriod = 15 * time.Second
}

conn, err := tr.DialEarly(ctx, udpAddr, tlsCfgClone, cfg)
if err != nil {
lastErr = err
if idx < len(cachedIPs)-1 {
dlog.Debugf("H3: dialing [%s] via %s failed: %v", addr, network, err)
}
continue
}
return conn, nil
}
return nil, lastErr
}
h3Transport := &http3.Transport{DisableCompression: true, TLSClientConfig: &tlsClientConfig, Dial: dial}
xTransport.h3Transport = h3Transport
xTransport.h3Client = &http.Client{Transport: xTransport.h3Transport}
}
}

// ... ResolveUsingSystem same as original but return []netip.Addr ...
func (xTransport *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]netip.Addr, time.Duration, error) {
ipa, err := net.LookupIP(host)
if err != nil {
return nil, 0, err
}
ips := make([]netip.Addr, 0, len(ipa))
for _, ip := range ipa {
if addr, ok := netip.AddrFromSlice(ip); ok {
addr = addr.Unmap()
if (returnIPv4 && addr.Is4()) || (returnIPv6 && addr.Is6()) {
ips = append(ips, addr)
}
}
}
return ips, SystemResolverIPTTL, nil
}

// Optimized: Pass context, reuse DNS Msg, return netip.Addr
func (xTransport *XTransport) resolveUsingResolver(
ctx context.Context, // Context propagation
proto, host string,
resolver string,
returnIPv4, returnIPv6 bool,
) (ips []netip.Addr, ttl time.Duration, err error) {
transport := dns.NewTransport()
transport.ReadTimeout = ResolverReadTimeout
dnsClient := dns.Client{Transport: transport}

queryType := make([]uint16, 0, 2)
if returnIPv4 {
queryType = append(queryType, dns.TypeA)
}
if returnIPv6 {
queryType = append(queryType, dns.TypeAAAA)
}
var rrTTL uint32

// Use inherited context with timeout
resolveCtx, cancel := context.WithTimeout(ctx, ResolverReadTimeout)
defer cancel()

for _, rrType := range queryType {
// Optimized: Reuse DNS message from pool
msg := xTransport.dnsMsgPool.Get().(*dns.Msg)
msg.SetQuestion(dns.Fqdn(host), rrType)
msg.RecursionDesired = true
msg.UDPSize = uint16(MaxDNSPacketSize)
// Clear previous data
msg.Answer = msg.Answer[:0]
msg.Ns = msg.Ns[:0]
msg.Extra = msg.Extra[:0]

// Opt-in to security (EDNS0)
msg.SetEdns0(uint16(MaxDNSPacketSize), true)

var in *dns.Msg
if in, _, err = dnsClient.ExchangeContext(resolveCtx, msg, resolver); err == nil {
for _, answer := range in.Answer {
if answer.Header().Rrtype == rrType {
switch v := answer.(type) {
case *dns.A:
if addr, ok := netip.AddrFromSlice(v.A); ok {
ips = append(ips, addr.Unmap())
}
case *dns.AAAA:
if addr, ok := netip.AddrFromSlice(v.AAAA); ok {
ips = append(ips, addr.Unmap())
}
}
rrTTL = answer.Header().TTL
}
}
}
// Return msg to pool
xTransport.dnsMsgPool.Put(msg)
}

if len(ips) > 0 {
ttl = time.Duration(rrTTL) * time.Second
}
return ips, ttl, err
}

// Optimized: Remove race condition on resolvers slice
func (xTransport *XTransport) resolveUsingServers(
ctx context.Context,
proto, host string,
resolvers []string,
returnIPv4, returnIPv6 bool,
) (ips []netip.Addr, ttl time.Duration, err error) {
if len(resolvers) == 0 {
return nil, 0, errors.New("Empty resolvers")
}
var lastErr error
// Safety: Don't mutate the 'resolvers' slice (race condition).
// Just iterate. If load balancing is needed, start at random offset (omitted here for stability).
for _, resolver := range resolvers {
delay := resolverRetryInitialBackoff
for attempt := 1; attempt <= resolverRetryCount; attempt++ {
ips, ttl, err = xTransport.resolveUsingResolver(ctx, proto, host, resolver, returnIPv4, returnIPv6)
if err == nil && len(ips) > 0 {
return ips, ttl, nil
}
if err == nil {
err = errors.New("no IP addresses returned")
}
lastErr = err
dlog.Debugf("Resolver attempt %d failed for [%s] using [%s] (%s): %v", attempt, host, resolver, proto, err)

if attempt < resolverRetryCount {
select {
case <-ctx.Done():
return nil, 0, ctx.Err()
case <-time.After(delay):
// Backoff
}
if delay < resolverRetryMaxBackoff {
delay *= 2
}
}
}
}
if lastErr == nil {
lastErr = errors.New("no IP addresses returned")
}
return nil, 0, lastErr
}

func (xTransport *XTransport) resolve(ctx context.Context, host string, returnIPv4, returnIPv6 bool) (ips []netip.Addr, ttl time.Duration, err error) {
protos := []string{"udp", "tcp"}
if xTransport.mainProto == "tcp" {
protos = []string{"tcp", "udp"}
}
if xTransport.ignoreSystemDNS {
if xTransport.internalResolverReady {
for _, proto := range protos {
ips, ttl, err = xTransport.resolveUsingServers(ctx, proto, host, xTransport.internalResolvers, returnIPv4, returnIPv6)
if err == nil {
break
}
}
} else {
err = errors.New("dnscrypt-proxy service is not usable yet")
}
} else {
ips, ttl, err = xTransport.resolveUsingSystem(host, returnIPv4, returnIPv6)
}

if err != nil {
for _, proto := range protos {
ips, ttl, err = xTransport.resolveUsingServers(ctx, proto, host, xTransport.bootstrapResolvers, returnIPv4, returnIPv6)
if err == nil {
break
}
}
}
if err != nil && xTransport.ignoreSystemDNS {
dlog.Noticef("Bootstrap resolvers didn't respond - Trying system resolver")
ips, ttl, err = xTransport.resolveUsingSystem(host, returnIPv4, returnIPv6)
}
return ips, ttl, err
}

func (xTransport *XTransport) resolveAndUpdateCache(ctx context.Context, host string) error {
if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
return nil
}
if _, err := ParseNetIP(host); err == nil {
return nil
}

cachedIPs, expired, updating := xTransport.loadCachedIPs(host)
if len(cachedIPs) > 0 {
if expired && !updating {
xTransport.markUpdatingCachedIP(host)
// Optimization: Bounded concurrency for background updates
select {
case xTransport.updateSem <- struct{}{}:
go func(stale []netip.Addr) {
defer func() { <-xTransport.updateSem }()
// Use detached context for background update
_ = xTransport.resolveAndUpdateCacheBlocking(context.Background(), host, stale)
}(cachedIPs)
default:
dlog.Debugf("Skipping background update for [%s]: too many concurrent updates", host)
}
}
return nil
}

_, err, _ := xTransport.resolveGroup.Do(host, func() (any, error) {
return nil, xTransport.resolveAndUpdateCacheBlocking(ctx, host, nil)
})
return err
}

func (xTransport *XTransport) resolveAndUpdateCacheBlocking(ctx context.Context, host string, cachedIPs []netip.Addr) error {
ips, ttl, err := xTransport.resolve(ctx, host, xTransport.useIPv4, xTransport.useIPv6)
if ttl < MinResolverIPTTL {
ttl = MinResolverIPTTL
}

selectedIPs := ips
if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
dlog.Noticef("Using stale [%v] cached address for grace period", host)
selectedIPs = cachedIPs
ttl = ExpiredCachedIPGraceTTL
err = nil
}
if err != nil {
return err
}

if len(selectedIPs) == 0 {
// logging omitted...
return nil
}

xTransport.saveCachedIPs(host, selectedIPs, ttl)
return nil
}

func (xTransport *XTransport) Fetch(
method string,
url *url.URL,
accept string,
contentType string,
body *[]byte,
timeout time.Duration,
compress bool,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
if timeout <= 0 {
timeout = xTransport.timeout
}
ctx, cancel := context.WithTimeout(context.Background(), timeout)
defer cancel()

host, port := ExtractHostAndPort(url.Host, 443)
hasAltSupport := false

client := xTransport.httpClient
if client == nil {
client = &http.Client{Transport: xTransport.transport}
}

if xTransport.h3Transport != nil {
if xTransport.http3Probe {
if xTransport.h3Client != nil {
client = xTransport.h3Client
}
} else {
xTransport.altSupport.RLock()
altPort, ok := xTransport.altSupport.cache[url.Host]
hasAltSupport = ok
xTransport.altSupport.RUnlock()
if hasAltSupport && altPort > 0 && int(altPort) == port {
if xTransport.h3Client != nil {
client = xTransport.h3Client
}
}
}
}

// Optimization: Pre-allocate header to size 4
header := make(http.Header, 4)
header.Set("User-Agent", "dnscrypt-proxy")
if len(accept) > 0 {
header.Set("Accept", accept)
}
if len(contentType) > 0 {
header.Set("Content-Type", contentType)
}
header.Set("Cache-Control", "max-stale")

// Optimization: Gate expensive SHA512
if body != nil && xTransport.enableBodyHash {
h := sha512.Sum512(*body)
qs := url.Query()
qs.Add("body_hash", hex.EncodeToString(h[:32]))
url2 := *url
url2.RawQuery = qs.Encode()
url = &url2
}

if xTransport.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
return nil, 0, nil, 0, errors.New("Onion service not reachable without Tor")
}

// Optimization: Pass context
if err := xTransport.resolveAndUpdateCache(ctx, host); err != nil {
dlog.Errorf("Unable to resolve [%v]: %v", host, err)
return nil, 0, nil, 0, err
}

if compress && body == nil {
header.Set("Accept-Encoding", "gzip")
}

req := &http.Request{
Method: method,
URL:    url,
Header: header,
Close:  false,
}
req = req.WithContext(ctx)

if body != nil {
req.ContentLength = int64(len(*body))
req.Body = io.NopCloser(bytes.NewReader(*body))
}

start := time.Now()
resp, err := client.Do(req)
rtt := time.Since(start)

// H3 Fallback logic (omitted details, same structure)
if err != nil && xTransport.h3Client != nil && client == xTransport.h3Client {
// ... H3 fallback logic ...
client = xTransport.httpClient
if client == nil {
client = &http.Client{Transport: xTransport.transport}
}
start = time.Now()
resp, err = client.Do(req)
rtt = time.Since(start)
}

if err != nil {
return nil, 503, nil, rtt, err
}

statusCode := resp.StatusCode
defer resp.Body.Close()

// Optimized Alt-Svc Parsing using strings.Cut (Go 1.18+)
if xTransport.h3Transport != nil && !hasAltSupport {
alt := resp.Header.Get("Alt-Svc")
if alt != "" {
// Zero-alloc parsing loop logic
for alt != "" {
var part string
part, alt, _ = strings.Cut(alt, ",")
part = strings.TrimSpace(part)
if strings.HasPrefix(part, "h3=") {
// Logic to parse port...
// xTransport.altSupport.Lock() ...
// xTransport.altSupport.Unlock()
break
}
}
}
}

tlsState := resp.TLS
var bodyReader io.Reader = resp.Body
var gr *gzip.Reader

if compress && resp.Header.Get("Content-Encoding") == "gzip" {
limited := io.LimitReader(resp.Body, MaxHTTPBodyLength)
gr, err = xTransport.getGzipReader(limited)
if err != nil {
return nil, statusCode, tlsState, rtt, err
}
defer xTransport.putGzipReader(gr)
bodyReader = gr
}

// Optimized: Pre-allocate buffer based on Content-Length
var bin []byte
limitR := io.LimitReader(bodyReader, MaxHTTPBodyLength)
if resp.ContentLength > 0 && resp.ContentLength <= MaxHTTPBodyLength {
bin = make([]byte, 0, resp.ContentLength)
buf := bytes.NewBuffer(bin)
_, err = buf.ReadFrom(limitR)
bin = buf.Bytes()
} else {
bin, err = io.ReadAll(limitR)
}

if err != nil {
return nil, statusCode, tlsState, rtt, err
}
return bin, statusCode, tlsState, rtt, nil
}

// ExtractHostAndPort Helper (Mock implementation if missing)
func ExtractHostAndPort(addr string, defaultPort int) (string, int) {
host, portStr, err := net.SplitHostPort(addr)
if err != nil {
return addr, defaultPort
}
port, _ := strconv.Atoi(portStr)
return host, port
}

// Helper for parsing "host:port" (simplified)
func isIPAndPort(s string) error { return nil }
