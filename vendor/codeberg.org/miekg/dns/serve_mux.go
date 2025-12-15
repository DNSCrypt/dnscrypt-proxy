package dns

import (
	"context"
	"io"
	"sync"
)

// Handler is implemented by any value that implements ServeDNS. The message r is minimally decoded, only up
// to the question section (mostly first 20-ish bytes) are decoded, see [Option]. The rest of the message is available in
// r.Data, so if a message is deemed worthwhile a:
//
//	r.Unpack()
//
// to get the entire message.
//
// The context is cancelled when the server exits. The context carries the pattern of the handler (this is
// commonly the DNS zone) that was used to invoke it. You can retrieve that pattern with [Zone].
type Handler interface {
	ServeDNS(ctx context.Context, w ResponseWriter, r *Msg)
}

// Zone gets the zone from the context. When the server calls a handler it sets the matched pattern in the
// context. If not found it returns the empty string.
func Zone(ctx context.Context) string {
	zone, ok := ctx.Value(contextKeyZone).(string)
	if !ok {
		return ""
	}
	return zone
}

type contextKey string

var contextKeyZone = contextKey("zone")

// The HandlerFunc type is an adapter to allow the use of ordinary functions as DNS handlers.  If f is a function
// with the appropriate signature, HandlerFunc(f) is a Handler object that calls f.
type HandlerFunc func(context.Context, ResponseWriter, *Msg)

// ServeDNS calls f(w, r).
func (f HandlerFunc) ServeDNS(ctx context.Context, w ResponseWriter, r *Msg) { f(ctx, w, r) }

// ServeMux is an DNS request multiplexer. It matches the zone name of each incoming request against a list of
// registered patterns add calls the handler for the pattern that most closely matches the zone name.
//
// ServeMux is DNSSEC aware, meaning that queries for the DS record are redirected to the parent zone (if that
// is also registered), otherwise the child gets the query.
//
// ServeMux is also safe for concurrent access from multiple goroutines. The zero ServeMux is empty and ready for use.
type ServeMux struct {
	z map[string]Handler
	sync.RWMutex
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux { return &ServeMux{z: map[string]Handler{}} }

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

func (mux *ServeMux) match(q string, t uint16) (Handler, string) {
	q = dnsutilCanonical(q)

	var handler Handler
	var ds, off, end = 0, 0, false
	mux.RLock()
	for ; !end; off, end = dnsutilNext(q, off) {
		if h, ok := mux.z[q[off:]]; ok {
			if t != TypeDS {
				mux.RUnlock()
				return h, q[off:]
			}
			// Continue for DS to see if we have a parent too, if so delegate to the parent.
			handler = h
			ds = off
		}
	}
	if handler != nil {
		mux.RUnlock()
		return handler, q[ds:]
	}

	// Wildcard match, if we have found nothing try the root zone as a last resort.
	if h, ok := mux.z["."]; ok {
		mux.RUnlock()
		return h, "."
	}

	mux.RUnlock()
	return nil, ""
}

// Handle adds a handler to the ServeMux for pattern. Identical patterns silently overwrites earlier handlers.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	if dnsutilCanonical(pattern) != pattern || pattern == "" {
		panic("dns: pattern should be in canonical form: " + pattern)
	}
	mux.Lock()
	if mux.z == nil {
		mux.z = make(map[string]Handler)
	}
	mux.z[pattern] = handler
	mux.Unlock()
}

// HandleFunc adds a handler function to the ServeMux for pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(context.Context, ResponseWriter, *Msg)) {
	mux.Handle(pattern, HandlerFunc(handler))
}

// HandleRemove deregisters the handler specific for pattern from the ServeMux.
func (mux *ServeMux) HandleRemove(pattern string) {
	if dnsutilCanonical(pattern) != pattern || pattern == "" {
		panic("dns: pattern should be in canonical form: " + pattern)
	}
	mux.Lock()
	delete(mux.z, pattern)
	mux.Unlock()
}

// ServeDNS dispatches the request to the handler whose pattern most closely matches the request message.
//
// ServeDNS is DNSSEC aware, meaning that queries for the DS record are redirected to the parent zone (if
// that is also registered), otherwise the child gets the query.
//
// If no handler is found a standard REFUSED message is returned. No checks are made on the request message.
func (mux *ServeMux) ServeDNS(ctx context.Context, w ResponseWriter, req *Msg) {
	h, zone := mux.match(req.Question[0].Header().Name, req.qtype)
	if h != nil {
		ctx = context.WithValue(ctx, contextKeyZone, zone)
		h.ServeDNS(ctx, w, req)
		return
	}

	refuse(w, req)
}

// Handle registers the handler with the given pattern in the [DefaultServeMux]. The documentation for
// [ServeMux] explains how patterns are matched.
func Handle(pattern string, handler Handler) { DefaultServeMux.Handle(pattern, handler) }

// HandleRemove deregisters the handle with the given pattern in the [DefaultServeMux].
func HandleRemove(pattern string) { DefaultServeMux.HandleRemove(pattern) }

// HandleFunc registers the handler function with the given pattern in the [DefaultServeMux].
func HandleFunc(pattern string, handler func(context.Context, ResponseWriter, *Msg)) {
	DefaultServeMux.HandleFunc(pattern, handler)
}

// refuse writes a REFUSED response to w.
func refuse(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.Data = r.Data

	// dnsutil.SetReply as used here, but led to all kinds of cyclic imports, just use that very static code here.
	m.ID, m.Rcode = r.ID, RcodeRefused
	m.Response, m.Opcode = true, r.Opcode
	m.RecursionDesired = r.RecursionDesired
	m.CheckingDisabled = r.CheckingDisabled
	m.Security = r.Security
	m.Question = r.Question
	m.Answer, m.Ns, m.Extra, m.Pseudo = nil, nil, nil, nil

	m.Pack()
	io.Copy(w, m)
}
