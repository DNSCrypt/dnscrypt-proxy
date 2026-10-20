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
// registered patterns add calls the handler for the pattern that most closely matches the zone name and
// class.
//
// ServeMux is DNSSEC aware, meaning that queries for the DS record are redirected to the parent zone (if that
// is also registered), otherwise the child gets the query.
//
// ServeMux is also safe for concurrent access from multiple goroutines. The zero ServeMux is empty and ready for use.
type ServeMux struct {
	z map[uint16]map[string]Handler
	sync.RWMutex
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux { return &ServeMux{z: map[uint16]map[string]Handler{}} }

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

func (mux *ServeMux) match(q string, t, c uint16) (Handler, string) {
	q = dnsutilCanonical(q)

	var handler Handler
	var off, ds, end = 0, 0, false
	mux.RLock()
	m, ok := mux.z[c] // get the class map
	if !ok {
		// we don't know anything about the class.
		mux.RUnlock()
		return nil, ""
	}
	for ; !end; off, end = dnsutilNext(q, off) {
		if h, ok := m[q[off:]]; ok {
			if t != TypeDS {
				mux.RUnlock()
				return h, q[off:]
			}
			// Continue for DS to see if we have a parent too, if so delegate to the parent.
			// If we already found a DS target we should return the current handler as that
			// should be a parent.
			if handler != nil { // Set in previous iteration, we return "this one" (= h).
				mux.RUnlock()
				return h, q[off:]
			}
			handler = h
			ds = off
		}
	}
	mux.RUnlock()
	if handler != nil {
		return handler, q[ds:]
	}
	return nil, ""
}

// Handle adds a handler to the ServeMux for pattern. Identical patterns silently overwrites earlier handlers.
// Optionally a class can be given, this defaults to [ClassINET].
func (mux *ServeMux) Handle(pattern string, handler Handler, class ...uint16) {
	if dnsutilCanonical(pattern) != pattern || pattern == "" {
		panic("dns: pattern should be in canonical form: " + pattern)
	}
	mux.Lock()
	if mux.z == nil {
		mux.z = make(map[uint16]map[string]Handler)
	}
	c := uint16(ClassINET)
	if len(class) > 0 {
		c = class[0]
	}
	if mux.z[c] == nil {
		mux.z[c] = make(map[string]Handler)
	}
	mux.z[c][pattern] = handler
	mux.Unlock()
}

// HandleFunc adds a handler function to the ServeMux for pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(context.Context, ResponseWriter, *Msg), class ...uint16) {
	mux.Handle(pattern, HandlerFunc(handler), class...)
}

// HandleRemove deregisters the handler specific for pattern from the ServeMux. Optionally a class can be
// given, this defaults to [ClassINET].
func (mux *ServeMux) HandleRemove(pattern string, class ...uint16) {
	if dnsutilCanonical(pattern) != pattern || pattern == "" {
		panic("dns: pattern should be in canonical form: " + pattern)
	}
	mux.Lock()
	if len(class) > 0 {
		delete(mux.z[class[0]], pattern)
	} else {
		delete(mux.z[ClassINET], pattern)
	}
	mux.Unlock()
}

// ServeDNS dispatches the request to the handler whose pattern most closely matches the request message.
//
// ServeDNS is DNSSEC aware, meaning that queries for the DS record are redirected to the parent zone (if
// that is also registered), otherwise the current zone gets the query.
//
// If no handler is found a standard REFUSED message is returned. No checks are made on the request message.
func (mux *ServeMux) ServeDNS(ctx context.Context, w ResponseWriter, req *Msg) {
	if req.qtype == 0 { // this is an implicit check that we've at least seen something resembling a question
		refuse(w, req)
		return
	}

	if h, zone := mux.match(req.Question[0].Header().Name, req.qtype, req.qclass); h != nil {
		h.ServeDNS(context.WithValue(ctx, contextKeyZone, zone), w, req)
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

	// dnsutil.SetReply was used here, but led to all kinds of cyclic imports, just use that very static code here.
	m.ID, m.Rcode = r.ID, RcodeRefused
	m.Response, m.Opcode = true, r.Opcode
	m.RecursionDesired = r.RecursionDesired
	m.CheckingDisabled = r.CheckingDisabled
	m.Security = r.Security
	m.Question = r.Question
	m.Answer, m.Ns, m.Extra, m.Pseudo = nil, nil, nil, nil

	if err := m.Pack(); err != nil {
		msgPut(m)
		return
	}
	io.Copy(w, m)
}
