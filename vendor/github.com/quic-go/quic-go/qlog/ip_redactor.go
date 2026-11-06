package qlog

import (
	"context"
	"net/netip"

	"github.com/quic-go/quic-go/qlogwriter"
)

// RedactIPs wraps a QUIC connection tracer to redact endpoint and preferred addresses.
// redact returns the replacement and whether to apply it.
func RedactIPs(
	tracer func(context.Context, bool, ConnectionID) qlogwriter.Trace,
	redact func(addr netip.AddrPort, isLocal bool) (string, bool),
) func(context.Context, bool, ConnectionID) qlogwriter.Trace {
	if tracer == nil || redact == nil {
		return tracer
	}
	return func(ctx context.Context, client bool, id ConnectionID) qlogwriter.Trace {
		trace := tracer(ctx, client, id)
		if trace == nil {
			return nil
		}
		return &ipRedactingTrace{Trace: trace, redact: redact}
	}
}

type ipRedactingTrace struct {
	qlogwriter.Trace
	redact func(netip.AddrPort, bool) (string, bool)
}

var _ qlogwriter.Trace = &ipRedactingTrace{}

func (t *ipRedactingTrace) AddProducer() qlogwriter.Recorder {
	recorder := t.Trace.AddProducer()
	if recorder == nil {
		return nil
	}
	return &ipRedactingRecorder{Recorder: recorder, redact: t.redact}
}

type ipRedactingRecorder struct {
	qlogwriter.Recorder
	redact func(netip.AddrPort, bool) (string, bool)
}

var _ qlogwriter.Recorder = &ipRedactingRecorder{}

func (r *ipRedactingRecorder) RecordEvent(event qlogwriter.Event) {
	switch e := event.(type) {
	case StartedConnection:
		r.redactEndpoint(e.Local, true, &e.RedactedLocal)
		r.redactEndpoint(e.Remote, false, &e.RedactedRemote)
		event = e
	case TupleAssigned:
		r.redactEndpoint(e.Local, true, &e.RedactedLocal)
		r.redactEndpoint(e.Remote, false, &e.RedactedRemote)
		event = e
	case ParametersSet:
		if e.PreferredAddress != nil {
			isLocal := e.Initiator == InitiatorLocal
			addr := *e.PreferredAddress
			if addr.IPv4.IsValid() {
				if v, ok := r.redact(addr.IPv4, isLocal); ok {
					addr.RedactedIPv4 = &v
				}
			}
			if addr.IPv6.IsValid() {
				if v, ok := r.redact(addr.IPv6, isLocal); ok {
					addr.RedactedIPv6 = &v
				}
			}
			e.PreferredAddress = &addr
			event = e
		}
	}
	r.Recorder.RecordEvent(event)
}

// redactEndpoint sets redacted to the replacement for the endpoint's address, if it should be redacted.
// Otherwise, redacted is left unchanged.
func (r *ipRedactingRecorder) redactEndpoint(info TupleEndpointInfo, isLocal bool, redacted **string) {
	addr := info.IPv4
	if !addr.IsValid() {
		addr = info.IPv6
	}
	if !addr.IsValid() {
		return
	}
	if v, ok := r.redact(addr, isLocal); ok {
		*redacted = &v
	}
}
