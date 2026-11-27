package http3

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

type qpackError struct{ err error }

func (e *qpackError) Error() string { return fmt.Sprintf("qpack: %v", e.err) }
func (e *qpackError) Unwrap() error { return e.err }

// A fieldSectionReadError means that a field section was not read, so it wasn't decoded either.
type fieldSectionReadError struct{ err error }

func (e *fieldSectionReadError) Error() string { return e.err.Error() }
func (e *fieldSectionReadError) Unwrap() error { return e.err }

type headerFieldError struct {
	error
	InvalidName  bool
	InvalidValue bool
}

var (
	errHeaderTooLarge       = errors.New("http3: headers too large")
	errHeadersFrameTooLarge = errors.New("http3: HEADERS frame too large")
)

// decodeErrorCode is the stream error code for a header section that failed to decode.
func decodeErrorCode(err error) quic.StreamErrorCode {
	if _, ok := errors.AsType[*qpackError](err); ok {
		return quic.StreamErrorCode(ErrCodeQPACKDecompressionFailed)
	}
	return quic.StreamErrorCode(ErrCodeMessageError)
}

// readHeaderBlock preallocates up to 8 KiB, growing larger buffers as data arrives.
// The caller must check length against the configured header size limit first.
func readHeaderBlock(r io.Reader, length uint64) ([]byte, error) {
	const maxInitialBufferSize = 8 << 10

	b := make([]byte, min(length, maxInitialBufferSize))
	if length <= maxInitialBufferSize {
		_, err := io.ReadFull(r, b)
		return b, err
	}
	buf := bytes.NewBuffer(b[:0])
	n, err := io.CopyN(buf, r, int64(length))
	if errors.Is(err, io.EOF) && n > 0 {
		err = io.ErrUnexpectedEOF
	}
	return buf.Bytes(), err
}

type header struct {
	// Pseudo header fields defined in RFC 9114
	Path      string
	Method    string
	Authority string
	Scheme    string
	Status    string
	// for Extended connect
	Protocol string
	// parsed and deduplicated. -1 if no Content-Length header is sent
	ContentLength int64
	// all non-pseudo headers.
	// Some pseudo-header keys with nil values are temporarily added to track presence.
	Headers http.Header
}

func parseHeaders(decodeFn qpack.DecodeFunc, isRequest bool, sizeLimit int, headerFields *[]qpack.HeaderField) (header, error) {
	hdr := header{Headers: make(http.Header)}
	var readFirstRegularHeader, readContentLength, hasMethod, hasStatus bool
	var contentLengthStr string
	for {
		h, err := decodeFn()
		if err != nil {
			if err == io.EOF {
				break
			}
			return header{}, &qpackError{err}
		}
		if headerFields != nil {
			*headerFields = append(*headerFields, h)
		}
		// RFC 9114, section 4.2.2:
		// The size of a field list is calculated based on the uncompressed size of fields,
		// including the length of the name and value in bytes plus an overhead of 32 bytes for each field.
		sizeLimit -= len(h.Name) + len(h.Value) + 32
		if sizeLimit < 0 {
			return header{}, errHeaderTooLarge
		}
		if err := validateHeaderFieldNameAndValue(h); err != nil {
			return header{}, err
		}
		if h.IsPseudo() {
			if readFirstRegularHeader {
				// all pseudo headers must appear before regular header fields, see section 4.3 of RFC 9114
				return header{}, fmt.Errorf("received pseudo header %s after a regular header field", h.Name)
			}
			var isResponsePseudoHeader bool  // pseudo headers are either valid for requests or for responses
			var isDuplicatePseudoHeader bool // pseudo headers are allowed to appear exactly once
			switch h.Name {
			case ":path":
				_, isDuplicatePseudoHeader = hdr.Headers[h.Name]
				hdr.Headers[h.Name] = nil
				hdr.Path = h.Value
			case ":method":
				isDuplicatePseudoHeader = hasMethod
				hasMethod = true
				hdr.Method = h.Value
			case ":authority":
				_, isDuplicatePseudoHeader = hdr.Headers[h.Name]
				hdr.Headers[h.Name] = nil
				hdr.Authority = h.Value
			case ":protocol": // RFC 9220
				_, isDuplicatePseudoHeader = hdr.Headers[h.Name]
				hdr.Headers[h.Name] = nil
				hdr.Protocol = h.Value
			case ":scheme":
				_, isDuplicatePseudoHeader = hdr.Headers[h.Name]
				hdr.Headers[h.Name] = nil
				// URI schemes are case-insensitive and canonically lowercase, see section 3.1 of RFC 3986
				hdr.Scheme = strings.ToLower(h.Value)
			case ":status":
				isDuplicatePseudoHeader = hasStatus
				hasStatus = true
				hdr.Status = h.Value
				isResponsePseudoHeader = true
			default:
				return header{}, fmt.Errorf("unknown pseudo header: %s", h.Name)
			}
			if isDuplicatePseudoHeader {
				return header{}, fmt.Errorf("duplicate pseudo header: %s", h.Name)
			}
			if isRequest && isResponsePseudoHeader {
				return header{}, fmt.Errorf("invalid request pseudo header: %s", h.Name)
			}
			if !isRequest && !isResponsePseudoHeader {
				return header{}, fmt.Errorf("invalid response pseudo header: %s", h.Name)
			}
		} else {
			if err := validateRegularHeaderField(h, isRequest); err != nil {
				return header{}, err
			}
			readFirstRegularHeader = true
			switch h.Name {
			case "content-length":
				// Ignore duplicate Content-Length headers.
				// Fail if the duplicates differ.
				if !readContentLength {
					readContentLength = true
					contentLengthStr = h.Value
				} else if contentLengthStr != h.Value {
					return header{}, fmt.Errorf("contradicting content lengths (%s and %s)", contentLengthStr, h.Value)
				}
			default:
				hdr.Headers.Add(h.Name, h.Value)
			}
		}
	}
	hdr.ContentLength = -1
	if len(contentLengthStr) > 0 {
		// use ParseUint instead of ParseInt, so that parsing fails on negative values
		cl, err := strconv.ParseUint(contentLengthStr, 10, 63)
		if err != nil {
			return header{}, fmt.Errorf("invalid content length: %w", err)
		}
		hdr.Headers.Set("Content-Length", contentLengthStr)
		hdr.ContentLength = int64(cl)
	}
	return hdr, nil
}

func validateHeaderFieldNameAndValue(h qpack.HeaderField) error {
	// field names need to be lowercase, see section 4.2 of RFC 9114
	lowercase := strings.ToLower(h.Name) == h.Name
	invalidName := !httpguts.ValidHeaderFieldName(strings.TrimPrefix(h.Name, ":")) || !lowercase
	invalidValue := !httpguts.ValidHeaderFieldValue(h.Value)
	if !lowercase {
		return &headerFieldError{
			error:        fmt.Errorf("header field is not lower-case: %s", h.Name),
			InvalidName:  invalidName,
			InvalidValue: invalidValue,
		}
	}
	if invalidValue {
		return &headerFieldError{
			error:        fmt.Errorf("invalid header field value for %s: %q", h.Name, h.Value),
			InvalidName:  invalidName,
			InvalidValue: invalidValue,
		}
	}
	if invalidName {
		return &headerFieldError{
			error:        fmt.Errorf("invalid header field name: %q", h.Name),
			InvalidName:  invalidName,
			InvalidValue: invalidValue,
		}
	}
	return nil
}

// isForbiddenField reports whether HTTP/3 forbids a field with a lower-case name.
// Connection-specific fields are forbidden. The only exception is TE in a request header,
// which must not contain any value other than "trailers".
func isForbiddenField(name, value string, isRequestHeader bool) bool {
	switch name {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
		return true
	case "te":
		return !isRequestHeader || value != "trailers"
	}
	return false
}

func validateRegularHeaderField(h qpack.HeaderField, isRequestHeader bool) error {
	if isForbiddenField(h.Name, h.Value, isRequestHeader) {
		return fmt.Errorf("invalid connection-specific header field %s: %q", h.Name, h.Value)
	}
	return nil
}

// canSendField reports whether a field with a lower-case name is valid
// and allowed in a response header or a trailer section.
func canSendField(name, value string) bool {
	return httpguts.ValidHeaderFieldName(name) && httpguts.ValidHeaderFieldValue(value) && !isForbiddenField(name, value, false)
}

func validateTrailerHeaderField(h qpack.HeaderField) error {
	if err := validateRegularHeaderField(h, false); err != nil {
		return err
	}
	if !httpguts.ValidTrailerHeader(h.Name) {
		return fmt.Errorf("invalid trailer field name: %q", h.Name)
	}
	return nil
}

func parseTrailers(decodeFn qpack.DecodeFunc, sizeLimit int, headerFields *[]qpack.HeaderField) (http.Header, error) {
	h := make(http.Header)
	for {
		hf, err := decodeFn()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, &qpackError{err}
		}
		if headerFields != nil {
			*headerFields = append(*headerFields, hf)
		}
		// RFC 9114, section 4.2.2:
		// The size of a field list is calculated based on the uncompressed size of fields,
		// including the length of the name and value in bytes plus an overhead of 32 bytes for each field.
		sizeLimit -= len(hf.Name) + len(hf.Value) + 32
		if sizeLimit < 0 {
			return nil, errHeaderTooLarge
		}
		if err := validateHeaderFieldNameAndValue(hf); err != nil {
			return nil, err
		}
		if hf.IsPseudo() {
			return nil, fmt.Errorf("http3: received pseudo header in trailer: %s", hf.Name)
		}
		if err := validateTrailerHeaderField(hf); err != nil {
			return nil, err
		}
		h.Add(hf.Name, hf.Value)
	}
	return h, nil
}

func requestFromHeaders(decodeFn qpack.DecodeFunc, sizeLimit int, headerFields *[]qpack.HeaderField) (*http.Request, error) {
	hdr, err := parseHeaders(decodeFn, true, sizeLimit, headerFields)
	if err != nil {
		return nil, err
	}
	_, hasPath := hdr.Headers[":path"]
	_, hasAuthority := hdr.Headers[":authority"]
	_, hasScheme := hdr.Headers[":scheme"]
	_, hasProtocol := hdr.Headers[":protocol"]
	delete(hdr.Headers, ":path")
	delete(hdr.Headers, ":authority")
	delete(hdr.Headers, ":scheme")
	delete(hdr.Headers, ":protocol")

	if hdr.Method == "" {
		return nil, errors.New(":method must not be empty")
	}
	if !validMethod(hdr.Method) {
		return nil, fmt.Errorf("invalid :method: %q", hdr.Method)
	}

	// RFC 9114, Section 4.3.1 allows Host as an alternative to :authority.
	hosts := hdr.Headers["Host"]
	if len(hosts) > 1 {
		return nil, errors.New("too many Host headers")
	}
	host := hdr.Headers.Get("Host")
	// If both are present, they must contain the same value.
	if hasAuthority && len(hosts) > 0 && hdr.Authority != host {
		return nil, errors.New(":authority and Host header field values do not match")
	}
	isConnect := hdr.Method == http.MethodConnect
	// If :authority is missing, use Host as a fallback for HTTP(S) requests.
	// CONNECT requests are excluded since they must provide :authority (RFC 9114, Section 4.4).
	if !isConnect && !hasAuthority && (hdr.Scheme == "http" || hdr.Scheme == "https") {
		hdr.Authority = host
	}
	if strings.Contains(hdr.Authority, "@") && (hdr.Scheme == "http" || hdr.Scheme == "https") {
		return nil, errors.New("userinfo is not allowed in :authority")
	}

	// concatenate cookie headers, see https://tools.ietf.org/html/rfc6265#section-5.4
	if len(hdr.Headers["Cookie"]) > 0 {
		hdr.Headers.Set("Cookie", strings.Join(hdr.Headers["Cookie"], "; "))
	}

	// Extended CONNECT, see https://datatracker.ietf.org/doc/html/rfc8441#section-4
	isExtendedConnected := isConnect && hdr.Protocol != ""
	if isExtendedConnected {
		if !validExtendedConnectProtocol(hdr.Protocol) {
			return nil, fmt.Errorf("invalid :protocol: %q", hdr.Protocol)
		}
		if hdr.Scheme == "" || hdr.Path == "" || hdr.Authority == "" {
			return nil, errors.New("extended CONNECT: :scheme, :path and :authority must not be empty")
		}
	} else if isConnect {
		if hasScheme || hasPath || hdr.Authority == "" { // normal CONNECT
			return nil, errors.New(":scheme and :path must be omitted and :authority must not be empty")
		}
	} else if len(hdr.Path) == 0 || len(hdr.Authority) == 0 {
		return nil, errors.New(":path and :authority must not be empty")
	}

	if !isExtendedConnected && hasProtocol {
		return nil, errors.New(":protocol must be omitted")
	}
	// url.ParseRequestURI accepts absolute URIs and "*", so validate :path before parsing.
	validPath := strings.HasPrefix(hdr.Path, "/") || (hdr.Method == http.MethodOptions && hdr.Path == "*")
	if (!isConnect || isExtendedConnected) && !validPath {
		return nil, fmt.Errorf("invalid :path: %q", hdr.Path)
	}
	// Like net/http's HTTP/2 server, only accept http and https for regular requests.
	// This also rejects a missing :scheme, see section 4.3.1 of RFC 9114.
	if !isConnect && hdr.Scheme != "http" && hdr.Scheme != "https" {
		return nil, fmt.Errorf("invalid :scheme: %q", hdr.Scheme)
	}
	// Reject bytes that can't appear in a host and port, see section 4.3.1 of RFC 9114.
	// Like net/http, we don't validate the host and port syntax, see https://github.com/golang/go/issues/78172.
	if !httpguts.ValidHostHeader(hdr.Authority) {
		return nil, fmt.Errorf("invalid :authority: %q", hdr.Authority)
	}

	var u *url.URL
	var requestURI string

	protocol := "HTTP/3.0"

	if isExtendedConnected {
		u, err = url.ParseRequestURI(hdr.Path)
		if err != nil {
			return nil, err
		}
		requestURI = hdr.Path
		protocol = hdr.Protocol
	} else if isConnect {
		u = &url.URL{Host: hdr.Authority}
		requestURI = hdr.Authority
	} else {
		u, err = url.ParseRequestURI(hdr.Path)
		if err != nil {
			return nil, fmt.Errorf("invalid request URI: %w", err)
		}
		requestURI = hdr.Path
	}

	req := &http.Request{
		Method:        hdr.Method,
		URL:           u,
		Proto:         protocol,
		ProtoMajor:    3,
		ProtoMinor:    0,
		Header:        hdr.Headers,
		Body:          nil,
		ContentLength: hdr.ContentLength,
		Host:          hdr.Authority,
		RequestURI:    requestURI,
	}
	req.Trailer = extractAnnouncedTrailers(req.Header)
	return req, nil
}

func validExtendedConnectProtocol(protocol string) bool {
	// RFC 9220 specifies that the semantics of the :protocol pseudo are the same as defined in RFC 8441.
	// RFC 8441, Section 4 specifies that :protocol is a single value from the HTTP Upgrade Token Registry.
	// RFC 9110, Section 16.7 specifies that HTTP Upgrade Token Registry uses token grammar.
	// Therefore, ValidHeaderFieldName is the right syntax check here, despite the misleading name.
	return httpguts.ValidHeaderFieldName(protocol)
}

// updateResponseFromHeaders sets up http.Response as an HTTP/3 response,
// using the decoded qpack header filed.
// It is only called for the HTTP header (and not the HTTP trailer).
func updateResponseFromHeaders(rsp *http.Response, decodeFn qpack.DecodeFunc, sizeLimit int, headerFields *[]qpack.HeaderField) error {
	hdr, err := parseHeaders(decodeFn, false, sizeLimit, headerFields)
	if err != nil {
		return err
	}
	if hdr.Status == "" {
		return errors.New("missing :status field")
	}
	rsp.Proto = "HTTP/3.0"
	rsp.ProtoMajor = 3
	rsp.Header = hdr.Headers
	rsp.Trailer = extractAnnouncedTrailers(rsp.Header)
	rsp.ContentLength = hdr.ContentLength

	// Status codes have three digits and range from 100 to 599, see section 15 of RFC 9110.
	status, err := strconv.Atoi(hdr.Status)
	if err != nil || len(hdr.Status) != 3 || status < 100 || status > 599 {
		return fmt.Errorf("invalid status code: %q", hdr.Status)
	}
	rsp.StatusCode = status
	rsp.Status = hdr.Status + " " + http.StatusText(status)
	return nil
}

// extractAnnouncedTrailers extracts trailer keys from the "Trailer" header.
// It returns a map with the announced keys set to nil values, and removes the "Trailer" header.
// It handles both duplicate as well as comma-separated values for the Trailer header.
// For example:
//
//	Trailer: Trailer1, Trailer2
//	Trailer: Trailer3
//
// Will result in a map containing the keys "Trailer1", "Trailer2", "Trailer3" with nil values.
func extractAnnouncedTrailers(header http.Header) http.Header {
	rawTrailers, ok := header["Trailer"]
	if !ok {
		return nil
	}

	trailers := make(http.Header)
	for _, rawVal := range rawTrailers {
		for val := range strings.SplitSeq(rawVal, ",") {
			trailers[http.CanonicalHeaderKey(textproto.TrimString(val))] = nil
		}
	}
	delete(header, "Trailer")
	return trailers
}

// writeTrailers encodes and writes HTTP trailers as a HEADERS frame.
// It returns true if trailers were written, false if there were no trailers to write.
func writeTrailers(wr io.Writer, trailers http.Header, streamID quic.StreamID, qlogger qlogwriter.Recorder) (bool, error) {
	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	var headerFields []qlog.HeaderField
	if qlogger != nil {
		headerFields = make([]qlog.HeaderField, 0, len(trailers))
	}

	for k, vals := range trailers {
		if len(vals) == 0 {
			continue
		}
		if !httpguts.ValidTrailerHeader(k) {
			continue
		}
		lowercaseKey := strings.ToLower(k)
		for _, v := range vals {
			if !canSendField(lowercaseKey, v) {
				continue
			}
			if err := enc.WriteField(qpack.HeaderField{Name: lowercaseKey, Value: v}); err != nil {
				return false, err
			}
			if qlogger != nil {
				headerFields = append(headerFields, qlog.HeaderField{Name: lowercaseKey, Value: v})
			}
		}
	}
	if buf.Len() == 0 {
		return false, nil
	}

	b := make([]byte, 0, frameHeaderLen+buf.Len())
	b = (&headersFrame{Length: uint64(buf.Len())}).Append(b)
	b = append(b, buf.Bytes()...)
	if qlogger != nil {
		qlogCreatedHeadersFrame(qlogger, streamID, len(b), buf.Len(), headerFields)
	}
	_, err := wr.Write(b)
	return true, err
}
