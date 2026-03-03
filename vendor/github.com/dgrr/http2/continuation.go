package http2

const FrameContinuation FrameType = 0x9

var (
	_ Frame            = &Continuation{}
	_ FrameWithHeaders = &Continuation{}
)

// Continuation represents the Continuation frame.
//
// Continuation frame can carry raw headers and/or the EndHeaders flag.
//
// https://tools.ietf.org/html/rfc7540#section-6.10
type Continuation struct {
	endHeaders bool
	rawHeaders []byte
}

func (c *Continuation) Type() FrameType {
	return FrameContinuation
}

func (c *Continuation) Reset() {
	c.endHeaders = false
	c.rawHeaders = c.rawHeaders[:0]
}

func (c *Continuation) CopyTo(cc *Continuation) {
	cc.endHeaders = c.endHeaders
	cc.rawHeaders = append(cc.rawHeaders[:0], c.rawHeaders...)
}

// Headers returns Header bytes.
func (c *Continuation) Headers() []byte {
	return c.rawHeaders
}

func (c *Continuation) SetEndHeaders(value bool) {
	c.endHeaders = value
}

func (c *Continuation) EndHeaders() bool {
	return c.endHeaders
}

func (c *Continuation) SetHeader(b []byte) {
	c.rawHeaders = append(c.rawHeaders[:0], b...)
}

// AppendHeader appends the contents of `b` into the header.
func (c *Continuation) AppendHeader(b []byte) {
	c.rawHeaders = append(c.rawHeaders, b...)
}

// Write writes `b` into the header. Write is equivalent to AppendHeader.
func (c *Continuation) Write(b []byte) (int, error) {
	n := len(b)
	c.AppendHeader(b)
	return n, nil
}

func (c *Continuation) Deserialize(fr *FrameHeader) error {
	c.endHeaders = fr.Flags().Has(FlagEndHeaders)
	c.SetHeader(fr.payload)

	return nil
}

func (c *Continuation) Serialize(fr *FrameHeader) {
	if c.endHeaders {
		fr.SetFlags(
			fr.Flags().Add(FlagEndHeaders))
	}

	fr.setPayload(c.rawHeaders)
}
