package http2

var (
	StringPath          = []byte(":path")
	StringStatus        = []byte(":status")
	StringAuthority     = []byte(":authority")
	StringScheme        = []byte(":scheme")
	StringMethod        = []byte(":method")
	StringServer        = []byte("server")
	StringContentLength = []byte("content-length")
	StringContentType   = []byte("content-type")
	StringUserAgent     = []byte("user-agent")
	StringGzip          = []byte("gzip")
	StringGET           = []byte("GET")
	StringHEAD          = []byte("HEAD")
	StringPOST          = []byte("POST")
	StringHTTP2         = []byte("HTTP/2")
)

func ToLower(b []byte) []byte {
	for i := range b {
		b[i] |= 32
	}

	return b
}

const (
	// H2TLSProto is the string used in ALPN-TLS negotiation.
	H2TLSProto = "h2"
	// H2Clean is the string used in HTTP headers by the client to upgrade the connection.
	H2Clean = "h2c"
)
