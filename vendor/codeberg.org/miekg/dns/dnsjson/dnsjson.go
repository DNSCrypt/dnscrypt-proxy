// Package dnsjson implements the RR and RRset as defined in RFC 8427. The message type is not implemented.
// [codeberg.org/miekg/dns.MarshalJSON] and [codeberg.org/miekg/dns.UnmarshalJSON] are the primary interface of this package.
// As an example the RRs:
//
//   - www.example.org. IN A 127.0.0.1
//   - www.example.org. IN A 127.0.0.2
//
// Will be converted into the following JSON:
//
//	{
//	    "NAME": "www.example.org.",
//	    "TTL": 3600,
//	    "TYPEname": "A",
//	    "CLASSname": "IN",
//	    "rrSet": [
//	        {
//	            "RDATAHEX": "7f000001"
//	        },
//	        {
//	            "RDATAHEX": "7f000002"
//	        }
//	    ]
//	}
package dnsjson

import "codeberg.org/miekg/dns/pkg/pool"

// RR represents a DNS RR as specified in RFC 8427.
type RR struct {
	Name      string  `json:"NAME"`                // Name is the owner name of the RR.
	TTL       uint32  `json:"TTL"`                 // TTL is the time-to-live of the RR.
	TypeName  string  `json:"TYPEname,omitempty"`  // TypeName is the string representation of the type. If takes precedence of Type.
	Type      uint16  `json:"TYPE,omitempty"`      // Type is the type of the RR.
	ClassName string  `json:"CLASSname,omitempty"` // ClassName is the string representation of the class. It takes precedence over Class.
	Class     uint16  `json:"CLASS,omitempty"`     // Class is the class of the RR, this is not set, class IN is assumed.
	RdataHex  string  `json:"RDATAHEX,omitempty"`
	RRset     []RRset `json:"rrSet,omitempty"`
}

// RRset represents a DNS RRset as specified in RFC 8427.
type RRset struct {
	RdataHex string `json:"RDATAHEX"`
}

// Pool pools allocations to encode/decode to wire format.
var Pool = pool.New(512)
