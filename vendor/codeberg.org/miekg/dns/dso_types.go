package dns

import "fmt"

// DSO option codes. All DSO types and constants in this package carry the Stateful prefix.
const (
	StatefulNone        uint16 = 0x0
	StatefulKEEPALIVE   uint16 = 0x1
	StatefulRETRYDELAY  uint16 = 0x2
	StatefulDPADDING    uint16 = 0x3
	StatefulSUBSCRIBE   uint16 = 0x40
	StatefulPUSH        uint16 = 0x41
	StatefulUNSUBSCRIBE uint16 = 0x42
	StatefulRECONFIRM   uint16 = 0x43
)

// TODO: for string we want to be able parse them with New() at some point...
// string output is terrible at the moment, must look way more like RRs.
// builderPool usage!

// KEEPALIVE, see RFC 8490, section 7.1.
// This record must be put in the stateful section.
type KEEPALIVE struct {
	Timeout  uint32
	Interval uint32
}

func (d *KEEPALIVE) String() string {
	return fmt.Sprintf("timeout %dms, interval %dms", d.Timeout, d.Interval)
}

func (d *KEEPALIVE) Data() RDATA { return d }

// RETRYDELAY, see RFC 8490, section 7.2.
// This record must be put in the stateful section.
type RETRYDELAY struct {
	Delay uint32
}

func (d *RETRYDELAY) String() string {
	return fmt.Sprintf("delay %dms", d.Delay)
}

func (d *RETRYDELAY) Data() RDATA { return d }

// DPADDING option is used to add padding, see RRC 8490 section 7.3.
// This record must be put in the stateful section.
type DPADDING struct {
	Padding string `dns:"hex"`
}

func (d *DPADDING) String() string {
	return fmt.Sprintf("padding %s", d.Padding)
}

func (d *DPADDING) Data() RDATA { return d }

/*
TODO(miek): commented out because rdata with full blown RRs isn't supported.
// SUBSCRIBE, see RFC 8765.
type SUBSCRIBE struct {
	RR RR // RR is one without rdata, only name, class, and type are significant.
}

func (d *SUBSCRIBE) String() string { return d.RR.String() }

// PUSH, see RFC 8765.
type PUSH struct {
	RRs []RR
}

func (d *PUSH) String() string {
	s := ""
	for i := range d.RRs {
		s += d.RRs[i].String()
		if i < len(d.RRs) {
			s += "\n"
		}
	}
	return s
}

// UNSUBSSCRIBE, see RFC 8765.
type UNSUBSCRIBE struct {
	ID uint16
}

func (d *UNSUBSCRIBE) String() string { return fmt.Sprintf("%d", d.ID) }

// RECONFIRM, see RFC 8765.
type RECONFIRM struct {
	RR RR
}

func (d *RECONFIRM) String() string { return d.RR.String() }
*/
