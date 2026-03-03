package http2

const FrameSettings FrameType = 0x4

var _ Frame = &Settings{}

// default Settings parameters.
const (
	defaultHeaderTableSize   uint32 = 4096
	defaultConcurrentStreams uint32 = 100
	defaultWindowSize        uint32 = 1<<16 - 1
	defaultDataFrameSize     uint32 = 1 << 14

	maxFrameSize = 1<<24 - 1
)

// FrameSettings string values (https://httpwg.org/specs/rfc7540.html#SettingValues)
const (
	HeaderTableSize      uint16 = 0x1
	EnablePush           uint16 = 0x2
	MaxConcurrentStreams uint16 = 0x3
	MaxWindowSize        uint16 = 0x4
	MaxFrameSize         uint16 = 0x5
	MaxHeaderListSize    uint16 = 0x6
)

// Settings is the options to establish between endpoints
// when starting the connection.
//
// These options have been humanized.
type Settings struct {
	ack         bool
	rawSettings []byte
	tableSize   uint32
	enablePush  bool
	maxStreams  uint32
	windowSize  uint32
	frameSize   uint32
	headerSize  uint32
}

func (st *Settings) Type() FrameType {
	return FrameSettings
}

// Reset resets settings to default values.
func (st *Settings) Reset() {
	// default settings
	st.tableSize = defaultHeaderTableSize
	st.maxStreams = defaultConcurrentStreams
	st.windowSize = defaultWindowSize
	st.frameSize = defaultDataFrameSize
	st.enablePush = false
	st.headerSize = 0
	st.rawSettings = st.rawSettings[:0]
	st.ack = false
}

// CopyTo copies st fields to st2.
func (st *Settings) CopyTo(st2 *Settings) {
	st2.ack = st.ack
	st2.rawSettings = append(st2.rawSettings[:0], st.rawSettings...)
	st2.tableSize = st.tableSize
	st2.enablePush = st.enablePush
	st2.maxStreams = st.maxStreams
	st2.windowSize = st.windowSize
	st2.frameSize = st.frameSize
	st2.headerSize = st.headerSize
}

// SetHeaderTableSize sets the maximum size of the header
// compression table used to decode header blocks.
//
// Default value is 4096.
func (st *Settings) SetHeaderTableSize(size uint32) {
	st.tableSize = size
}

// HeaderTableSize returns the maximum size of the header
// compression table used to decode header blocks.
//
// Default value is 4096.
func (st *Settings) HeaderTableSize() uint32 {
	return st.tableSize
}

// SetPush allows to set the PushPromise settings.
//
// If value is true the Push Promise will be enabled.
// if not the Push Promise will be disabled.
func (st *Settings) SetPush(value bool) {
	st.enablePush = value
}

func (st *Settings) Push() bool {
	return st.enablePush
}

// SetMaxConcurrentStreams sets the maximum number of
// concurrent Streams that the sender will allow.
//
// Default value is 100. This value does not have max limit.
func (st *Settings) SetMaxConcurrentStreams(streams uint32) {
	st.maxStreams = streams
}

// MaxConcurrentStreams returns the maximum number of
// concurrent Streams that the sender will allow.
//
// Default value is 100. This value does not have max limit.
func (st *Settings) MaxConcurrentStreams() uint32 {
	return st.maxStreams
}

// SetMaxWindowSize sets the sender's initial window size
// for Stream-level flow control.
//
// Default value is 1 << 16 - 1
// Maximum value is 1 << 31 - 1.
func (st *Settings) SetMaxWindowSize(size uint32) {
	st.windowSize = size
}

// MaxWindowSize returns the sender's initial window size
// for Stream-level flow control.
//
// Default value is 1 << 16 - 1
// Maximum value is 1 << 31 - 1.
func (st *Settings) MaxWindowSize() uint32 {
	return st.windowSize
}

// SetMaxFrameSize sets the size of the largest frame
// Payload that the sender is willing to receive.
//
// Default value is 1 << 14
// Maximum value is 1 << 24 - 1.
func (st *Settings) SetMaxFrameSize(size uint32) {
	st.frameSize = size
}

// MaxFrameSize returns the size of the largest frame
// Payload that the sender is willing to receive.
//
// Default value is 1 << 14
// Maximum value is 1 << 24 - 1.
func (st *Settings) MaxFrameSize() uint32 {
	return st.frameSize
}

// SetMaxHeaderListSize sets maximum size of header list uncompressed.
//
// If this value is 0 indicates that there are no limit.
func (st *Settings) SetMaxHeaderListSize(size uint32) {
	st.headerSize = size
}

// MaxHeaderListSize returns maximum size of header list uncompressed.
//
// If this value is 0 indicates that there are no limit.
func (st *Settings) MaxHeaderListSize() uint32 {
	return st.headerSize
}

// Read reads from d and decodes the read values into st.
func (st *Settings) Read(d []byte) error {
	var b []byte
	var key uint16
	var value uint32

	last, i, n := 0, 6, len(d)

	for i <= n {
		b = d[last:i]
		key = uint16(b[0])<<8 | uint16(b[1])
		value = uint32(b[2])<<24 | uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5])

		switch key {
		case HeaderTableSize:
			st.tableSize = value
		case EnablePush:
			if value != 0 && value != 1 {
				return NewGoAwayError(ProtocolError, "wrong value for SETTINGS_ENABLE_PUSH")
			}
			st.enablePush = value != 0
		case MaxConcurrentStreams:
			st.maxStreams = value
		case MaxWindowSize:
			if value > 1<<31-1 {
				return NewGoAwayError(FlowControlError, "SETTINGS_INITIAL_WINDOW_SIZE above maximum")
			}
			st.windowSize = value
		case MaxFrameSize:
			if value < 1<<14 || value > 1<<24-1 {
				return NewGoAwayError(ProtocolError, "wrong value for SETTINGS_MAX_FRAME_SIZE")
			}
			st.frameSize = value
		case MaxHeaderListSize:
			st.headerSize = value
		}

		last = i
		i += 6
	}
	return nil
}

// Encode encodes settings to be sent through the wire.
func (st *Settings) Encode() {
	st.rawSettings = st.rawSettings[:0]

	if st.tableSize != 0 {
		st.rawSettings = append(st.rawSettings,
			byte(HeaderTableSize>>8), byte(HeaderTableSize),
			byte(st.tableSize>>24), byte(st.tableSize>>16),
			byte(st.tableSize>>8), byte(st.tableSize),
		)
	}

	if st.enablePush {
		st.rawSettings = append(st.rawSettings,
			byte(EnablePush>>8), byte(EnablePush),
			0, 0, 0, 1,
		)
	}

	if st.maxStreams != 0 {
		st.rawSettings = append(st.rawSettings,
			byte(MaxConcurrentStreams>>8), byte(MaxConcurrentStreams),
			byte(st.maxStreams>>24), byte(st.maxStreams>>16),
			byte(st.maxStreams>>8), byte(st.maxStreams),
		)
	}

	if st.windowSize != 0 {
		st.rawSettings = append(st.rawSettings,
			byte(MaxWindowSize>>8), byte(MaxWindowSize),
			byte(st.windowSize>>24), byte(st.windowSize>>16),
			byte(st.windowSize>>8), byte(st.windowSize),
		)
	}

	if st.frameSize != 0 {
		st.rawSettings = append(st.rawSettings,
			byte(MaxFrameSize>>8), byte(MaxFrameSize),
			byte(st.frameSize>>24), byte(st.frameSize>>16),
			byte(st.frameSize>>8), byte(st.frameSize),
		)
	}

	if st.headerSize != 0 {
		st.rawSettings = append(st.rawSettings,
			byte(MaxHeaderListSize>>8), byte(MaxHeaderListSize),
			byte(st.headerSize>>24), byte(st.headerSize>>16),
			byte(st.headerSize>>8), byte(st.headerSize),
		)
	}
}

// IsAck returns true if settings has FlagAck set.
func (st *Settings) IsAck() bool {
	return st.ack
}

// SetAck sets FlagAck when WriteTo is called.
func (st *Settings) SetAck(ack bool) {
	st.ack = ack
}

func (st *Settings) Deserialize(fr *FrameHeader) error {
	if len(fr.payload)%6 != 0 {
		return NewGoAwayError(FrameSizeError, "wrong payload for settings")
	}

	st.ack = fr.Flags().Has(FlagAck)

	if st.IsAck() && len(fr.payload) > 0 {
		return NewGoAwayError(FrameSizeError, "settings with ack and payload")
	}

	return st.Read(fr.payload)
}

func (st *Settings) Serialize(fr *FrameHeader) {
	if st.ack { // ACK should be empty
		fr.SetFlags(
			fr.Flags().Add(FlagAck))

		fr.payload = fr.payload[:0]
	} else {
		st.Encode()

		fr.setPayload(st.rawSettings)
	}
}
