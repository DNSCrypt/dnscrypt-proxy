package http2

import (
	"strconv"
	"sync"
)

type FrameType int8

func (ft FrameType) String() string {
	switch ft {
	case FrameData:
		return "FrameData"
	case FrameHeaders:
		return "FrameHeaders"
	case FramePriority:
		return "FramePriority"
	case FrameResetStream:
		return "FrameResetStream"
	case FrameSettings:
		return "FrameSettings"
	case FramePushPromise:
		return "FramePushPromise"
	case FramePing:
		return "FramePing"
	case FrameGoAway:
		return "FrameGoAway"
	case FrameWindowUpdate:
		return "FrameWindowUpdate"
	case FrameContinuation:
		return "FrameContinuation"
	}

	return strconv.Itoa(int(ft))
}

type FrameFlags int8

// Has returns if `f` is in the frame flags or not.
func (flags FrameFlags) Has(f FrameFlags) bool {
	return flags&f == f
}

// Add adds a flag to frame flags.
func (flags FrameFlags) Add(f FrameFlags) FrameFlags {
	return flags | f
}

// Del deletes f from frame flags.
func (flags FrameFlags) Del(f FrameFlags) FrameFlags {
	return flags ^ f
}

type Frame interface {
	Type() FrameType
	Reset()

	Serialize(*FrameHeader)
	Deserialize(*FrameHeader) error
}

var framePools = func() [FrameContinuation + 1]*sync.Pool {
	var pools [FrameContinuation + 1]*sync.Pool

	pools[FrameData] = &sync.Pool{
		New: func() interface{} {
			return &Data{}
		},
	}
	pools[FrameHeaders] = &sync.Pool{
		New: func() interface{} {
			return &Headers{}
		},
	}
	pools[FramePriority] = &sync.Pool{
		New: func() interface{} {
			return &Priority{}
		},
	}
	pools[FrameResetStream] = &sync.Pool{
		New: func() interface{} {
			return &RstStream{}
		},
	}
	pools[FrameSettings] = &sync.Pool{
		New: func() interface{} {
			return &Settings{}
		},
	}
	pools[FramePushPromise] = &sync.Pool{
		New: func() interface{} {
			return &PushPromise{}
		},
	}
	pools[FramePing] = &sync.Pool{
		New: func() interface{} {
			return &Ping{}
		},
	}
	pools[FrameGoAway] = &sync.Pool{
		New: func() interface{} {
			return &GoAway{}
		},
	}
	pools[FrameWindowUpdate] = &sync.Pool{
		New: func() interface{} {
			return &WindowUpdate{}
		},
	}
	pools[FrameContinuation] = &sync.Pool{
		New: func() interface{} {
			return &Continuation{}
		},
	}

	return pools
}()

func AcquireFrame(ftype FrameType) Frame {
	fr := framePools[ftype].Get().(Frame)
	fr.Reset()

	return fr
}

func ReleaseFrame(fr Frame) {
	framePools[fr.Type()].Put(fr)
}
