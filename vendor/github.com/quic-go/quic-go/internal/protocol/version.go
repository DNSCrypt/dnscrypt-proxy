package protocol

import (
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"time"

	"golang.org/x/exp/rand"
)

// Version is a version number as int
type Version uint32

// gQUIC version range as defined in the wiki: https://github.com/quicwg/base-drafts/wiki/QUIC-Versions
const (
	gquicVersion0   = 0x51303030
	maxGquicVersion = 0x51303439
)

// The version numbers, making grepping easier
const (
	VersionUnknown Version = math.MaxUint32
	versionDraft29 Version = 0xff00001d // draft-29 used to be a widely deployed version
	Version1       Version = 0x1
	Version2       Version = 0x6b3343cf
)

// SupportedVersions lists the versions that the server supports
// must be in sorted descending order
var SupportedVersions = []Version{Version1, Version2}

// IsValidVersion says if the version is known to quic-go
func IsValidVersion(v Version) bool {
	return v == Version1 || IsSupportedVersion(SupportedVersions, v)
}

func (vn Version) String() string {
	//nolint:exhaustive
	switch vn {
	case VersionUnknown:
		return "unknown"
	case versionDraft29:
		return "draft-29"
	case Version1:
		return "v1"
	case Version2:
		return "v2"
	default:
		if vn.isGQUIC() {
			return fmt.Sprintf("gQUIC %d", vn.toGQUICVersion())
		}
		return fmt.Sprintf("%#x", uint32(vn))
	}
}

func (vn Version) isGQUIC() bool {
	return vn > gquicVersion0 && vn <= maxGquicVersion
}

func (vn Version) toGQUICVersion() int {
	return int(10*(vn-gquicVersion0)/0x100) + int(vn%0x10)
}

// IsSupportedVersion returns true if the server supports this version
func IsSupportedVersion(supported []Version, v Version) bool {
	for _, t := range supported {
		if t == v {
			return true
		}
	}
	return false
}

// ChooseSupportedVersion finds the best version in the overlap of ours and theirs
// ours is a slice of versions that we support, sorted by our preference (descending)
// theirs is a slice of versions offered by the peer. The order does not matter.
// The bool returned indicates if a matching version was found.
func ChooseSupportedVersion(ours, theirs []Version) (Version, bool) {
	for _, ourVer := range ours {
		for _, theirVer := range theirs {
			if ourVer == theirVer {
				return ourVer, true
			}
		}
	}
	return 0, false
}

var (
	versionNegotiationMx   sync.Mutex
	versionNegotiationRand = rand.New(rand.NewSource(uint64(time.Now().UnixNano())))
)

// generateReservedVersion generates a reserved version (v & 0x0f0f0f0f == 0x0a0a0a0a)
func generateReservedVersion() Version {
	var b [4]byte
	_, _ = versionNegotiationRand.Read(b[:]) // ignore the error here. Failure to read random data doesn't break anything
	return Version((binary.BigEndian.Uint32(b[:]) | 0x0a0a0a0a) & 0xfafafafa)
}

// GetGreasedVersions adds one reserved version number to a slice of version numbers, at a random position.
// It doesn't modify the supported slice.
func GetGreasedVersions(supported []Version) []Version {
	versionNegotiationMx.Lock()
	defer versionNegotiationMx.Unlock()
	randPos := rand.Intn(len(supported) + 1)
	greased := make([]Version, len(supported)+1)
	copy(greased, supported[:randPos])
	greased[randPos] = generateReservedVersion()
	copy(greased[randPos+1:], supported[randPos:])
	return greased
}
