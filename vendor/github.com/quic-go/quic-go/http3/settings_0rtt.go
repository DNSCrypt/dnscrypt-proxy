package http3

import (
	"bytes"

	"github.com/quic-go/quic-go/quicvarint"
)

const serverSettingsSessionTicketPrefix = "quic-go h3 settings v1"

type settings = settingsFrame

func settingsForSessionTicket(current *settings) []byte {
	return current.Append([]byte(serverSettingsSessionTicketPrefix))
}

func settingsDataFromSessionTicket(extras [][]byte) ([]byte, bool) {
	prefix := []byte(serverSettingsSessionTicketPrefix)
	for _, extra := range extras {
		if data, ok := bytes.CutPrefix(extra, prefix); ok {
			return data, true
		}
	}
	return nil, false
}

func settingsCompatibleFor0RTT(data []byte, current *settings) bool {
	r := bytes.NewReader(data)
	frameType, err := quicvarint.Read(r)
	if err != nil || frameType != 0x4 {
		return false
	}
	length, err := quicvarint.Read(r)
	if err != nil || uint64(r.Len()) != length {
		return false
	}
	old, err := parseSettingsFrame(&countingByteReader{Reader: r}, length, 0, nil)
	if err != nil {
		return false
	}
	// An unknown setting might belong to an extension that this version no longer supports.
	if len(old.Other) > 0 {
		return false
	}

	if current.MaxFieldSectionSize >= 0 && (old.MaxFieldSectionSize < 0 || old.MaxFieldSectionSize > current.MaxFieldSectionSize) {
		return false
	}
	if old.Datagram && !current.Datagram {
		return false
	}
	if old.ExtendedConnect && !current.ExtendedConnect {
		return false
	}
	return true
}
