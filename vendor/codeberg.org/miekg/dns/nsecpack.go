package dns

import (
	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

func unpackNSEC(s *cryptobyte.String) ([]uint16, error) {
	var nsec []uint16
	lastwindow := -1
	for !s.Empty() {
		var (
			window byte
			bits   cryptobyte.String
		)
		if !s.ReadUint8(&window) ||
			!s.ReadUint8LengthPrefixed(&bits) {
			return nsec, unpack.ErrOverflow
		}
		if int(window) <= lastwindow {
			// RFC 4034: Blocks are present in the NSEC RR RDATA in
			// increasing numerical order.
			return nsec, &unpack.Error{Err: "out of order NSEC(3) BLock in type bitmap"}
		}
		if len(bits) == 0 {
			// RFC 4034: Blocks with no types present MUST NOT be included.
			return nsec, &unpack.Error{Err: "empty NSEC(3) block in type bitmap"}
		}
		if len(bits) > 32 {
			return nsec, &unpack.Error{Err: "NSEC(3) block too long in type bitmap"}
		}

		// Walk the bytes in the window and extract the type bits
		for i, b := range bits {
			for n := range uint(8) {
				if b&(1<<(7-n)) != 0 {
					nsec = append(nsec, uint16(int(window)*256+i*8+int(n)))
				}
			}
		}

		lastwindow = int(window)
	}
	return nsec, nil
}

// typeBitMapLen is a helper function which computes the "maximum" length of
// a the NSEC Type BitMap field.
func typeBitMapLen(bitmap []uint16) int {
	var l int
	var lastwindow, lastlength uint16
	for _, t := range bitmap {
		window := t / 256
		length := (t-window*256)/8 + 1
		if window > lastwindow && lastlength != 0 { // New window, jump to the new off
			l += int(lastlength) + 2
			lastlength = 0
		}
		if window < lastwindow || length < lastlength {
			// packNsec would return Error{err: "nsec bits out of order"} here, but
			// when computing the length, we want do be liberal.
			continue
		}
		lastwindow, lastlength = window, length
	}
	l += int(lastlength) + 2
	return l
}

func packNSEC(bitmap []uint16, msg []byte, off int) (int, error) {
	if len(bitmap) == 0 {
		return off, nil
	}
	if off > len(msg) {
		return off, &pack.Error{Err: "overflow NSEC(3)"}
	}
	toZero := msg[off:]
	if maxLen := typeBitMapLen(bitmap); maxLen < len(toZero) {
		toZero = toZero[:maxLen]
	}
	for i := range toZero {
		toZero[i] = 0
	}
	var lastwindow, lastlength uint16
	for _, t := range bitmap {
		window := t / 256
		length := (t-window*256)/8 + 1
		if window > lastwindow && lastlength != 0 { // New window, jump to the new off
			off += int(lastlength) + 2
			lastlength = 0
		}
		if window < lastwindow || length < lastlength {
			return len(msg), &pack.Error{Err: "NSEC(3) bits out of order"}
		}
		if off+2+int(length) > len(msg) {
			return len(msg), &pack.Error{Err: "overflow NSEC(3)"}
		}
		// Setting the window #
		msg[off] = byte(window)
		// Setting the octets length
		msg[off+1] = byte(length)
		// Setting the bit value for the type in the right octet
		msg[off+1+int(length)] |= byte(1 << (7 - t%8))
		lastwindow, lastlength = window, length
	}
	off += int(lastlength) + 2
	return off, nil
}
