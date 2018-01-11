package xsecretbox

import (
	"bytes"
	"testing"
)

func TestSecretbox(t *testing.T) {
	key := [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	nonce := [24]byte{23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	src := []byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42}

	dst := Seal(nil, nonce[:], src[:], key[:])
	dec, err := Open(nil, nonce[:], dst[:], key[:])
	if err != nil || !bytes.Equal(src, dec) {
		t.Errorf("got %x instead of %x", dec, src)
	}

	dst[0]++
	_, err = Open(nil, nonce[:], dst[:], key[:])
	if err == nil {
		t.Errorf("tag validation failed")
	}

	_, _ = SharedKey(key, key)
}
