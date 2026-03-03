package http2

import (
	"sync"
)

// HeaderField represents a field in HPACK tables.
//
// Use AcquireHeaderField to acquire HeaderField.
type HeaderField struct {
	key, value []byte
	sensible   bool
}

// String returns a string representation of the header field.
func (hf *HeaderField) String() string {
	return string(hf.AppendBytes(nil))
}

var headerPool = sync.Pool{
	New: func() interface{} {
		return &HeaderField{}
	},
}

// AcquireHeaderField gets HeaderField from the pool.
func AcquireHeaderField() *HeaderField {
	return headerPool.Get().(*HeaderField)
}

// ReleaseHeaderField puts HeaderField to the pool.
func ReleaseHeaderField(hf *HeaderField) {
	hf.Reset()
	headerPool.Put(hf)
}

// Empty returns true if `hf` doesn't contain any key nor value.
func (hf *HeaderField) Empty() bool {
	return len(hf.key) == 0 && len(hf.value) == 0
}

// Reset resets header field values.
func (hf *HeaderField) Reset() {
	hf.key = hf.key[:0]
	hf.value = hf.value[:0]
	hf.sensible = false
}

// AppendBytes appends header representation of hf to dst and returns the new dst.
func (hf *HeaderField) AppendBytes(dst []byte) []byte {
	dst = append(dst, hf.key...)
	dst = append(dst, ':', ' ')
	dst = append(dst, hf.value...)
	return dst
}

// Size returns the header field size as RFC specifies.
//
// https://tools.ietf.org/html/rfc7541#section-4.1
func (hf *HeaderField) Size() uint32 {
	return uint32(len(hf.key) + len(hf.value) + 32)
}

// CopyTo copies the HeaderField to `other`.
func (hf *HeaderField) CopyTo(other *HeaderField) {
	other.key = append(other.key[:0], hf.key...)
	other.value = append(other.value[:0], hf.value...)
	other.sensible = hf.sensible
}

func (hf *HeaderField) Set(k, v string) {
	hf.SetKey(k)
	hf.SetValue(v)
}

func (hf *HeaderField) SetBytes(k, v []byte) {
	hf.SetKeyBytes(k)
	hf.SetValueBytes(v)
}

// Key returns the key of the field.
func (hf *HeaderField) Key() string {
	return string(hf.key)
}

// Value returns the value of the field.
func (hf *HeaderField) Value() string {
	return string(hf.value)
}

// KeyBytes returns the key bytes of the field.
func (hf *HeaderField) KeyBytes() []byte {
	return hf.key
}

// ValueBytes returns the value bytes of the field.
func (hf *HeaderField) ValueBytes() []byte {
	return hf.value
}

// SetKey sets key to the field.
func (hf *HeaderField) SetKey(key string) {
	hf.key = append(hf.key[:0], key...)
}

// SetValue sets value to the field.
func (hf *HeaderField) SetValue(value string) {
	hf.value = append(hf.value[:0], value...)
}

// SetKeyBytes sets key to the field.
func (hf *HeaderField) SetKeyBytes(key []byte) {
	hf.key = append(hf.key[:0], key...)
}

// SetValueBytes sets value to the field.
func (hf *HeaderField) SetValueBytes(value []byte) {
	hf.value = append(hf.value[:0], value...)
}

// IsPseudo returns true if field is pseudo header.
func (hf *HeaderField) IsPseudo() bool {
	return len(hf.key) > 0 && hf.key[0] == ':'
}

// IsSensible returns if header field have been marked as sensible.
func (hf *HeaderField) IsSensible() bool {
	return hf.sensible
}
