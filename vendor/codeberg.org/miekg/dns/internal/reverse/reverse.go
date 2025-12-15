package reverse

// Reverse an uint8 map.
func Int8(m map[uint8]string) map[string]uint8 {
	n := make(map[string]uint8, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}

// Reverse an uint16 map.
func Int16(m map[uint16]string) map[string]uint16 {
	n := make(map[string]uint16, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}
