package reverse

// Map reverses a uint8 or uint16 map.
func Map[K uint8 | uint16](m map[K]string) map[string]K {
	n := make(map[string]K, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}
