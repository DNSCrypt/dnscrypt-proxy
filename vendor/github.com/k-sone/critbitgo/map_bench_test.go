package critbitgo_test

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
)

var keyCount int = 10000
var keyLen int = 128

var keys []string
var alphabet string = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
var alphalen int = len(alphabet)

func init() {
	keys = make([]string, keyCount)
	random := rand.New(rand.NewSource(0))
	for i := 0; i < len(keys); i++ {
		keys[i] = genRandomKey(random)
	}
}

func genRandomKey(rand *rand.Rand) string {
	buf := bytes.NewBufferString("")
	for i := 0; i < keyLen; i++ {
		buf.WriteByte(alphabet[rand.Intn(alphalen)])
	}
	return buf.String()
}

func buildMap(keys []string) map[string]string {
	m := make(map[string]string)
	for _, key := range keys {
		m[key] = key
	}
	return m
}

func BenchmarkMapBuild(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buildMap(keys)
	}
}

func BenchmarkSortedMapBuild(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buildSortedMap(keys)
	}
}

func BenchmarkMapGet(b *testing.B) {
	m := buildMap(keys)
	random := rand.New(rand.NewSource(0))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		k := keys[random.Intn(keyCount)]
		_ = m[k]
	}
}

func BenchmarkSortedMapGet(b *testing.B) {
	m := buildSortedMap(keys)
	random := rand.New(rand.NewSource(0))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		k := keys[random.Intn(keyCount)]
		_, _ = m.Get(k)
	}
}

func BenchmarkMapDelete(b *testing.B) {
	m := buildMap(keys)
	random := rand.New(rand.NewSource(0))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		k := keys[random.Intn(keyCount)]
		if _, ok := m[k]; ok {
			delete(m, k)
		}
	}
}

func BenchmarkSortedMapDelete(b *testing.B) {
	m := buildSortedMap(keys)
	random := rand.New(rand.NewSource(0))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		k := keys[random.Intn(keyCount)]
		m.Delete(k)
	}
}

func BenchmarkMapKeys(b *testing.B) {
	m := buildMap(keys)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		list := make([]string, 0, len(m))
		for _, k := range m {
			list = append(list, k)
		}
		sort.Strings(list)
	}
}

func BenchmarkSortedMapKeys(b *testing.B) {
	m := buildSortedMap(keys)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.Keys()
	}
}
