package critbitgo_test

import (
	"strings"
	"testing"

	"github.com/k-sone/critbitgo"
)

func buildSortedMap(keys []string) *critbitgo.SortedMap {
	m := critbitgo.NewSortedMap()
	for _, key := range keys {
		m.Set(key, key)
	}
	return m
}

func TestSortedMapContains(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	m := buildSortedMap(keys)

	for _, key := range keys {
		if !m.Contains(key) {
			t.Error("Contains() - not found - [%s]", key)
		}
	}

	if m.Contains("aaa") {
		t.Error("Contains() - phantom found")
	}
}

func TestSortedMapGet(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	m := buildSortedMap(keys)

	for _, key := range keys {
		if value, ok := m.Get(key); !ok || value != key {
			t.Error("Get() - not found - [%s]", key)
		}
	}

	if value, ok := m.Get("aaa"); ok || value != nil {
		t.Error("Get() - phantom found")
	}
}

func TestSortedMapDelete(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	m := buildSortedMap(keys)

	for i, key := range keys {
		if !m.Contains(key) {
			t.Error("Delete() - not exists - [%s]", key)
		}
		if value, ok := m.Delete(key); !ok || value != key {
			t.Error("Delete() - failed - [%s]", key)
		}
		if m.Contains(key) {
			t.Error("Delete() - exists - [%s]", key)
		}
		if value, ok := m.Delete(key); ok || value != nil {
			t.Error("Delete() - phantom found - [%s]", key)
		}
		if i != len(keys) {
			for _, key2 := range keys[i+1:] {
				if !m.Contains(key2) {
					t.Errorf("Delete() - other not exists - [%s](%s)", key2, key)
				}
			}
		}
	}
}

func TestSortedMapSize(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	m := buildSortedMap(keys)
	klen := len(keys)
	if s := m.Size(); s != klen {
		t.Errorf("Size() - expected [%s], actual [%s]", klen, s)
	}

	for i, key := range keys {
		m.Delete(key)
		if s := m.Size(); s != klen-(i+1) {
			t.Errorf("Size() - expected [%s], actual [%s]", klen, s)
		}
	}
}

func TestSortedMapKeys(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	m := buildSortedMap(keys)
	skeys := m.Keys()
	for _, key := range keys {
		match := false
		for _, skey := range skeys {
			if key == skey {
				match = true
				break
			}
		}
		if !match {
			t.Errorf("Keys() - not found [%s]", key)
		}
	}
}

func TestSortedMapEach(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	m := buildSortedMap(keys)

	elems := make(map[string]interface{})
	handle := func(key string, value interface{}) bool {
		elems[key] = value
		return true
	}
	if !m.Each("", handle) {
		t.Error("Each() - invalid result")
	}
	for _, key := range keys {
		if _, ok := elems[key]; !ok {
			t.Errorf("Each() - not found [%s]", key)
		} else if value, ok := elems[key].(string); !ok || value != key {
			t.Errorf("Each() - invalid value [%s](%s)", value, key)
		}
	}

	elems = make(map[string]interface{})
	handle = func(key string, value interface{}) bool {
		elems[key] = value
		return true
	}
	if !m.Each("b", handle) {
		t.Error("Each() - invalid result")
	}
	for _, key := range keys {
		if strings.Index(key, "b") == 0 {
			if _, ok := elems[key]; !ok {
				t.Errorf("Each() - not found [%s]", key)
			} else if value, ok := elems[key].(string); !ok || value != key {
				t.Errorf("Each() - invalid value [%s](%s)", value, key)
			}
		} else {
			if _, ok := elems[key]; ok {
				t.Errorf("Each() - phantom found [%s]", key)
			}
		}
	}

	elems = make(map[string]interface{})
	handle = func(key string, value interface{}) bool {
		elems[key] = value
		return true
	}
	if !m.Each("c", handle) {
		t.Error("Each() - invalid result")
	}
	for _, key := range keys {
		if _, ok := elems[key]; ok {
			t.Errorf("Each() - phantom found [%s]", key)
		}
	}
}
