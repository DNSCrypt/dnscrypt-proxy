package revera

// A small open-addressing hash table for the memo records of the capture solver.
// The subset has no map type, so this file spells the table out.
// It uses a power-of-two capacity, linear probing, and growth at 3/4 load.

type memoKey struct {
	a int32
	b int32
	c int32
	d int32
}

type memoVal struct {
	x int32
	y int32
	z int32
}

type memoTab struct {
	keys  []memoKey
	vals  []memoVal
	used  []uint8
	count int
}

func memoHash(k memoKey) uint64 {
	h := uint64(uint32(k.a))*0x9e3779b1 ^ uint64(uint32(k.b))*0x85ebca77
	h ^= uint64(uint32(k.c)) * 0xc2b2ae3d
	h ^= uint64(uint32(k.d)) * 0x27d4eb2f
	h ^= h >> 29
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 32
	return h
}

func memoGet(t *memoTab, k memoKey) (memoVal, bool) {
	var none memoVal
	if len(t.keys) == 0 {
		return none, false
	}
	mask := uint64(len(t.keys) - 1)
	at := memoHash(k) & mask
	for t.used[at] != 0 {
		if t.keys[at] == k {
			return t.vals[at], true
		}
		at = (at + 1) & mask
	}
	return none, false
}

// memoInsert files one pair without growth checks.
func memoInsert(t *memoTab, k memoKey, v memoVal) {
	mask := uint64(len(t.keys) - 1)
	at := memoHash(k) & mask
	for t.used[at] != 0 {
		if t.keys[at] == k {
			t.vals[at] = v
			return
		}
		at = (at + 1) & mask
	}
	t.used[at] = 1
	t.keys[at] = k
	t.vals[at] = v
	t.count++
}

func memoGrow(t *memoTab) {
	oldKeys := t.keys
	oldVals := t.vals
	oldUsed := t.used
	size := 64
	if len(oldKeys) > 0 {
		size = 2 * len(oldKeys)
	}
	t.keys = make([]memoKey, size)
	t.vals = make([]memoVal, size)
	t.used = make([]uint8, size)
	t.count = 0
	for i := 0; i < len(oldKeys); i++ {
		if oldUsed[i] != 0 {
			memoInsert(t, oldKeys[i], oldVals[i])
		}
	}
}

func memoPut(t *memoTab, k memoKey, v memoVal) {
	if 4*(t.count+1) >= 3*len(t.keys) {
		memoGrow(t)
	}
	memoInsert(t, k, v)
}
