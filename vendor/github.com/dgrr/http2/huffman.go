package http2

import (
	"errors"
	"fmt"
)

// HuffmanEncode encodes src into dst using Huffman algorithm.
//
// src and dst must not point to the same address.
func HuffmanEncode(dst, src []byte) []byte {
	var code uint64
	var length uint8
	// TODO: I'd be nice to implement this lookup using SSE.
	// But since you need to use the Golang's ASM I don't know
	// how much will that take.
	for _, b := range src {
		n := huffmanCodeLen[b]
		c := uint64(huffmanCodes[b])
		length += n
		code = code<<n | c
		for length >= 8 {
			length -= 8
			dst = append(dst, byte(code>>length))
		}
	}

	if length > 0 {
		n := 8 - length
		code = code<<n | (1<<n - 1)
		dst = append(dst, byte(code))
	}

	return dst
}

// HuffmanDecode decodes src into dst using Huffman codes.
//
// src and dst must not point to the same address.
func HuffmanDecode(dst, src []byte) ([]byte, error) {
	var accBits uint32
	var bits uint8
	var bitsLeft uint8

	root := rootHuffmanNode
	for _, b := range src {
		// accumulate bits until having more than or equal to 8
		accBits = accBits<<8 | uint32(b)
		bits += 8
		bitsLeft += 8

		for bits >= 8 {
			// take the bits that were added first
			idx := byte(accBits >> (bits - 8))

			root = root.sub[idx]
			if root == nil {
				return nil, fmt.Errorf("invalid huffman index: %x", idx)
			}

			// if we have more to read, then just continue
			if root.sub != nil {
				bits -= 8
			} else {
				bits -= root.codeLen
				dst = append(dst, root.sym)
				root = rootHuffmanNode
				bitsLeft = bits
			}

			// not needed:
			// accBits &= 1<<bits - 1
		}
	}

	// if we have bits left
	for bits > 0 {
		// as the last byte can contain some padding, we need to remove the padding
		// by just shifting 8 - bits
		idx := byte(accBits << (8 - bits))

		root = root.sub[idx]
		if root == nil {
			return nil, fmt.Errorf("invalid huffman index: %x", idx)
		}

		if root.sub != nil || root.codeLen > bits {
			break
		}

		dst = append(dst, root.sym)
		bits -= root.codeLen
		root = rootHuffmanNode
		bitsLeft = bits
	}

	if bitsLeft > 7 {
		return nil, errors.New("bits left decoding huffman bytes")
	}

	if mask := uint32(1<<bits - 1); accBits&mask != mask {
		return nil, errors.New("bits has a zero prefix")
	}

	return dst, nil
}

var rootHuffmanNode = func() *huffmanNode {
	node := &huffmanNode{
		sub: make([]*huffmanNode, 256),
	}

	for i, code := range huffmanCodes {
		node.add(byte(i), code, huffmanCodeLen[i])
	}

	return node
}()

type huffmanNode struct {
	sub     []*huffmanNode
	codeLen uint8
	sym     byte
}

// This function is going to create a list of tables of 256 elements.
//
// If an element in the Huffman table takes more than 8 bits it'll be stored
// in the `sub` table recursively, that means, if an element is 18 bits long,
// 3 tables will be needed, the main table, a sub table and a sub-sub table.
func (node *huffmanNode) add(sym byte, code uint32, length uint8) {
	// if length is more than 8, then we need to recursively look for the table
	// where we are going to insert the element.
	for length > 8 {
		length -= 8
		i := uint8(code >> length)
		if node.sub[i] == nil {
			node.sub[i] = &huffmanNode{
				sub: make([]*huffmanNode, 256),
			}
		}

		node = node.sub[i]
	}

	n := 8 - length
	// use a range to fill 8 bits because later we are going to index based on 8 bit index numbers.
	start, end := int(uint8(code<<n)), 1<<n

	for i := start; i < start+end; i++ {
		node.sub[i] = &huffmanNode{sym: sym, codeLen: length}
	}
}

// huffmanCodes has been copied from https://github.com/golang/net/blob/master/http2/hpack/tables.go#L203
var huffmanCodes = [256]uint32{
	0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3,
	0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
	0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9,
	0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
	0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0,
	0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
	0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7,
	0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
	0x14, 0x3f8, 0x3f9, 0xffa,
	0x1ff9, 0x15, 0xf8, 0x7fa,
	0x3fa, 0x3fb, 0xf9, 0x7fb,
	0xfa, 0x16, 0x17, 0x18,
	0x0, 0x1, 0x2, 0x19,
	0x1a, 0x1b, 0x1c, 0x1d,
	0x1e, 0x1f, 0x5c, 0xfb,
	0x7ffc, 0x20, 0xffb, 0x3fc,
	0x1ffa, 0x21, 0x5d, 0x5e,
	0x5f, 0x60, 0x61, 0x62,
	0x63, 0x64, 0x65, 0x66,
	0x67, 0x68, 0x69, 0x6a,
	0x6b, 0x6c, 0x6d, 0x6e,
	0x6f, 0x70, 0x71, 0x72,
	0xfc, 0x73, 0xfd, 0x1ffb,
	0x7fff0, 0x1ffc, 0x3ffc, 0x22,
	0x7ffd, 0x3, 0x23, 0x4,
	0x24, 0x5, 0x25, 0x26,
	0x27, 0x6, 0x74, 0x75,
	0x28, 0x29, 0x2a, 0x7,
	0x2b, 0x76, 0x2c, 0x8,
	0x9, 0x2d, 0x77, 0x78,
	0x79, 0x7a, 0x7b, 0x7ffe,
	0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
	0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8,
	0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
	0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc,
	0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
	0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0,
	0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
	0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5,
	0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
	0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb,
	0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
	0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0,
	0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
	0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2,
	0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
	0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4,
	0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
	0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1,
	0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
	0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde,
	0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
	0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0,
	0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
	0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9,
	0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
	0xfffec, 0xfffff3, 0xfffed, 0x1fffe6,
	0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
	0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef,
	0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
	0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed,
	0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
	0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed,
	0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
}

var huffmanCodeLen = [256]uint8{
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
}
