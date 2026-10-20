//go:build !openbsd

package quic

const desiredBufferSize = 7 << 20 // 7 MiB
