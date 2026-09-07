//go:build openbsd

package quic

// The OpenBSD kernel rejects socket buffer sizes larger than SB_MAX (2 MB, see sys/sys/socketvar.h)
// instead of clamping them. This limit is not queryable at runtime; changing it requires a custom
// kernel (sb_max is a patchable kernel variable, not a sysctl).
const desiredBufferSize = 2 << 20 // 2 MiB
