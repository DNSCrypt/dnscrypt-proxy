#!/bin/bash

set -euo pipefail

echo "Build date (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# Select the toolchain from quic-go's go.mod and build its fuzzers.
cd "$GOPATH/src/github.com/quic-go/quic-go"
git log -1 --format='quic-go revision: %H (%cI) %s'
source .clusterfuzzlite/build.sh

# fuzz qpack
cd "$GOPATH/src/github.com/quic-go/qpack"
git log -1 --format='qpack revision: %H (%cI) %s'
compile_native_go_fuzzer_v2 github.com/quic-go/qpack FuzzDecode qpack_decode_fuzzer

# for debugging
ls -al "$OUT"
