#!/bin/bash

set -euo pipefail

echo "Build date (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

go version
go env

# fuzz qpack
cd $GOPATH/src/github.com/quic-go/qpack
git log -1 --format='qpack revision: %H (%cI) %s'
compile_native_go_fuzzer_v2 github.com/quic-go/qpack FuzzDecode qpack_decode_fuzzer

# fuzz quic-go
cd $GOPATH/src/github.com/quic-go/quic-go/
git log -1 --format='quic-go revision: %H (%cI) %s'

build_native_go_fuzzer() {
	local pkg=$1
	local fuzz=$2
	local name=$3
	local corpus_dir="${WORK:-/tmp}/quic-go-seed-corpus/$name"
	local corpus_zip="$OUT/${name}_seed_corpus.zip"

	# FUZZ_CORPUS_DIR makes go-ossfuzz-seeds write each f.Add seed as a raw
	# libFuzzer corpus file. OSS-Fuzz picks up <fuzzer>_seed_corpus.zip from
	# $OUT and unpacks it next to the fuzzer binary.
	rm -rf "$corpus_dir"
	mkdir -p "$corpus_dir"
	FUZZ_CORPUS_DIR="$corpus_dir" go test "$pkg" -run "^${fuzz}$" -count=1 -v

	rm -f "$corpus_zip"
	corpus_files=$(find "$corpus_dir" -type f | wc -l)
	echo "$name: generated $corpus_files corpus files"
	if [[ "$corpus_files" -gt 0 ]]; then
		(cd "$corpus_dir" && zip -q -r "$corpus_zip" .)
	fi

	compile_native_go_fuzzer_v2 "$pkg" "$fuzz" "$name"
}

build_native_go_fuzzer github.com/quic-go/quic-go/internal/wire FuzzFrames frame_fuzzer_v2
build_native_go_fuzzer github.com/quic-go/quic-go/internal/wire FuzzTransportParameters transportparameter_fuzzer_v2
build_native_go_fuzzer github.com/quic-go/quic-go/http3 FuzzFrameParser http3_frame_fuzzer
build_native_go_fuzzer github.com/quic-go/quic-go/internal/wire FuzzHeaderParser header_fuzzer_v2
build_native_go_fuzzer github.com/quic-go/quic-go/internal/handshake FuzzHandshake handshake_fuzzer_v2
build_native_go_fuzzer github.com/quic-go/quic-go FuzzFrameSorter frame_sorter_fuzzer
build_native_go_fuzzer github.com/quic-go/quic-go/http3 FuzzHeaderParsing http3_header_parsing_fuzzer

# for debugging
ls -al $OUT
