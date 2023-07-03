//go:build gomock || generate

package http3

//go:generate sh -c "go run github.com/golang/mock/mockgen -build_flags=\"-tags=gomock\"  -package http3 -destination mock_roundtripcloser_test.go github.com/quic-go/quic-go/http3 RoundTripCloser"
type RoundTripCloser = roundTripCloser

//go:generate sh -c "go run github.com/golang/mock/mockgen -package http3 -destination mock_quic_early_listener_test.go github.com/quic-go/quic-go/http3 QUICEarlyListener"
