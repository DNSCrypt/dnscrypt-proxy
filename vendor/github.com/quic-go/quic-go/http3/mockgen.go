//go:build gomock || generate

package http3

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\"  -package http3 -destination mock_singleroundtripper_test.go github.com/quic-go/quic-go/http3 SingleRoundTripper"
type SingleRoundTripper = singleRoundTripper

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -package http3 -destination mock_quic_early_listener_test.go github.com/quic-go/quic-go/http3 QUICEarlyListener"
