//go:build gomock || generate

package http3

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -mock_names=TestClientConnInterface=MockClientConn  -package http3 -destination mock_clientconn_test.go github.com/quic-go/quic-go/http3 TestClientConnInterface"
type TestClientConnInterface = clientConn

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -package http3 -destination mock_quic_early_listener_test.go github.com/quic-go/quic-go/http3 QUICEarlyListener"
