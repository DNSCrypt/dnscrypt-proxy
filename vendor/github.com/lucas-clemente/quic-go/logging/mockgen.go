package logging

//go:generate sh -c "go run github.com/golang/mock/mockgen -package logging -self_package github.com/lucas-clemente/quic-go/logging -destination mock_connection_tracer_test.go github.com/lucas-clemente/quic-go/logging ConnectionTracer"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package logging -self_package github.com/lucas-clemente/quic-go/logging -destination mock_tracer_test.go github.com/lucas-clemente/quic-go/logging Tracer"
