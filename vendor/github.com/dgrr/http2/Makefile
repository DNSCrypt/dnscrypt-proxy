.PHONY: test fmt

test:
	go test -v
	cd h2spec && go test -v

fmt:
	goimports -w .
	gofmt -w -s .
