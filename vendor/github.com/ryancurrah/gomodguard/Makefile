current_dir = $(shell pwd)

.PHONEY: lint
lint:
	golangci-lint run ./...

.PHONEY: build
build:
	go build -o gomodguard cmd/gomodguard/main.go

.PHONEY: run
run: build
	./gomodguard

.PHONEY: test
test:
	go test -v -coverprofile coverage.out 

.PHONEY: cover
cover:
	gocover-cobertura < coverage.out > coverage.xml

.PHONEY: dockerrun
dockerrun: dockerbuild
	docker run -v "${current_dir}/.gomodguard.yaml:/.gomodguard.yaml" ryancurrah/gomodguard:latest

.PHONEY: release
release:
	goreleaser --rm-dist

.PHONEY: clean
clean:
	rm -rf dist/
	rm -f gomodguard coverage.xml coverage.out

.PHONEY: install-tools-mac
install-tools-mac:
	brew install goreleaser/tap/goreleaser

.PHONEY: install-go-tools
install-go-tools:
	go get github.com/t-yuki/gocover-cobertura
