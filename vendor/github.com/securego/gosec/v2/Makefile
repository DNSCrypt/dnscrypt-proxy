GIT_TAG?= $(shell git describe --always --tags)
BIN = gosec
FMT_CMD = $(gofmt -s -l -w $(find . -type f -name '*.go' -not -path './vendor/*') | tee /dev/stderr)
IMAGE_REPO = securego
BUILDFLAGS := '-w -s'
CGO_ENABLED = 0
GO := GO111MODULE=on go
GO_NOMOD :=GO111MODULE=off go
GOPATH ?= $(shell $(GO) env GOPATH)
GOBIN ?= $(GOPATH)/bin
GOLINT ?= $(GOBIN)/golint
GOSEC ?= $(GOBIN)/gosec
GINKGO ?= $(GOBIN)/ginkgo
GO_VERSION = 1.15

default:
	$(MAKE) build

install-test-deps:
	$(GO_NOMOD) get -u github.com/onsi/ginkgo/ginkgo
	$(GO_NOMOD) get -u golang.org/x/crypto/ssh
	$(GO_NOMOD) get -u github.com/lib/pq

test: install-test-deps build fmt lint sec
	$(GINKGO) -r -v

fmt:
	@echo "FORMATTING"
	@FORMATTED=`$(GO) fmt ./...`
	@([[ ! -z "$(FORMATTED)" ]] && printf "Fixed unformatted files:\n$(FORMATTED)") || true

lint:
	@echo "LINTING"
	$(GO_NOMOD) get -u golang.org/x/lint/golint
	$(GOLINT) -set_exit_status ./...
	@echo "VETTING"
	$(GO) vet ./...

sec:
	@echo "SECURITY SCANNING"
	./$(BIN) ./...

test-coverage: install-test-deps
	go test -race -coverprofile=coverage.txt -covermode=atomic

build:
	go build -o $(BIN) ./cmd/gosec/

clean:
	rm -rf build vendor dist coverage.txt
	rm -f release image $(BIN)

release:
	@echo "Releasing the gosec binary..."
	goreleaser release

build-linux:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 go build -ldflags $(BUILDFLAGS) -o $(BIN) ./cmd/gosec/

image:
	@echo "Building the Docker image..."
	docker build -t $(IMAGE_REPO)/$(BIN):$(GIT_TAG) --build-arg GO_VERSION=$(GO_VERSION) .
	docker tag $(IMAGE_REPO)/$(BIN):$(GIT_TAG) $(IMAGE_REPO)/$(BIN):latest
	touch image

image-push: image
	@echo "Pushing the Docker image..."
	docker push $(IMAGE_REPO)/$(BIN):$(GIT_TAG)
	docker push $(IMAGE_REPO)/$(BIN):latest

.PHONY: test build clean release image image-push
