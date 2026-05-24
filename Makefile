GO          = go
GOFLAGS     =
LDFLAGS     = -s -w
TAGS        =
PKG         = ./...
SRCDIR      = dnscrypt-proxy
BIN         = dnscrypt-proxy
PREFIX      = /usr/local
BINDIR      = $(PREFIX)/bin
INSTALL     = install

.PHONY: all build install uninstall test test-short test-race test-suite \
        bench fmt vet tidy vendor staticcheck lint clean distclean run \
        version help

all: build

help:
	@echo "Available targets:"
	@echo "  build         Build the $(BIN) binary"
	@echo "  install       Install $(BIN) to \$$PREFIX/bin (default /usr/local/bin)"
	@echo "  uninstall     Remove the installed binary"
	@echo "  test          Run the full test suite"
	@echo "  test-short    Run tests with -short"
	@echo "  test-race     Run tests with the race detector"
	@echo "  test-suite    Run the categorized test script (run_tests.sh)"
	@echo "  bench         Run benchmarks"
	@echo "  fmt           Format the code with gofmt"
	@echo "  vet           Run go vet"
	@echo "  staticcheck   Run staticcheck (must be installed)"
	@echo "  lint          Run fmt, vet and staticcheck"
	@echo "  tidy          Run go mod tidy"
	@echo "  vendor        Refresh the vendor directory"
	@echo "  run           Build and run the binary in place"
	@echo "  version       Print the application version"
	@echo "  clean         Remove build artifacts"
	@echo "  distclean     clean + remove the vendor directory"

build:
	cd $(SRCDIR) && $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -tags "$(TAGS)" -o $(BIN) .

install: build
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(SRCDIR)/$(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)

test:
	cd $(SRCDIR) && $(GO) test $(GOFLAGS) -tags "$(TAGS)" $(PKG)

test-short:
	cd $(SRCDIR) && $(GO) test $(GOFLAGS) -short -tags "$(TAGS)" $(PKG)

test-race:
	cd $(SRCDIR) && $(GO) test $(GOFLAGS) -race -tags "$(TAGS)" $(PKG)

test-suite:
	cd $(SRCDIR) && sh ./run_tests.sh

bench:
	cd $(SRCDIR) && $(GO) test $(GOFLAGS) -run=^$$ -bench=. -benchmem $(PKG)

fmt:
	$(GO) fmt ./...

vet:
	cd $(SRCDIR) && $(GO) vet $(PKG)

staticcheck:
	cd $(SRCDIR) && staticcheck $(PKG)

lint: fmt vet staticcheck

tidy:
	$(GO) mod tidy

vendor:
	$(GO) mod vendor

run: build
	cd $(SRCDIR) && ./$(BIN)

version: build
	@$(SRCDIR)/$(BIN) -version

clean:
	rm -f $(SRCDIR)/$(BIN)
	cd $(SRCDIR) && $(GO) clean $(PKG)

distclean: clean
	rm -rf vendor
