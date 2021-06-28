current_dir = $(shell pwd)
version = $(shell printf '%s' $$(cat VERSION))

.PHONEY: lint
lint:
	golangci-lint run ./...

.PHONEY: build
build:
	go build -o gomodguard cmd/gomodguard/main.go

.PHONEY: dockerbuild
dockerbuild:
	docker build --build-arg GOMODGUARD_VERSION=${version} --tag ryancurrah/gomodguard:${version} .
 
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
	git tag ${version}
	git push --tags
	goreleaser --skip-validate --rm-dist

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
