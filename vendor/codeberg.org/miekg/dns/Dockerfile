ARG BUILD_IMAGE=golang:latest
ARG BASE=alpine:latest

FROM --platform=$BUILDPLATFORM ${BUILD_IMAGE} AS build
RUN mkdir -p /tmp/build
WORKDIR /tmp/build
COPY . .
WORKDIR /tmp/build/cmd/atomdns
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go mod download
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build
RUN cp atomdns /tmp/atomdns

FROM ${BASE}
COPY --from=build /tmp/atomdns /atomdns
WORKDIR /
EXPOSE 53 53/udp 443
ENTRYPOINT ["/atomdns"]
