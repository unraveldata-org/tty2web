FROM golang:1.24 AS builder
ARG TARGETARCH
COPY . /go/src/github.com/unravel-data/tty2web
WORKDIR /go/src/github.com/unravel-data/tty2web
RUN go build -o /go/bin/tty2web -v -trimpath -ldflags "-w -s" .

FROM ubuntu:latest

ARG TARGETARCH

LABEL org.opencontainers.image.vendor="Unravel Data, Inc." \
      org.opencontainers.image.authors="Unravel Data, Inc." \
      org.opencontainers.image.title="tty2web"

COPY --from=builder /go/bin/tty2web /usr/local/bin/tty2web
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["tty2web"]