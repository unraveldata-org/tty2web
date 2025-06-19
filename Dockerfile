FROM golang:1.24 AS builder
ARG TARGETARCH
COPY . /go/src/github.com/unravel-data/tty2web
WORKDIR /go/src/github.com/unravel-data/tty2web
RUN go build -o /go/bin/tty2web -v -trimpath -ldflags "-w -s" .

FROM rockylinux/rockylinux:10

ARG TARGETARCH

LABEL org.opencontainers.image.vendor="Unravel Data, Inc." \
      org.opencontainers.image.authors="Unravel Data, Inc." \
      org.opencontainers.image.title="tty2web"

COPY --from=builder /go/bin/tty2web /usr/local/bin/tty2web

ENV TERM=xterm-256color

RUN dnf install -y nano procps-ng \
    && dnf clean all \
    && rm -rf /var/cache/dnf/*

RUN groupadd unravel && useradd -u 1000 -m -s /bin/bash -g unravel unravel
RUN groupadd hadoop && useradd -u 1001 -m -s /bin/bash -g hadoop hadoop
RUN groupadd hdfs && useradd -u 1002 -m -s /bin/bash -g hdfs hdfs

USER unravel

ENTRYPOINT ["tty2web"]