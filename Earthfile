VERSION 0.7
FROM golang:1.21-alpine3.17

RUN apk add --update --no-cache \
    bash \
    bash-completion \
    binutils \
    ca-certificates \
    coreutils \
    curl \
    findutils \
    g++ \
    git \
    grep \
    less \
    make \
    openssl \
    util-linux

WORKDIR /identity

# deps downloads and caches all dependencies for earthly. When called directly,
# go.mod and go.sum will be updated locally.
deps:
	FROM +base
    RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.1
    COPY go.mod go.sum ./
    RUN go mod download
    SAVE ARTIFACT go.mod AS LOCAL go.mod
    SAVE ARTIFACT go.sum AS LOCAL go.sum

test:
	FROM +deps
	COPY . .
	RUN go test -v ./...
