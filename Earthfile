VERSION 0.7
PROJECT sonrhq/sonr-testnet-0

FROM golang:1.21-alpine3.17
RUN apk add --update --no-cache \
    bash \
    bash-completion \
    binutils \
    ca-certificates \
    clang-extra-tools \
    coreutils \
    curl \
    findutils \
    g++ \
    git \
    grep \
    jq \
    less \
    make \
    nodejs \
    npm \
    openssl \
    util-linux


# deps - downloads and caches all dependencies for earthly. go.mod and go.sum will be updated locally.
deps:
    FROM +base
    RUN npm install -g swagger-combine
    RUN npm install @bufbuild/buf
    FROM ghcr.io/cosmos/proto-builder:0.14.0
    RUN go install cosmossdk.io/orm/cmd/protoc-gen-go-cosmos-orm@latest
	RUN go install cosmossdk.io/orm/cmd/protoc-gen-go-cosmos-orm-proto@latest
    SAVE IMAGE deps

# generate - generates all code from proto files
generate:
    FROM +deps
    COPY . .
    RUN sh ./scripts/protocgen.sh
    SAVE ARTIFACT sonrhq/identity AS LOCAL api
    SAVE ARTIFACT proto AS LOCAL proto

# test - runs all tests
test:
	FROM +base
	COPY . .
	RUN go test -v ./...
