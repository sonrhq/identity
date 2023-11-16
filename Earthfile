VERSION 0.7
FROM golang:1.21-alpine3.18
WORKDIR /app

test:
	go test -v ./...

proto:
	ARG protoVer=0.14.0
	ARG protoImageName=protoc

