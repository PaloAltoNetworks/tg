MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail

export GO111MODULE = on

default: lint test

lint:
	golangci-lint run \
		--disable-all \
		--exclude-use-default=false \
		--enable=errcheck \
		--enable=goimports \
		--enable=ineffassign \
		--enable=golint \
		--enable=unused \
		--enable=structcheck \
		--enable=staticcheck \
		--enable=varcheck \
		--enable=deadcode \
		--enable=unconvert \
		--enable=misspell \
		--enable=prealloc \
		--enable=nakedret \
		--enable=unparam \
		./...

test:
	go test ./... -race -cover -covermode=atomic -coverprofile=unit_coverage.cov

build:
	CGO_ENABLED=0 go build

build_linux: prebuild
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build

build_darwin: prebuild
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build
