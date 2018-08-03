MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail

PROJECT_SHA ?= $(shell git rev-parse HEAD)
PROJECT_VERSION ?= $(lastword $(shell git tag --sort version:refname --merged $(shell git rev-parse --abbrev-ref HEAD)))
PROJECT_RELEASE ?= dev

ci: init lint test build_linux build_darwin build_windows package

define VERSIONS_FILE
package versions

// Various version information.
var (
	ProjectVersion = "$(PROJECT_VERSION)"
	ProjectSha     = "$(PROJECT_SHA)"
	ProjectRelease = "$(PROJECT_RELEASE)"
)
endef
export VERSIONS_FILE

init:
	@echo generating versions.go
	@mkdir -p ./internal/versions
	@echo "$$VERSIONS_FILE" > ./internal/versions/versions.go
	go generate ./...
	dep ensure -v

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
		--enable=varcheck \
		--enable=ineffassign \
		--enable=deadcode \
		--enable=unconvert \
		--enable=misspell \
		--enable=unparam \
		./...

test:
	go test ./... -race -cover

prebuild:
	mkdir -p ./build/{darwin,linux,windows}

.PHONY: build
build:
	go build

build_linux: prebuild
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
	cp ./apoctl ./build/linux

build_darwin: prebuild
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build
	cp ./apoctl ./build/darwin

build_windows:
	echo "not working" > ./build/windows/apoctl

package: build_linux
	mkdir -p ./docker/app
	cp ./apoctl ./docker/app

container: package
	cd docker && docker build -t gcr.io/aporetodev/apoctl:$(PROJECT_VERSION) .
