MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail

PROJECT_SHA ?= $(shell git rev-parse HEAD)
PROJECT_VERSION ?= $(lastword $(shell git tag --sort version:refname --merged $(shell git rev-parse --abbrev-ref HEAD)))
PROJECT_RELEASE ?= dev

ci: init lint test build_linux build_darwin build_windows package

init:
	go generate ./...

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
	cp ./tg ./build/linux

build_darwin: prebuild
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build
	cp ./tg ./build/darwin

build_windows:
	echo "not working" > ./build/windows/tg

package: build_linux
	mkdir -p ./docker/app
	cp ./tg ./docker/app

container: package
	cd docker && docker build -t gcr.io/aporetodev/tg:$(PROJECT_VERSION) .
