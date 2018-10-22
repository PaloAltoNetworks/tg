MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail

PROJECT_SHA ?= $(shell git rev-parse HEAD)
PROJECT_VERSION ?= $(lastword $(shell git tag --sort version:refname --merged $(shell git rev-parse --abbrev-ref HEAD)))
PROJECT_RELEASE ?= dev

ci: init lint test build_linux build_darwin build_windows package
	@echo "ci artifacts dir layout: https://github.com/aporeto-inc/builder/wiki#dir-layout"
	mkdir -p artifacts/
	echo "$(PROJECT_SHA)" > artifacts/src_sha
	echo "$(PROJECT_VERSION)" > artifacts/src_semver
	echo "$(PROJECT_BRANCH)" > artifacts/src_branch
	if [[ -f Gopkg.toml ]] ; then cp Gopkg.toml artifacts/ ; fi
	if [[ -f Gopkg.lock ]] ; then cp Gopkg.lock artifacts/ ; fi
	if [[ -d build/ ]] ; then cp -r build/ artifacts/build/ ; fi
	if [[ -d docker/ ]] ; then cp -r docker/ artifacts/docker/ ; fi
	mkdir -p artifacts/repo/helm/
	if [[ -d helm/repo/ ]] ; then cp -r helm/repo/* artifacts/repo/helm/ ; fi
	if [[ -d helm/aggregated/ ]] ; then cp -r helm/aggregated/* artifacts/repo/helm/ ; fi
	mkdir -p artifacts/repo/swarm/
	if [[ -d swarm/repo/ ]] ; then cp -r swarm/repo/* artifacts/repo/swarm/ ; fi
	if [[ -d swarm/aggregated/ ]] ; then cp -r swarm/aggregated/* artifacts/repo/swarm/ ; fi

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
		--enable=deadcode \
		--enable=unconvert \
		--enable=misspell \
		--enable=unparam \
		--enable=prealloc \
		--enable=nakedret \
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
