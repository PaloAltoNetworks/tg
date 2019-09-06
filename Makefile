MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail

PROJECT_SHA ?= $(shell git rev-parse HEAD)
PROJECT_VERSION ?= $(lastword $(shell git tag --sort version:refname --merged $(shell git rev-parse --abbrev-ref HEAD)))
PROJECT_RELEASE ?= dev

# Until we support go.mod properly
export GO111MODULE = off

ci: init lint test codecov build_linux build_darwin build_windows package
	@echo "ci artifacts dir layout: https://github.com/aporeto-inc/builder/wiki#dir-layout"
	mkdir -p artifacts/
	echo "$(PROJECT_SHA)" > artifacts/src_sha
	echo "$(PROJECT_VERSION)" > artifacts/src_semver
	echo "$(PROJECT_BRANCH)" > artifacts/src_branch
	if [[ -d docker/ ]] ; then cp -r docker/ artifacts/docker/ ; fi
	if [[ -f Gopkg.toml ]] ; then cp Gopkg.toml artifacts/ ; fi
	if [[ -f Gopkg.lock ]] ; then cp Gopkg.lock artifacts/ ; fi
	if [[ -d build/ ]] ; then cp -r build/ artifacts/build/ ; fi

init:
	go get -u github.com/aporeto-inc/go-bindata/...
	go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
	dep ensure
	dep status || true
	go generate ./...

lint:
	# --enable=unparam
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
		./...

test:
	@ echo 'mode: atomic' > unit_coverage.cov
	@ for d in $(shell go list ./... | grep -v vendor); do \
		go test -race -coverprofile=profile.out -covermode=atomic "$$d" && \
		if [ -f profile.out ]; then tail -q -n +2 profile.out >> unit_coverage.cov; rm -f profile.out; fi; \
	done;

coverage_aggregate:
	@ mkdir -p artifacts
	@ for f in `find . -maxdepth 1 -name '*.cov' -type f`; do \
		filename="$${f##*/}" && \
		go tool cover -html=$$f -o artifacts/$${filename%.*}.html; \
	done;

codecov: coverage_aggregate
	bash <(curl -s https://codecov.io/bash)

prebuild:
	mkdir -p ./build/{darwin,linux,windows}

.PHONY: build
build:
	&& go build

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
