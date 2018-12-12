MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail

PROJECT_SHA ?= $(shell git rev-parse HEAD)
PROJECT_VERSION ?= $(lastword $(shell git tag --sort version:refname --merged $(shell git rev-parse --abbrev-ref HEAD)))
PROJECT_RELEASE ?= dev

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
	# go get ./...
	dep ensure
	dep status

init:
	go generate ./...

lint:
	golangci-lint run \
		--deadline=3m \
		--disable-all \
		--exclude-use-default=false \
		--enable=errcheck \
		--enable=goimports \
		--enable=ineffassign \
		--enable=govet \
		--enable=golint \
		--enable=unused \
		--enable=structcheck \
		--enable=varcheck \
		--enable=deadcode \
		--enable=unconvert \
		--enable=goconst \
		--enable=gosimple \
		--enable=misspell \
		--enable=staticcheck \
		--enable=unparam \
		--enable=prealloc \
		--enable=nakedret \
		--enable=typecheck \
		./...

test:
	go test ./... -race -cover -covermode=atomic -coverprofile=unit_coverage.cov

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
