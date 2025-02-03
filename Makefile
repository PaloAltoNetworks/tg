MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail

export GO111MODULE = on

default: test

test:
	go test ./... -race -cover -covermode=atomic -coverprofile=unit_coverage.out

lint:
	golangci-lint run \
		--disable-all \
		--exclude-use-default=false \
		--exclude=package-comments \
		--exclude=unused-parameter \
		--enable=errcheck \
		--enable=goimports \
		--enable=ineffassign \
		--enable=revive \
		--enable=unused \
		--enable=staticcheck \
		--enable=unconvert \
		--enable=misspell \
		--enable=prealloc \
		--enable=nakedret \
		--enable=unparam \
		--enable=typecheck \
		./...

sec:
	# gosec -quiet -exclude=G304 ./...

upgrade-deps:
	go get -u github.com/smartystreets/goconvey@latest
	go get -u github.com/spf13/cobra@latest
	go get -u github.com/spf13/viper@latest
	go get -u golang.org/x/term@latest
	go mod tidy
