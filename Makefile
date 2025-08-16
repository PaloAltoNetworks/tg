MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail

export GO111MODULE = on

default: test

test:
	go test ./... -race -cover -covermode=atomic -coverprofile=unit_coverage.out

lint:
	golangci-lint run ./...

sec:
	# gosec -quiet -exclude=G304 ./...

update-deps:
	go get -u github.com/smartystreets/goconvey@latest
	go get -u github.com/spf13/cobra@latest
	go get -u github.com/spf13/viper@latest
	go get -u golang.org/x/term@latest
	go mod tidy
