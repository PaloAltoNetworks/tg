MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail

export GO111MODULE = on

default: test

test:
	go test ./... -race -cover -covermode=atomic -coverprofile=unit_coverage.out

sec:
	# gosec -quiet -exclude=G304 ./...
