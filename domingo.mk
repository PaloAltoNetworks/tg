## configure this throught environment variables
PROJECT_NAME				?= $(shell basename $(PWD))
PROJECT_VERSION			?= $(shell git rev-parse --abbrev-ref HEAD)
PROJECT_SHA					?= $(shell git rev-parse HEAD)
DOMINGO_DOCKER_TAG	?=latest
DOMINGO_DOCKER_REPO	?=gcr.io/aporetodev
GITHUB_TOKEN				?=
MAKEFLAGS						+= --warn-undefined-variables
SHELL								:= /bin/bash -o pipefail

domingo_init:
	@echo "initializing..."
	@if [ -f glide.yaml ]; then glide up -v; else go get ./...; fi

domingo_write_versions:
	@echo "writing versions file..."
	@go get -u github.com/aporeto-inc/domingo/tools/apolibver
	@apolibver --project-version $(PROJECT_VERSION) --project-sha $(PROJECT_SHA)

domingo_lint:
	@echo "running linters..."
	@gometalinter --vendor --disable-all \
		--enable=vet \
		--enable=vetshadow \
		--enable=golint \
		--enable=ineffassign \
		--enable=goconst \
		--enable=errcheck \
		--enable=varcheck \
		--enable=structcheck \
		--enable=gosimple \
		--enable=misspell \
		--enable=deadcode \
		--enable=staticcheck \
		--deadline 5m \
		--tests ./...

domingo_unit_tests:
	@echo "running unit tests..."
	@go test -race -cover $(shell glide novendor)

domingo_test: domingo_lint domingo_unit_tests

domingo_build:
	@echo "building $(PROJECT_NAME) for current platform..."
	@CGO_ENABLED=0 go build -a -installsuffix cgo

domingo_build_linux:
	@echo "building $(PROJECT_NAME) for linux..."
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo

domingo_build_windows:
	@echo "building $(PROJECT_NAME) for windows..."
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo

domingo_build_darwin:
	@echo "building $(PROJECT_NAME) for darwin..."
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo

domingo_package:
	@echo "packaging $(PROJECT_NAME) binary..."
	@mkdir -p docker/app
	@cp -a $(PROJECT_NAME) docker/app

domingo_container:
	@echo "building $(DOMINGO_DOCKER_REPO)/$(PROJECT_NAME):$(DOMINGO_DOCKER_TAG)"
	@make build_linux
	@cd docker && docker build -t $(DOMINGO_DOCKER_REPO)/$(PROJECT_NAME):$(DOMINGO_DOCKER_TAG) .

domingo_update:
	@echo "updating domingo.mk..."
	@curl --fail -o domingo.mk -H "Cache-Control: no-cache" -H "Authorization: token $(GITHUB_TOKEN)" https://raw.githubusercontent.com/aporeto-inc/domingo/master/domingo.mk
