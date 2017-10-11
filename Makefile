include domingo.mk

init: domingo_init
test: domingo_test
build: build_linux build_darwin build_windows

build_darwin: domingo_build_darwin
	mkdir -p build/darwin
	mv ./tg build/darwin

build_linux: domingo_build_linux
	mkdir -p build/linux
	mv ./tg build/linux

build_windows: domingo_build_windows
	mkdir -p build/windows
	mv ./tg.exe build/windows
