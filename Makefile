include domingo.mk

init: domingo_init
test: domingo_test
build: build_linux build_darwin build_windows package

build_darwin: domingo_build_darwin
	mkdir -p build/darwin
	mv ./tg build/darwin

build_linux: domingo_build_linux
	mkdir -p build/linux
	mv ./tg build/linux

build_windows:
	mkdir -p build/windows
	echo 'echo disabled' > build/windows/tg

package: build_linux
	cp build/linux/tg docker
