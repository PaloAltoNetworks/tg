ci:
	go get -u github.com/magefile/mage github.com/aporeto-inc/domingo/golang
	mage init
	mage test
	mage build
	mage package
