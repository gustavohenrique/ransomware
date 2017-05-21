.PHONY: test
test:
	rm -rf /tmp/test 2>/dev/null
	cp -r test /tmp
	go test -v cryptography/decrypt_test.go cryptography/encrypt_test.go cryptography/generate_keys_test.go
	go test util/html_test.go

win:
	GOOS=windows GOARCH=amd64 go build -o rswclient-windows-amd64.exe client.go
	GOOS=windows GOARCH=amd64 go build -o rswserver-windows-amd64.exe server.go

linux:
	GOOS=linux GOARCH=amd64 go build -o rswclient-linux-amd64 client.go
	GOOS=linux GOARCH=amd64 go build -o rswserver-linux-amd64 server.go

mac:
	GOOS=darwin GOARCH=amd64 go build -o rswclient-darwin-amd64 client.go
	GOOS=darwin GOARCH=amd64 go build -o rswserver-darwin-amd64 server.go

build: linux

all: linux win mac

install:
	go get -v github.com/Masterminds/glide
	cd ${GOPATH}/src/github.com/Masterminds/glide && git checkout tags/v0.12.3 && go install && cd -
	glide install
