VERSION=$(shell git describe --always --long --dirty)
.PHONY: all clean

all: test build

build:
	mkdir -p dist
	go build -v -o dist/sshencode cmd/sshencode/main.go

clean:
	rm dist/sshencode

test:
	cd pkg/sshencode && go test  || (echo "Tests failed"; exit 1)

