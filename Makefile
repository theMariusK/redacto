.PHONY: build test clean

BINARY := redacto

build:
	go build -o $(BINARY) .

test:
	go test -v ./...

clean:
	rm -f $(BINARY)
