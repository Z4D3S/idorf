BINARY := idorf
VERSION := $(shell grep -oP 'const version = "\K[^"]+' cmd/idorf/main.go)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

.PHONY: build test run clean install release

build:
	go build -o $(BINARY) -ldflags="-s -w" ./cmd/idorf/

install:
	go install ./cmd/idorf/

test:
	go test ./... -v

run:
	go run ./cmd/idorf/ $(ARGS)

clean:
	rm -f $(BINARY) results.json

release:
	@echo "Building release v$(VERSION)..."
	mkdir -p release
	GOOS=linux   GOARCH=amd64 go build -o release/$(BINARY)-linux-amd64 -ldflags="-s -w" ./cmd/idorf/
	GOOS=darwin  GOARCH=amd64 go build -o release/$(BINARY)-darwin-amd64 -ldflags="-s -w" ./cmd/idorf/
	GOOS=darwin  GOARCH=arm64 go build -o release/$(BINARY)-darwin-arm64 -ldflags="-s -w" ./cmd/idorf/
	GOOS=windows GOARCH=amd64 go build -o release/$(BINARY)-windows-amd64.exe -ldflags="-s -w" ./cmd/idorf/
	@echo "Done. Files in release/"

fmt:
	go fmt ./...

vet:
	go vet ./...