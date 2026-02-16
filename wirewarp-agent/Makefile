BINARY   = wirewarp-agent
GOOS    ?= linux
GOARCH  ?= amd64
OUT      = dist/$(BINARY)

.PHONY: build clean

build:
	mkdir -p dist
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(OUT) ./cmd/agent

clean:
	rm -rf dist
