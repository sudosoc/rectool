BIN     := bin/rectool
LDFLAGS := -s -w

.PHONY: build install test sites linux-amd64 linux-arm64 clean

build:
	go mod tidy
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/rectool

install:
	sh ./install.sh

test:
	go vet ./... && go test -race ./...

sites:
	sh scripts/update-sites.sh

# Cross-compile Linux binaries from any OS (single static file each).
linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/rectool-linux-amd64 ./cmd/rectool

linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/rectool-linux-arm64 ./cmd/rectool

clean:
	rm -rf bin reports out
