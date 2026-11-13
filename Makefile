VERSION ?= v0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)
PKG := ./cmd/dup

# Local binary extension on Windows.
ifeq ($(OS),Windows_NT)
EXT := .exe
endif

.PHONY: build test race vet dist dist-win dist-linux-amd64 dist-linux-arm64 clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dup$(EXT) ./cmd/dup

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

# Cross-compile all release targets (pure Go, CGO off).
# Env vars are exported per target so this works under cmd.exe as well as sh.
dist: dist-win dist-linux-amd64 dist-linux-arm64

dist-win: export GOOS := windows
dist-win: export GOARCH := amd64
dist-win: export CGO_ENABLED := 0
dist-win:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/dup-windows-amd64.exe $(PKG)

dist-linux-amd64: export GOOS := linux
dist-linux-amd64: export GOARCH := amd64
dist-linux-amd64: export CGO_ENABLED := 0
dist-linux-amd64:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/dup-linux-amd64 $(PKG)

dist-linux-arm64: export GOOS := linux
dist-linux-arm64: export GOARCH := arm64
dist-linux-arm64: export CGO_ENABLED := 0
dist-linux-arm64:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/dup-linux-arm64 $(PKG)

clean:
ifeq ($(OS),Windows_NT)
	-if exist dist rmdir /s /q dist
	-if exist dup del dup
	-if exist dup.exe del dup.exe
else
	rm -rf dist dup
endif
