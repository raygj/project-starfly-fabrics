BINARY := starfly
GO     := go

.PHONY: all build build-dev test clean dev deps

all: build

build:
	$(GO) build -o bin/$(BINARY) ./cmd/starfly/

build-dev:
	$(GO) build -tags dev -o bin/$(BINARY) ./cmd/starfly/

build-siggen:
	$(GO) build -o bin/starfly-siggen ./cmd/starfly-siggen/

test:
	$(GO) test -race ./pkg/...

dev: build-dev
	STARFLY_STORAGE_PATH=/tmp/starfly-dev \
	STARFLY_POLICY_BUNDLE_PATH=policies/dev \
	./bin/$(BINARY) --dev

deps:
	$(GO) mod download

clean:
	rm -rf bin/
