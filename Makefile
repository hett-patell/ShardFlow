GO       ?= go
BIN_DIR  := bin
BINS     := shardflow shardflowd

.PHONY: all build test lint vet fmt clean test-env test-int help

all: build

build: $(addprefix $(BIN_DIR)/, $(BINS))

$(BIN_DIR)/%: cmd/%/*.go
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $@ ./cmd/$*

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

lint: vet
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; else echo "(skipping golangci-lint, not installed)"; fi

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html

# Integration test environment: requires root (creates network namespaces).
test-env:
	sudo bash test/netns/setup.sh

test-int:
	sudo $(GO) test -tags=integration -v ./test/...

help:
	@echo "Targets: build test lint vet fmt clean test-env test-int"
