GO       ?= go
BIN_DIR  := bin
BINS     := shardflow shardflowd

# Source-file dependency for build targets. Including internal/ makes
# `make build` correctly trigger a rebuild whenever any package the
# binaries link against changes — not just files under cmd/. Go's own
# build cache prevents redundant compilation, so this is essentially
# free; without it `make build` would silently use the stale binary
# after editing internal/* (Go would still rebuild on `go run`, but the
# bin/ artefact wouldn't move).
SRCS := $(shell find cmd internal -name '*.go' -not -name '*_test.go' 2>/dev/null)

.PHONY: all build test lint vet fmt clean test-env test-int lab-up lab-down help

# Default fake-host count for `make lab-up`. Override on the command
# line: `make lab-up COUNT=24`.
COUNT ?= 12

all: build

build: $(addprefix $(BIN_DIR)/, $(BINS))

$(BIN_DIR)/%: $(SRCS)
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

# Local scan playground: a Linux bridge with COUNT netns hosts, all
# auto-replying to ARP. See scripts/lab-up for the rationale and the
# follow-up commands to point shardflowd at it.
lab-up:
	sudo bash scripts/lab-up $(COUNT)

lab-down:
	sudo bash scripts/lab-down

help:
	@echo "Targets:"
	@echo "  build / test / lint / vet / fmt / clean"
	@echo "  test-env test-int          — netns rig for the integration test suite"
	@echo "  lab-up [COUNT=N]           — N fake hosts on bridge sf-lab0 for manual scan testing"
	@echo "  lab-down                   — tear the lab rig down"
