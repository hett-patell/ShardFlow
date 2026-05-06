# ShardFlow — Design Specification

- **Status:** Draft, awaiting user approval
- **Date:** 2026-05-06
- **Authors:** hett (product), brainstormed with Claude
- **Inspiration / point of comparison:** Arcai NetCut (https://arcai.com/)

---

## 1. Summary

ShardFlow is a Linux-only Layer-2 LAN workbench for **authorized** pentesting,
red-team engagements, and classroom/CTF lab use. From a single Go binary pair
(`shardflowd` + `shardflow`) it discovers every device on the local segment,
selectively redirects chosen targets' traffic through the operator host via
ARP poisoning, and applies one of three per-target policies — **drop**,
**throttle**, or **passive pcap capture** — using kernel primitives
(`nftables`, `tc`, `AF_PACKET`) for the data plane and a Go control plane that
exposes the operator interface as a CLI and a TUI dashboard.

Where NetCut is a point-and-click "kick people off Wi-Fi" tool with no
operational scaffolding, ShardFlow is a structured workbench: a clean
target→policy abstraction, a kernel-fast data plane, and a layout that leaves
a clear seam for future MITM modes (HTTP rewrite, TLS interception via a local
CA, scriptable hooks) without disturbing the v1 core.

## 2. Goals

- Operate on a single Linux host with `CAP_NET_RAW` + `CAP_NET_ADMIN`.
- Discover devices on the local IPv4 segment and enrich each with vendor
  (OUI), hostname (mDNS / NetBIOS / DHCP), and model (SSDP) where available.
- Allow the operator to attach independent policies per target:
  **drop**, **throttle (rate-limited forwarding)**, or **pcap (passive
  capture to file while forwarding)**.
- Apply policies via ARP poisoning of the gateway/target pair, with
  forwarding and rate-limiting performed in the kernel.
- Recover the LAN cleanly on normal shutdown (corrective gratuitous ARPs).
- Detect leftover state from a previous crashed run and refuse (or clean)
  rather than silently re-using it.
- Provide a CLI suitable for scripting and a feature-complete TUI suitable
  for operators who don't memorise commands. Both speak the same RPC.
- Architect the policy layer so additional capabilities (HTTP rewrite, TLS
  interception, eBPF redirect, Lua/Starlark scripting) can be added later as
  new effectors + new compile rules without touching the rest of the daemon.

## 3. Non-goals (v1)

The following are deliberately out of scope for v1. They are not "nice to
have"; they are explicitly deferred to keep the v1 surface coherent.

- **TLS interception** of any kind. No local CA generation, no SNI proxy.
- **HTTP rewrite / response modification.** Pcap copies traffic; it does not
  alter it.
- **Scripting hooks** (Lua, Starlark, JavaScript, etc.).
- **IPv6 support.** No NDP spoofing, no IPv6 device tracking. The address-
  family abstraction is structured so adding IPv6 later is additive, not a
  rewrite. Caveat documented in §11.
- **OS fingerprinting.** No active nmap-style probing. Fingerprint data
  comes only from passive sources (DHCP options, mDNS, SSDP) and OUI lookup.
- **Multi-host coordination.** A single `shardflowd` per host; no cluster
  mode, no remote agents.
- **Cross-restart persistence.** Daemon state is in-memory. Restart wipes
  policies and the device list. By design.
- **Authorization scaffolding** — no scope file, no scope enforcement, no
  audit log, no confirmation prompts, no self-lockout protection. The tool
  trusts the operator. (See §4.)
- **Web UI.** TUI only. The RPC layer is intentionally generic enough that
  a future web client is a separable spec, not a v1 deliverable.
- **Cross-platform builds.** Linux only. Kernel ≥ 4.18 (for nftables).

## 4. Use case & authorization stance

ShardFlow is intended for use in **explicitly authorized** contexts:
in-scope pentest engagements, red-team exercises with documented rules of
engagement, classroom labs, and CTF environments. Use against networks the
operator does not own or is not authorized to test is, in most jurisdictions,
unauthorized access.

Per the explicit product decision recorded during design, ShardFlow does
**not** itself enforce authorization at runtime. There is no scope file, no
allow-list, no audit log, and no confirmation prompt. The daemon executes
whatever the client asks. This matches the operating model of similar tools
in this space (`bettercap`, `ettercap`, `mitmproxy`) and treats authorization
as out-of-band — owned by the engagement contract, not the binary. This
decision is intentional and recorded here so it is not re-litigated in
implementation.

A consequence: ShardFlow ships with no built-in protection against
self-lockout (e.g., poisoning the operator's own management interface). The
operator is expected to know which interface they are working from.

## 5. v1 capability slice

The v1 product is **discovery + cutter + throttle + passive L2 intercept**.
Each capability shares one underlying primitive (the operator becomes the
forwarder for selected targets via ARP poisoning); they differ only in the
policy applied to that forwarded traffic.

| Policy | Behaviour |
|---|---|
| `drop` | Forwarded frames dropped at the kernel by an `nftables` rule. |
| `throttle <rate>` | Forwarded frames pass through a `tc` HTB class on the IFB interface, rate-limited per target. |
| `pcap <file>` | Frames forwarded normally; a `tc act_mirred` copy is written to a per-target pcap-ng file via `AF_PACKET TPACKET_V3`. |

A target may have at most one policy at a time. A target with no policy is
not poisoned and not affected.

## 6. Architecture

### 6.1 Process topology

Two binaries, one repository:

- **`shardflowd`** — the privileged daemon. One per host. Requires
  `CAP_NET_RAW` and `CAP_NET_ADMIN`. Owns all kernel state (sockets,
  nftables, tc, IFB) and all in-memory state (device store, active policies).
- **`shardflow`** — the unprivileged client. Provides the CLI (Cobra
  subcommands) and the TUI (bubbletea) modes; mode is selected by argv.

The client is a thin wrapper around the RPC. Both modes — CLI and TUI — call
the same JSON-RPC methods on the daemon. The TUI is operationally complete:
every action available from the CLI is available from the TUI, and vice
versa. Feature parity is enforced by construction (one back-end, two
front-ends).

### 6.2 Control plane vs data plane

The daemon's load-bearing structural decision is the split between control
plane (Go code) and data plane (kernel-managed):

```
              ┌─────────────────────────────────────────────┐
              │                shardflowd                   │
              │  ┌────────────┐   ┌────────────────────┐    │
   RPC over   │  │  control   │   │     data plane     │    │
   Unix sock  │  │   plane    │   │   (kernel-owned)   │    │
   ───────────┼─▶│  (Go code) │──▶│  nftables rules    │    │
   shardflow     │            │   │  tc qdiscs (HTB)   │    │
                 │  scanners  │   │  ifb / dummy ifs   │    │
                 │  ARP engine│   │  AF_PACKET ring ◀──┼─── pcap copy
                 │  policy    │   │                    │    │
                 │  compiler  │   └────────────────────┘    │
                 └────────────┘                             │
              └─────────────────────────────────────────────┘
                         │
                         ▼  raw packets (ARP poison only)
                   ┌─────────────┐
                   │  LAN NIC    │
                   └─────────────┘
```

ARP poisoning (low-rate control-plane traffic) is sent from userspace via
`AF_PACKET`. Forwarding, dropping, and throttling are done by the kernel.
Pcap data is read by userspace from a `tc act_mirred` copy stream, not from
the primary forwarding path.

### 6.3 RPC

- **Transport:** Unix domain socket at `/run/shardflow/sock`, mode 0600,
  owned root.
- **Protocol:** JSON-RPC 2.0, with server-initiated **`event` notifications**
  for asynchronous updates (`device.discovered`, `device.updated`,
  `policy.applied`, `counters.tick` at 1 Hz, `pcap.rotated`).
- **Connection model:** the connection is bidirectional and carries both
  request/response RPC frames and unsolicited event frames over a single
  socket. Clients use whichever subset they need: the CLI sends one request
  and exits (request/response only); the TUI keeps the connection open and
  consumes the server-pushed event stream to avoid polling.

### 6.4 Persistence

None. Daemon state lives in process memory. A daemon restart wipes the
device list and any active policies. Discovered devices repopulate from
the always-on passive sniffer plus on-demand active scans.

The startup recovery check (§9.1) detects leftover *kernel* state from a
prior crashed daemon (an `shardflow` nftables table or a `shardflow0` IFB
interface) and refuses to start unless explicitly told to clean it up.

## 7. Components

Each component has one responsibility, a small interface, and explicit
dependencies.

### 7.1 State

**`devicestore`**
- *Purpose:* the in-memory map keyed by MAC address holding
  `Device{ip, mac, hostname, vendor, last_seen, fingerprint, policy}`.
  Single source of truth for "what's on the LAN right now."
- *API:* `Upsert(observation)`, `Get(mac)`, `ResolveIP(ip) (mac, ok)`,
  `List()`, `Subscribe() <-chan Event`.
- *Depends on:* nothing (pure Go).

**Target identity (MAC-canonical, IP-friendly).** The MAC is the canonical
identifier everywhere inside the daemon: `devicestore` is MAC-keyed,
policies are bound to a MAC, and the audit-style `policy.applied` event
carries the MAC. The operator-facing CLI/TUI accepts either an IP or a MAC;
when given an IP, the RPC layer resolves it via `devicestore.ResolveIP`
**at command time** and the resolved MAC is what is stored. If a target's
IP changes during a session (DHCP renewal, etc.), the policy follows the
MAC: the always-on passive sniffer updates the device's IP in the store,
the `arpengine` is notified, and subsequent poison frames are emitted with
the updated IP↔MAC assertion. A Policy.Set against an IP that has no
known MAC is rejected (`unknown target — run scan first`).

### 7.2 Discovery

**`scan/active`** — issues ARP requests to every host in the iface's CIDR;
feeds replies into `devicestore`. Triggered by `Scan` RPC. Depends on
`AF_PACKET` and iface info.

**`scan/passive`** — always-on sniffer; reads ARP, DHCP, mDNS, NetBIOS, and
SSDP broadcast traffic; enriches `devicestore` rows. Depends on `AF_PACKET`.

**`scan/mdns`** — issues mDNS-SD queries on demand for hostname/service
enrichment. UDP socket; no privilege beyond bind.

**`scan/ssdp`** — issues SSDP `M-SEARCH` for router/printer/IoT model strings.
UDP socket.

**`oui`** — pure-data package, OUI database embedded at build time.
`Lookup(mac) → vendor`.

### 7.3 Effectors (kernel-touching)

**`arpengine`** — the poisoner.
- For each `(target, gateway)` pair under active poisoning, emits unsolicited
  ARP replies on a configurable cadence (default 1 s) telling the target
  that the gateway's MAC is the operator's, and the gateway that the
  target's MAC is the operator's. Tracks `ActivePoison{target, gw, started_at}`.
- On `Stop(target)` or daemon shutdown, sends corrective gratuitous ARPs
  with the real mappings.
- *API:* `Start(target)`, `Stop(target)`, `StopAll()`, `Active() []ActivePoison`.
- *Depends on:* `AF_PACKET`, `devicestore` (gateway MAC lookup).

**`nftmgr`** — owns a single `shardflow` nftables table. Typed operations:
`EnsureTable()`, `AddTargetForward(target)`, `AddTargetDrop(target)`,
`RemoveTarget(target)`, `Teardown()`. Every change is one nftables
transaction. Implementation choice between shelling out to `nft(8)` and
using the `google/nftables` netlink library is deferred to implementation
(see §11).

**`tcmgr`** — owns one IFB interface (`shardflow0`) used as the throttle
attach-point. Per-target HTB classes. API: `SetThrottle(target, rate)`,
`ClearThrottle(target)`, `Teardown()`. Same deferred shell-out-vs-netlink
choice as `nftmgr`.

**`pcapwriter`** — for targets with a pcap policy: opens a tc-mirrored copy
stream via `AF_PACKET TPACKET_V3`; writes pcap-ng to
`/var/lib/shardflow/pcap/<engagement>/<mac>-<ts>.pcap`; rotates by
configurable size or time. Depends on `AF_PACKET` and the kernel
`act_mirred` action.

### 7.4 Orchestration

**`policycompiler`** — the central abstraction.
- *Purpose:* given a desired `(target → policy)` map, produces an ordered
  sequence of operations against `arpengine`, `nftmgr`, `tcmgr`, and
  `pcapwriter` that takes the system from current state to desired state.
- *API:* `Apply(desired StateMap) (Result, error)`. Idempotent — calling
  with the same desired state twice is a no-op.
- *Order of operations* (rigid; ensures we never redirect traffic into a
  half-built kernel pipeline). For drop policy, only steps 1 and 4 run; for
  throttle, 1+2+4; for pcap, 1+3+4.
  1. `nftmgr` rule: `AddTargetDrop(target)` for drop policy, otherwise
     `AddTargetForward(target)`.
  2. `tcmgr.SetThrottle(target, rate)` — throttle policy only.
  3. `pcapwriter.Open(target)` — pcap policy only.
  4. `arpengine.Start(target)`.
- *Rollback:* on failure of any step, the compiler reverses the steps it
  has already executed in this transaction, in reverse order. Returns the
  underlying error to the caller.
- *Why this is the central abstraction:* every future intercept mode
  (HTTP rewrite via `NFQUEUE`, TLS via SNI proxy, eBPF redirect, scripting)
  is a new effector + a new compile rule, slotted into the existing
  pipeline. Nothing else in the daemon needs to change.

### 7.5 Interface

**`rpc`** — JSON-RPC 2.0 server over the Unix socket. Methods:
`Scan`, `Devices.List`, `Devices.Get`, `Policy.Set`, `Policy.Clear`,
`Policy.List`, `Stats`. Server-pushed events as listed in §6.3.
Concurrency: writes (`Policy.*`) serialise through a single mutex on the
policy compiler; reads run concurrently.

**`cli`** — Cobra subcommands on the `shardflow` client binary: `scan`,
`devices`, `policy` (`set`, `clear`, `list`), `stats`, `tui`. Each
translates to one or more JSON-RPC calls. Output formats: human-readable
table by default, `--json` for scripts. (The daemon is a separate binary,
`shardflowd`, started directly — it is not a `shardflow` subcommand.)

**`tui`** — bubbletea client. Subscribes to the daemon's event stream and
re-renders on each event; sends actions back via the same RPC the CLI uses.
Layout (final widget choices deferred to implementation):

```
┌──────────────────── shardflow ─ iface: wlan0 ─ gw: 10.0.0.1 ─────────────────┐
│ Devices (12)                          │ Policy: 10.0.0.42                    │
│ ─────────────────────────────────     │ ──────────────────────────────────   │
│ ▶ 10.0.0.42  Apple-iPhone   3c:aa:..  │  state:    throttled (200kbit)       │
│   10.0.0.55  Samsung-TV     8c:f5:..  │  poisoned: yes (since 12:04:11)      │
│   10.0.0.71  Raspberry Pi   b8:27:..  │  rx:       1.2 MB    tx:  340 KB     │
│   …                                   │  pcap:     —                         │
│                                       │                                      │
│ [a] add  [r] remove                   │ [d] drop  [t] throttle  [p] pcap     │
│                                       │ [x] clear                            │
├───────────────────────────────────────┴──────────────────────────────────────┤
│ Live (last 10s):  poisoned=3   throughput=4.1 MB/s   policy-changes=2        │
│ Log: 12:04:11  policy 10.0.0.42 → throttle 200kbit                           │
│      12:03:58  scan complete: 12 devices                                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

The contract: **left pane lists discovered devices; right pane edits the
selected target's policy; bottom shows live counters and a scrolling event
log; every action has a single-key shortcut and a corresponding CLI flag
form.**

### 7.6 Dependency graph

```
cli, tui  ──▶  rpc-client  ──▶  rpc-server
                                    │
                                    ▼
                            policycompiler
                            ┌─────┬─────┬─────┐
                            ▼     ▼     ▼     ▼
                       arpengine nftmgr tcmgr pcapwriter
                            │     │     │     │
                            └─────┴─────┴─────┘
                                    │
                                    ▼
                              devicestore  ◀── scan/{active,passive,mdns,ssdp}, oui
```

No cycles. Each box is small enough to test in isolation.

## 8. Discovery techniques (v1)

| Technique | Direction | What it adds | Always-on? |
|---|---|---|---|
| Active ARP sweep | active | MAC↔IP for the local CIDR | on demand (`Scan`) |
| Passive sniffer | passive | ARP, DHCP, mDNS, NetBIOS, SSDP broadcasts → hostname/vendor/arrival events | yes |
| mDNS / Bonjour | active | hostnames, service strings | on demand |
| SSDP / UPnP M-SEARCH | active | router/printer/IoT model strings | on demand |
| OUI lookup | offline | vendor from MAC OUI | always |

Active OS fingerprinting (nmap-style) is explicitly out of v1 (§3).

## 9. Operational behaviour

### 9.1 Daemon lifecycle

**Startup**
1. Parse flags, validate `-i <iface>`.
2. Check capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`); exit with a clear
   error if missing.
3. Claim `/run/shardflow/sock`. If a stale socket file exists, exit unless
   `--force` was passed.
4. **Recovery check:** if a `shardflow` nftables table or a `shardflow0` IFB
   interface already exists, log it and either (a) clean it up and continue
   if `--clean-on-start` was passed, or (b) refuse to start. Default: refuse,
   so the operator notices.
5. Initialise an empty `shardflow` nftables table. Create the `shardflow0`
   IFB interface and attach base qdiscs.
6. Save the current value of `net.ipv4.ip_forward` and set it to `1`
   (without IP forwarding the kernel drops redirected frames; throttle and
   pcap policies need forwarding enabled, drop policy works with or without
   it but we keep behaviour uniform). The saved value is restored on clean
   shutdown.
7. Start the passive sniffer goroutine.
8. Open the RPC socket and accept connections.

**Clean shutdown** (`SIGINT` / `SIGTERM`)
1. Stop accepting new RPC requests; reply `ECANCELED` to in-flight ones.
2. For every active poison: call `arpengine.Stop(target)` which sends
   corrective gratuitous ARPs (real gateway MAC to target, real target MAC
   to gateway) and waits ~3× the poison cadence.
3. Flush the `shardflow` nftables table; delete `shardflow0`.
4. Close pcap writers (proper trailer).
5. Restore the saved `net.ipv4.ip_forward` value.
6. Remove the socket file. Exit 0.

**Hard crash** (`SIGKILL`, panic, OOM): no in-process cleanup possible.
Targets recover from ARP cache poisoning naturally as cache entries time out
(typically minutes). The startup recovery check (step 4 above) is the safety
net for the orphaned kernel state.

### 9.2 Per-target lifecycle

```
   discovered ──▶ idle (no policy)
                    │
                    ▼  Policy.Set
              ┌── compiling ──┐
              │   (rollback   │
              │    if any     │
              │    step fails)│
              └───────────────┘
                    │
                    ▼
                 active ──┐
                    │     │ Policy.Set (change)
                    │     └─▶ compiling …
                    │
                    ▼  Policy.Clear  /  daemon shutdown
                cleaning up
                (corrective ARP + nft del + tc del + close pcap)
                    │
                    ▼
                   idle
```

Order of operations as defined in §7.4. Rollback in reverse on any failure.

## 10. Error handling

| Failure mode | Behaviour |
|---|---|
| nftables transaction fails | `policycompiler` rolls back; RPC returns the underlying error verbatim; target stays in prior state. |
| `tc` operation fails | Same as above. |
| Pcap directory full / unwritable | `Policy.Set pcap` rejected up-front (`statfs` check before commit). An already-running pcap rotates and emits a `pcap.rotated` event with `error`; forwarding for the target continues. |
| Iface goes down mid-session | All active policies stay registered; their `applied` flag flips false; an `iface.down` event is pushed. On `iface.up`, policies are re-applied automatically. The TUI surfaces this as e.g. "wlan0 down — 3 policies suspended". |
| Target's gateway equals the operator's IP | Refuse with explicit error: "operator host is the gateway; nothing to poison". |
| Concurrent RPC writers | Serialised through a single mutex on the policy compiler. Reads run concurrently. |
| Target IP outside the iface's CIDR | Refuse — sanity check; ARP poisoning across subnets makes no sense. |
| Daemon receives RPC for an unknown target MAC | Refuse with `not found`; the client is expected to `Scan` first. |

There is no broader "panic on any error" anywhere. Every effector returns
typed errors; the policy compiler is responsible for rollback.

## 11. Open items deferred to implementation

These are deliberate non-decisions in the spec; the implementation plan or
the implementation itself will resolve them.

1. **`nftmgr` and `tcmgr`: shell-out vs netlink library.** Both options are
   viable. Shelling out to `nft(8)` and `tc(8)` is simpler, more inspectable
   in logs, and side-steps version-skew issues with the netlink libraries.
   Using `google/nftables` and a tc-netlink library is faster, avoids
   parsing tool output, and doesn't require those binaries on the host.
   Decide during implementation; the public API of both packages is the
   same either way.
2. **Exact shape of RPC method payloads.** §6.3 lists the methods and event
   names. Field-level schemas are the implementation plan's job.
3. **Final TUI keybindings and concrete bubbletea component choices.**
   §7.5 fixes the layout contract; specifics are an implementation detail.
4. **Pcap rotation policy defaults** (size threshold, time threshold).
   Sensible starting point: 100 MB or 15 min, configurable.

## 12. Real-world conditions that defeat the v1 tool

These are not bugs and are not in scope to fix in v1; they are documented
so the first failed run is not mistaken for the tool being broken.

- **AP/client isolation** (also called "guest mode" or "AP isolation") is
  enabled by default on most modern guest Wi-Fi and many enterprise SSIDs.
  The access point silently drops Layer-2 traffic between client stations,
  including ARP. Against an AP-isolated network, ShardFlow cannot poison
  the target's ARP cache because its frames never reach the target. The
  device list will populate normally (broadcasts still pass), but every
  policy will appear to do nothing. There is no workaround at this layer —
  the AP is enforcing the isolation.
- **Static ARP entries** on hardened endpoints (servers, security appliances,
  some IoT devices configured for it) are not affected by ARP poisoning at
  all. ShardFlow will report "poisoned" because it is sending the frames,
  but the target ignores them and continues to use the real gateway MAC.
- **Switches with dynamic ARP inspection (DAI)** in managed enterprise
  networks may drop the spoofed ARP frames at the switch port and, on some
  configurations, disable the operator's port. Be aware of this before
  testing in a managed environment.
- **Wired vs Wi-Fi forwarding asymmetry.** On Wi-Fi, the AP is between every
  pair of clients; ShardFlow's frames are visible to the AP and may be
  rate-limited or filtered. On a flat Ethernet segment, this concern goes
  away.

The `arpengine` and `policycompiler` do not attempt to detect any of
these conditions. The TUI's poisoned/unpoisoned indicator reflects what
ShardFlow has *sent*, not what the target has *believed*.

## 13. IPv6 caveat (recorded for the record)

IPv4 only in v1 is a real limitation. A dual-stack target that prefers IPv6
will route around ShardFlow's poisoning entirely — DNS over IPv6, traffic
over IPv6, etc. — and the operator will see only the target's IPv4 traffic
(if any). Networks with strict IPv4-preferred policies are unaffected;
modern home and enterprise networks increasingly are not. The address-
family abstraction inside `arpengine`, `scan/passive`, and `nftmgr` is
designed so adding NDP spoofing and IPv6 nft rules later is additive.

## 14. Testing strategy

Three independently runnable layers.

**Unit tests** — pure-Go packages with no kernel dependency:
`devicestore`, `oui`, `policycompiler` (with all four effectors mocked
behind interfaces). `go test ./...` on any machine; no privilege.

**Integration tests** — driven by `make test-env`, which builds a Linux
**network-namespace** topology:

```
 ns:gateway ─── veth-gw ─┐
                          ├─── (linux bridge in ns:lab)
 ns:victim  ─── veth-vic ─┤
                          │
 ns:operator── veth-op ──┘   <- shardflowd runs here
```

Tests in this layer run an actual `shardflowd` against actual `nftables`
and `tc` and assert observable behaviours, e.g.:
- after `policy set victim drop`, victim cannot reach gateway;
- after `policy clear victim`, victim's ARP cache contains the real gateway
  MAC within N seconds;
- after `policy set victim throttle 200kbit`, throughput is bounded;
- after `policy set victim pcap`, frames captured to disk match frames seen
  by the gateway.

Requires `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`; runs in CI under a privileged
container.

**TUI snapshot tests** — bubbletea views fed synthetic event streams,
golden-file diff. No daemon, no kernel.

**Manual smoke tests** on a real LAN are documented in a runbook but are
not automated.

## 15. Project layout

```
cmd/
  shardflow/      # the client (CLI + TUI)
  shardflowd/     # the daemon
internal/
  devicestore/
  scan/
    active/
    passive/
    mdns/
    ssdp/
  oui/
  arpengine/
  nftmgr/
  tcmgr/
  pcapwriter/
  policycompiler/
  rpc/            # shared types + server + client
  tui/            # bubbletea views
test/
  netns/          # the namespace harness + integration tests
Makefile
go.mod
```

`internal/` because nothing here is intended as a public Go library — these
are implementation packages of the two binaries.

## 16. Glossary

- **ARP poisoning** — sending unsolicited ARP replies to associate the
  attacker's MAC with another host's IP in the victim's ARP cache,
  causing the victim to send traffic to the attacker.
- **Gratuitous ARP** — an unsolicited ARP reply broadcast to update other
  hosts' caches; used here both *to* poison and to *un*-poison.
- **IFB** — Linux Intermediate Functional Block interface; a virtual
  interface used as an attach-point for tc qdiscs that need to act on
  ingress traffic.
- **HTB** — Hierarchical Token Bucket, a tc qdisc family used here for
  per-target rate limiting.
- **`AF_PACKET TPACKET_V3`** — Linux raw packet socket variant with a
  ring buffer mapped into user space; used for high-throughput pcap
  capture.
- **`act_mirred`** — a tc action that mirrors (or redirects) packets to
  another interface; used here to copy a target's frames to a dummy
  interface that the daemon reads.
