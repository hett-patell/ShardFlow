```
   _____ __                   ____  _____
  / ___// /_  ____ __________/ / / / __  )___ _      __
  \__ \/ __ \/ __  / ___/ __  / /_/ / __  / __ \ | /| / /
 ___/ / / / / /_/ / /  / /_/ / __  / /_/ / /_/ / |/ |/ /
/____/_/ /_/\__,_/_/   \__,_/_/ /_/_/ /_/\____/|__/|__/
```

**ShardFlow** — your friendly neighbourhood Layer-2 LAN workbench. Find every
device on the wire, then drop, throttle, or quietly pcap them. Built for
red-team labs, ethics class demos, and that one moment your roommate's
Bluetooth speaker hits 100 dB at 3 AM.

> ⚠️ **Authorized use only.** This tool ARP-poisons the LAN you point it at.
> Run it on a network you own, or one whose owner has given you explicit
> written permission. We're not bailing you out, and neither is your CS
> professor.

---

## What it does

| Capability | What that means in plain English |
|---|---|
| **Discovery** | Finds every device on the LAN (active ARP sweep + passive sniff + mDNS + SSDP + OUI vendor lookup). Not just whoever happens to be talking. |
| **Drop** | Quietly stops a device from reaching the gateway. Your sister claims the wifi is "broken." It is. For her. |
| **Throttle** | Rate-limit a victim to a specific bitrate. Want your housemate's 4K stream to load like 2007? `200kbit` does the trick. |
| **Pcap** | Passively capture a target's traffic to a rotating `.pcapng`. Read it later in Wireshark and pretend you understand it. |
| **TUI dashboard** | Bubbletea-powered hacker green/cyan/pink terminal UI. One screen for everything. Scan, pick, attack, watch, regret. |

Implementation is the hybrid kernel-fast-path approach: **nftables** for drops,
**tc + IFB** for throttle, **libpcap** for capture, **AF_PACKET ARP poisoning**
to convince the LAN that the operator's box is the gateway. Two binaries, one
Unix socket, JSON-RPC 2.0, no auth scaffolding (operator-trusted by design —
you're root, you know what you're doing, you live with the consequences).

---

## Quick start

You need a Linux box, root, and these:

```bash
sudo apt install -y libpcap-dev nftables iproute2 iputils-ping
```

Build:

```bash
make build
```

Pick the interface you want to attack — usually your Wi-Fi or Ethernet:

```bash
ip -4 addr show
# look for the one with your LAN IP, e.g. wlp3s0 or enp2s0
```

Fire up the daemon (terminal 1):

```bash
sudo ./bin/shardflowd -i wlp3s0 -sock /tmp/sf.sock --force --clean-on-start
```

Open the dashboard (terminal 2):

```bash
sudo ./bin/shardflow --sock /tmp/sf.sock tui
```

You're now in the matrix. Hit `s` to scan, `j/k` to navigate, `d`/`t`/`p`/`x`
to apply drop / throttle / pcap / clear. `q` to quit and pretend none of this
happened.

---

## Keys

```
j / k         move cursor
s             trigger LAN scan
d             ⊘ DROP — cut this device's traffic
t             ◐ THROTTLE — rate-limit (default 200kbit)
p             ◉ PCAP — start passive capture
x             clear policy (sends corrective ARP)
q             quit
```

---

## "But which device is which?"

The TUI shows IP, MAC, **vendor** (from the IEEE OUI database, ~39k entries),
**hostname** (if the device speaks mDNS or SSDP), and the active policy. So
you'll see things like:

```
192.168.1.10    e4:0d:36:92:84:57   Intel Corporate         het-laptop.local
192.168.1.42    aa:bb:cc:dd:ee:ff   Apple, Inc.             Hets-iPhone.local
192.168.1.50    08:63:32:60:3f:63   IEEE Reg. Authority     —
192.168.1.99    46:05:df:dd:31:89   —                       —
```

If a device shows no vendor (`—`), it's almost always a phone using a
randomized privacy MAC (`02:*` / `06:*` / `0A:*` / `0E:*` / `42:*` / `46:*`).
That's a feature of modern iOS/Android, not a bug in our tool. The vendor is
literally not derivable from the MAC.

If a device shows no hostname, it just isn't broadcasting Bonjour or UPnP.
Most smart-home gear is silent. C'est la vie.

---

## CLI (for the terminal-purist)

If the TUI isn't your thing, every action is reachable via the CLI:

```bash
shardflow --sock /tmp/sf.sock scan
shardflow --sock /tmp/sf.sock devices list           # add --json for jq fans
shardflow --sock /tmp/sf.sock policy set 192.168.1.42 drop
shardflow --sock /tmp/sf.sock policy set 192.168.1.42 throttle 200kbit
shardflow --sock /tmp/sf.sock policy set 192.168.1.42 pcap --pcap-dir /tmp/sf-pcap
shardflow --sock /tmp/sf.sock policy clear 192.168.1.42
shardflow --sock /tmp/sf.sock policy list
shardflow --sock /tmp/sf.sock stats
```

---

## Architecture (one-paragraph version)

`shardflowd` (the daemon, runs as root, manages kernel state) talks to
`shardflow` (the client / CLI / TUI, also runs as root because of the kernel
control plane) over a Unix socket using JSON-RPC 2.0 with bidirectional events.
Eight components inside the daemon: **devicestore** (MAC-keyed map),
**scan** (active ARP + passive + mDNS + SSDP), **arpengine** (the poisoner),
**nftmgr** (drop rules), **tcmgr** (throttle / mirror via tc-flower + HTB +
IFB), **pcapwriter** (rotating pcap-ng), **policycompiler** (the brain that
turns "drop 10.0.99.42" into the right sequence of nft + tc + arp calls),
**rpc** (the wire). Tear it apart in `internal/`. The full design lives at
`docs/superpowers/specs/2026-05-06-shardflow-design.md`.

---

## Tests

15 unit-test packages (race-clean):

```bash
make test    # or: go test ./...
```

4 integration tests in network namespaces (drop, throttle, pcap, recovery) —
need root because they create netns + run nft / tc:

```bash
sudo PATH=$PATH go test -tags=integration ./test/...
```

---

## OUI database refresh

The IEEE OUI list grows. To pull a fresh copy:

```bash
go generate ./internal/oui/...
git add internal/oui/data/oui.txt
git commit -m "chore: refresh OUI db"
```

---

## What this isn't

- **Not stealthy.** ARP poisoning lights up any half-decent IDS like a
  Christmas tree. If you need stealth, you need a different tool.
- **Not for the public internet.** It works at L2; you have to be on the
  same broadcast domain as your target.
- **Not a beginner's lockpick.** Run it on a real network without thinking
  and you will brick the network for everyone on it. Maybe practice in a
  netns first (`test/netns/setup.sh` builds you one).

---

## Wisdom from the trenches

> "ARP is a protocol from 1982 that nobody has fixed because we'd all rather
> patch the symptoms forever than admit our network stack is held together
> with hope and broadcast." — every L2 attacker, ever

Have fun. Don't be evil. Bring snacks.
