
<p align="center">
    <picture>
        <img src="https://github.com/user-attachments/assets/9621c7b1-bc37-43e0-bb48-4e4b0be5076e" alt="ShardFlow" width="500">
    </picture>
</p>

# ShardFlow

[![Release](https://img.shields.io/github/v/release/hett-patell/ShardFlow?color=blue)](https://github.com/hett-patell/ShardFlow/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Authorized Use Only](https://img.shields.io/badge/Use-Authorized%20Lab%20Only-red.svg)](#)
[![Go Report Card](https://goreportcard.com/badge/github.com/hett-patell/ShardFlow)](https://goreportcard.com/report/github.com/hett-patell/ShardFlow)

A Layer-2 LAN workbench for people who want to know exactly who's on their network and, optionally, ruin their day.

Finds every device on the wire. Drops them, throttles them, or silently records everything they send. Built for red-team labs, ethics class demos, and anyone whose upstairs neighbour discovered Twitch streaming at midnight.

> ⚠️ **Authorized use only.** This tool ARP-poisons whatever LAN you aim it at. Use it on a network you own, or one where you have explicit written permission from the owner. "I was testing my own router" is not a legal defense. Neither is this README.

---

## What it does

| Capability | What actually happens |
|---|---|
| **Discovery** | Active ARP sweep + passive sniff + mDNS + SSDP + OUI vendor lookup. Finds every device, including the ones being sneaky about it. |
| **Drop** | Cuts a device off from the gateway. They'll spend 20 minutes unplugging and replugging their router before they blame their ISP. |
| **Throttle** | Clamps a target to whatever bitrate you choose. `200kbit` is enough to load Gmail. Eventually. On a good day. |
| **Pcap** | Silently captures their traffic to a rotating `.pcapng`. Open it in Wireshark and feel like a hacker in a movie. |
| **TUI dashboard** | Full terminal UI. Scan the network, pick a target, apply a policy, watch the chaos unfold — all without leaving your chair. |
| **Tunable ARP poisoning** | Default is 1 Hz × 4 frames/cycle, which works on most things. Modern iPhones and hardened Android kernels think they're too good for this, so you can crank it to `50ms` cadence (~80 frames/sec) to keep up. When you clear a policy, the corrective floods 90+ ARP frames in ~3 s to undo the damage. It's a lot. It works. |

Under the hood: **nftables** for drops, **tc + IFB** for throttle, **libpcap** for capture, **AF_PACKET ARP poisoning** to convince the LAN your box is the gateway. Two binaries, one Unix socket, JSON-RPC 2.0. No auth — you're already root, you're already committed.

Full design doc at `docs/superpowers/specs/2026-05-06-shardflow-design.md` if you want to know how the sausage is made.

---

## Quick start

Linux, root, and a functional sense of responsibility. Also these:

```bash
sudo apt install -y libpcap-dev nftables iproute2 iputils-ping
```

Build:

```bash
make build
```

The easy way. One command. No flags, no picking interfaces, no opening two terminals like it's 2003:

```bash
sudo ./scripts/shardflow-up
```

Auto-detects your default interface, starts the daemon, opens the TUI. When you quit, it sends corrective ARPs so every device gets its network back. You're a monster, but a considerate one.

Keys once you're in: `s` to scan, `j/k` to move, `d`/`t`/`p`/`x` to apply or clear a policy, `q` to quit and go touch grass.

Need a specific interface, socket path, or a faster cadence for phones that think they're clever:

```bash
sudo ./scripts/shardflow-up -i wlp3s0 -s /tmp/sf.sock -c 50ms
```

`-c 50ms` fires ~80 ARP frames/sec/target. Use this for iOS 16+, hardened Android, or anything whose kernel refreshes its ARP cache faster than you can poison it.

### The manual way

For when you want to feel more in control, or you're wiring this into systemd and need to pretend it's production infrastructure:

```bash
# terminal 1: daemon
sudo ./bin/shardflowd -i wlp3s0 -sock /tmp/sf.sock --force --clean-on-start

# terminal 2: TUI
sudo ./bin/shardflow --sock /tmp/sf.sock tui
```

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

## Figuring out who's who

The TUI shows IP, MAC, **vendor** (IEEE OUI database, ~39k entries), **hostname** (if the device bothers with mDNS or SSDP), and current policy:

```
192.168.1.10    e4:0d:36:92:84:57   Intel Corporate         het-laptop.local
192.168.1.42    aa:bb:cc:dd:ee:ff   Apple, Inc.             Hets-iPhone.local
192.168.1.50    08:63:32:60:3f:63   IEEE Reg. Authority     —
192.168.1.99    46:05:df:dd:31:89   —                       —
```

No vendor shown? It's using a randomized privacy MAC (`02:*` / `06:*` / `0A:*` / `0E:*` / `42:*` / `46:*`). Modern iOS and Android do this by default. The vendor is genuinely unresolvable — the tool isn't broken, the phone is just paranoid.

No hostname? It's not broadcasting Bonjour or UPnP. Most smart home devices are completely silent. Your smart fridge has better privacy hygiene than your laptop.

---

## CLI

Not a TUI person? Every action works from the command line:

```bash
shardflow --sock /tmp/sf.sock scan
shardflow --sock /tmp/sf.sock devices list           # add --json for jq fans
shardflow --sock /tmp/sf.sock policy set 192.168.1.42 drop
shardflow --sock /tmp/sf.sock policy set 192.168.1.42 throttle 200kbit
shardflow --sock /tmp/sf.sock policy set 192.168.1.42 pcap --pcap-dir /tmp/sf-pcap
shardflow --sock /tmp/sf.sock policy clear 192.168.1.42
shardflow --sock /tmp/sf.sock policy list
shardflow --sock /tmp/sf.sock session                # iface, gw, wifi assoc, scan stats
shardflow --sock /tmp/sf.sock stats                  # --json supported
shardflow --version                                  # also works on shardflowd
```

---

## Architecture

`shardflowd` (daemon, root, owns all kernel state) talks to `shardflow` (CLI / TUI client, also root, no choice) over a Unix socket with JSON-RPC 2.0 and bidirectional events.

Eight components inside the daemon: **devicestore** (MAC-keyed map), **scan** (active ARP + passive + mDNS + SSDP), **arpengine** (the poisoner), **nftmgr** (drop rules), **tcmgr** (throttle / mirror via tc-flower + HTB + IFB), **pcapwriter** (rotating pcap-ng), **policycompiler** (the part that turns "drop 10.0.99.42" into the correct sequence of nft + tc + arp calls without setting anything on fire), **rpc** (the wire).

Source in `internal/`. It's readable. Probably.

---

## Tests

17 unit-test packages, all race-clean:

```bash
make test    # or: go test ./...
go test -race ./...    # if you want the race detector to chew on it
```

4 integration tests in network namespaces — drop, throttle, pcap, and recovery end-to-end. Need root because they create actual netns and invoke nft / tc:

```bash
make test-int    # equivalent: sudo go test -tags=integration -v ./test/...
```

## Local scan sandbox

No LAN handy? Spin up a Linux bridge with N fake netns hosts that auto-reply to ARP. Safe to throttle / drop / poison without disturbing anyone real:

```bash
sudo make lab-up COUNT=16
sudo ./scripts/shardflow-up -i sf-lab0
# press q in the TUI to quit
sudo make lab-down
```

---

## OUI database refresh

The IEEE list grows. Pull a fresh copy when it starts feeling stale:

```bash
go generate ./internal/oui/...
git add internal/oui/data/oui.txt
git commit -m "chore: refresh OUI db"
```

---

## Limitations worth knowing about

**It's not stealthy.** ARP poisoning is loud. Any network with a half-decent IDS will log this immediately. If you need stealth, this is the wrong tool.

**L2 only.** You have to be on the same broadcast domain as your targets. Does not work over the internet, which is probably for the best.

**It will break things if you're careless.** Run it on a network you don't understand and you'll confuse every device on it simultaneously. Practice in a network namespace first — `test/netns/setup.sh` sets one up for you. It takes 30 seconds and will save you from a very awkward conversation.

---

> "ARP is a protocol from 1982 that nobody has fixed because we'd all rather patch the symptoms forever than admit our network stack is held together with hope and broadcast." — every L2 attacker, ever

Have fun. Don't be evil. Bring snacks.

---

## License

MIT - see [LICENSE](LICENSE).

---

## The Shard ecosystem

| Repo | What it does |
|---|---|
| [ShardLure](https://github.com/hett-patell/ShardLure) | SSH honeypot + threat-intel dashboard |
| [ShardC2](https://github.com/hett-patell/ShardC2) | Red-team C2 framework in Go |
| [ShardFlow](https://github.com/hett-patell/ShardFlow) | Layer-2 LAN workbench (ARP, drop, throttle) |
| [ShardShell](https://github.com/hett-patell/ShardShell) | PHP post-exploitation shell |
| [ShardPass](https://github.com/hett-patell/ShardPass) | Minimal TOTP authenticator (Chrome MV3) |
| [ShardPet](https://github.com/hett-patell/ShardPet) | Pixel-Pokémon browser extension |
| [ShardTune](https://github.com/hett-patell/ShardTune) | Spotify controller + listening analytics (Chrome/Brave) |
