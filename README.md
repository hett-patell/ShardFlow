# ShardFlow

Linux Layer-2 LAN workbench for authorized pentesting and lab use.

See `docs/superpowers/specs/2026-05-06-shardflow-design.md` for the full design.

## Building

    go build ./...

## Running

Requires `CAP_NET_RAW` and `CAP_NET_ADMIN` for `shardflowd`. See the spec for
details.
