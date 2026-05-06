# ShardFlow

Linux Layer-2 LAN workbench for authorized pentesting and lab use.

See `docs/superpowers/specs/2026-05-06-shardflow-design.md` for the full design.

## Building

    go build ./...

## Running

Requires `CAP_NET_RAW` and `CAP_NET_ADMIN` for `shardflowd`. See the spec for
details.

## Regenerating the OUI database

The OUI vendor database is embedded at build time. To refresh it from
IEEE's source:

    go generate ./internal/oui/...

Commit the resulting `internal/oui/data/oui.txt`.
