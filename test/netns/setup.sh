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
  local name=$1 ip=$2 veth_outer=$3 veth_inner=$4 inner_mac=$5
  ip netns add "$name"
  ip link add "$veth_outer" type veth peer name "$veth_inner"
  ip link set "$veth_inner" netns "$name"
  ip link set "$veth_outer" netns "$BR_NS"
  ip -n "$BR_NS" link set "$veth_outer" master "$BR"
  ip -n "$BR_NS" link set "$veth_outer" up
  ip -n "$name" link set "$veth_inner" address "$inner_mac"
  ip -n "$name" addr add "$ip"/24 dev "$veth_inner"
  ip -n "$name" link set lo up
  ip -n "$name" link set "$veth_inner" up
}

# Explicit MACs avoid the flakiness we saw when the kernel handed out
# pseudo-random veth MACs that happened to repeat across runs and broke
# kernel-ARP resolution from lab-op.
create_node lab-gw  10.0.99.1  lab-veth-gw  eth0 02:00:00:00:99:01
create_node lab-vic 10.0.99.42 lab-veth-vic eth0 02:00:00:00:99:42
create_node lab-op  10.0.99.5  lab-veth-op  eth0 02:00:00:00:99:05

ip -n lab-vic route add default via 10.0.99.1
ip -n lab-op route add default via 10.0.99.1

echo "lab namespaces ready: gw=10.0.99.1 vic=10.0.99.42 op=10.0.99.5"
