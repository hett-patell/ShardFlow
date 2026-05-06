#!/usr/bin/env bash
set -euo pipefail
for n in lab-gw lab-vic lab-op lab-bridge; do
  ip netns del "$n" 2>/dev/null || true
done
ip link del lab-veth-gw 2>/dev/null || true
ip link del lab-veth-vic 2>/dev/null || true
ip link del lab-veth-op 2>/dev/null || true
echo "lab namespaces removed"
