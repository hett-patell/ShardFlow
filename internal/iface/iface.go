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

// Lookup returns Info for the named interface. On success, IP and IPNet are
// always non-nil — Lookup returns an error if the interface has no IPv4
// address. The Gateway field is populated by parsing `ip route show
// default`; if that fails, Gateway is nil and the caller is expected to
// handle it (Gateway is best-effort, IP/IPNet are required).
//
// Address selection: an iface can carry several IPv4 addresses (DHCP
// primary plus IPv4LL autoconf, secondaries from `ip addr add`, kernel
// admin addresses on lo, etc). The order returned by netIf.Addrs() is
// arbitrary, so we score and pick:
//   - skip 0.0.0.0 (unspecified)
//   - skip 169.254.0.0/16 (link-local, autoconf fallback)
//   - prefer the loopback canonical 127.0.0.1 when scanning lo
//   - otherwise take the first non-skipped address
//
// Rationale: on a host with a routable address AND a stale link-local
// secondary, the previous "first non-nil ip4" picked whichever the
// kernel happened to return first, which on some systems was the
// link-local — leading to a daemon that bound the wrong source IP for
// ARP sweeps. Sorting/scoring is one-pass O(N) so cost is irrelevant.
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

	type cand struct {
		ip   net.IP
		mask net.IPMask
	}
	var best cand
	bestScore := -1
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		// 0.0.0.0 is never useful; reject outright.
		if ip4.IsUnspecified() {
			continue
		}
		// Score:
		//   3  loopback canonical 127.0.0.1 on lo
		//   2  routable non-link-local (e.g. 192.168.1.42, 10.0.0.5)
		//   1  any other private/loopback address
		//   0  link-local 169.254/16 (last resort only)
		score := 1
		switch {
		case ip4.IsLinkLocalUnicast():
			score = 0
		case name == "lo" && ip4.Equal(net.IPv4(127, 0, 0, 1)):
			score = 3
		case !ip4.IsLoopback():
			score = 2
		}
		if score > bestScore {
			bestScore = score
			best = cand{ip: ip4, mask: ipnet.Mask}
		}
	}
	if bestScore < 0 {
		return Info{}, fmt.Errorf("iface %s: no IPv4 address", name)
	}
	info.IP = best.ip
	info.IPNet = &net.IPNet{IP: best.ip, Mask: best.mask}
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
