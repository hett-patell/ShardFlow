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
