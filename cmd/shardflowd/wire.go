package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/hett-patell/ShardFlow/internal/iface"
)

func preflight(sockPath, realIface string, force, clean bool) error {
	if _, err := os.Stat(sockPath); err == nil {
		if !force {
			return fmt.Errorf("socket %s already exists; another shardflowd running, or pass --force", sockPath)
		}
		_ = os.Remove(sockPath)
	}
	if err := os.MkdirAll(filepathDir(sockPath), 0o700); err != nil {
		return err
	}
	type probe struct {
		name     string
		exists   func() bool
		teardown func()
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
		{realIface + " egress HTB qdisc (orphaned from prior run)",
			func() bool {
				out, err := exec.Command("tc", "qdisc", "show", "dev", realIface).CombinedOutput()
				return err == nil && strings.Contains(string(out), "htb 1:")
			},
			func() { run("tc", "qdisc", "del", "dev", realIface, "root") }},
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
	return writeSysctl("/proc/sys/net/ipv4/ip_forward", v)
}

// sendRedirectsPrev holds the previous sysctl values for restoration on shutdown.
type sendRedirectsPrev struct {
	all, def, iface string
}

// disableSendRedirects turns off ICMP Redirect emission on the operator's
// real iface, the global "all" knob, AND the "default" knob. With redirects
// on, the kernel sees the routed-back-to-itself MITM traffic and helpfully
// tells the victim to bypass us — defeating the policy.
//
// IMPORTANT: We must disable all three:
//   - all:     global override (but doesn't always stick)
//   - default: affects new interfaces and can reset per-iface settings
//   - <iface>: the specific interface we're using
//
// Returns the previous values so the caller can restore them on shutdown.
func disableSendRedirects(realIface string) (prev sendRedirectsPrev, err error) {
	prev.all, err = writeSysctl("/proc/sys/net/ipv4/conf/all/send_redirects", "0")
	if err != nil {
		return prev, fmt.Errorf("disable all send_redirects: %w", err)
	}
	prev.def, err = writeSysctl("/proc/sys/net/ipv4/conf/default/send_redirects", "0")
	if err != nil {
		// Best-effort restore before bubbling.
		_, _ = writeSysctl("/proc/sys/net/ipv4/conf/all/send_redirects", prev.all)
		return prev, fmt.Errorf("disable default send_redirects: %w", err)
	}
	prev.iface, err = writeSysctl("/proc/sys/net/ipv4/conf/"+realIface+"/send_redirects", "0")
	if err != nil {
		// Best-effort restore before bubbling.
		_, _ = writeSysctl("/proc/sys/net/ipv4/conf/all/send_redirects", prev.all)
		_, _ = writeSysctl("/proc/sys/net/ipv4/conf/default/send_redirects", prev.def)
		return prev, fmt.Errorf("disable %s send_redirects: %w", realIface, err)
	}
	return prev, nil
}

func writeSysctl(path, v string) (string, error) {
	prev, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(v+"\n"), 0o644); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(prev)), nil
}

// legacySysctlGet reads numeric strings from the legacy /proc/sys/ tree.
// Differences from writeSysctl: doesn't need to write anything; doesn't
// care about errors (best-effort diagnostic lookup only).
func legacySysctlGet(name string) string {
	out, err := os.ReadFile("/proc/sys/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// resolveGatewayMAC asks the kernel to resolve info.Gateway's MAC by sending
// short UDP datagrams (which force ARP via the normal stack), then polls the
// kernel neighbour table via netlink until an entry appears. Going via the
// kernel is more reliable than crafting the ARP ourselves: in some
// netns/bridge configurations the peer kernel does not respond to ARP
// requests originated from packet sockets, even though it answers
// kernel-originated ARPs. The kick is repeated every 500ms because the
// kernel gives up after three mcast_solicit attempts and parks the
// neighbour entry in FAILED for ~60s — re-triggering forces a fresh
// attempt without waiting that out.
//
// Previous implementation shelled out to `ip -4 neigh show` every poll
// (up to 16 forks per startup). Netlink RTM_GETNEIGH is a single syscall
// per poll, no string parsing, no PATH dependency.
func resolveGatewayMAC(info iface.Info) (net.HardwareAddr, error) {
	link, err := netlink.LinkByName(info.Name)
	if err != nil {
		return nil, fmt.Errorf("netlink link %s: %w", info.Name, err)
	}
	linkIndex := link.Attrs().Index

	if mac, ok := readNeighMAC(linkIndex, info.Gateway); ok {
		return mac, nil
	}
	kick := func() {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: info.Gateway, Port: 9})
		if err == nil {
			_, _ = conn.Write([]byte{0})
			_ = conn.Close()
		}
	}
	kick()
	deadline := time.Now().Add(8 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		if mac, ok := readNeighMAC(linkIndex, info.Gateway); ok {
			return mac, nil
		}
		select {
		case <-ticker.C:
			kick()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, errors.New("timeout resolving gateway MAC via kernel")
}

// readNeighMAC queries the kernel neighbour table via netlink and returns
// the lladdr for gw on the named iface index, if present and not in a
// FAILED/INCOMPLETE state. ok=false when the entry is missing, in a
// non-resolvable state, or has no HardwareAddr yet.
//
// Why iterate NeighList instead of a targeted query: vishvananda/netlink
// doesn't expose a single-IP RTM_GETNEIGH wrapper; NeighList(linkIndex,
// AF_INET) returns the few entries on the iface (typically <10 on a
// home LAN, hundreds at most) so linear scan is faster than the prior
// fork-and-parse path even in the worst case.
func readNeighMAC(linkIndex int, gw net.IP) (net.HardwareAddr, bool) {
	neighs, err := netlink.NeighList(linkIndex, unix.AF_INET)
	if err != nil {
		return nil, false
	}
	gw4 := gw.To4()
	for _, n := range neighs {
		ip4 := n.IP.To4()
		if ip4 == nil || !ip4.Equal(gw4) {
			continue
		}
		// NUD_FAILED / NUD_INCOMPLETE: kernel tried and gave up, or
		// is still trying. Either way the lladdr (if any) is stale.
		if n.State&(unix.NUD_FAILED|unix.NUD_INCOMPLETE) != 0 {
			return nil, false
		}
		if len(n.HardwareAddr) == 6 {
			return append(net.HardwareAddr{}, n.HardwareAddr...), true
		}
	}
	return nil, false
}
