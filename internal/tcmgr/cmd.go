package tcmgr

import (
	"fmt"
	"strconv"
)

func argvAddIFB(name string) []string {
	return []string{"link", "add", name, "type", "ifb"}
}

func argvAddDummy(name string) []string {
	return []string{"link", "add", name, "type", "dummy"}
}

func argvSetUp(name string) []string {
	return []string{"link", "set", name, "up"}
}

func argvDelLink(name string) []string {
	return []string{"link", "del", name}
}

// argvAddRootHTB attaches an HTB root qdisc to iface. `default ffff` directs
// unclassified traffic to a default class 1:ffff which MUST be created
// separately via argvAddDefaultHTBClass — otherwise unclassified traffic
// (including the host's own traffic on the real iface) gets dropped.
//
// We use `replace` instead of `add` to handle pre-existing root qdiscs
// (e.g. `noqueue` on wireless ifaces, `fq_codel` on wired). Replace is
// atomic and idempotent.
func argvAddRootHTB(iface string) []string {
	return []string{"qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb", "default", "ffff"}
}

// argvAddDefaultHTBClass creates the catch-all class for traffic that
// doesn't match any per-target filter. Set to 10gbit (effectively
// unlimited) so the host's own traffic passes through unaffected when
// the daemon is running but no throttle policies are active.
func argvAddDefaultHTBClass(iface string) []string {
	return []string{"class", "add", "dev", iface, "parent", "1:", "classid", "1:ffff",
		"htb", "rate", "10gbit", "ceil", "10gbit", "burst", "1m", "cburst", "1m"}
}

// argvAddHTBClass adds a leaf class with rate==ceil (no borrowing) and an
// explicit burst tuned for the rate. Without burst, the kernel auto-computes
// `rate/HZ` which at low rates can be below MTU — the class then cannot
// dequeue a full-size packet and the effective rate drifts.
//
// Burst formula: max(2 MTU = 3000 bytes, rate*10ms). 10ms is enough to
// absorb scheduler jitter; the MTU floor keeps the class functional at
// kbit-class rates.
func argvAddHTBClass(iface, classID, rate string) []string {
	burst := htbBurst(rate)
	return []string{"class", "add", "dev", iface, "parent", "1:", "classid", classID,
		"htb", "rate", rate, "ceil", rate, "burst", burst, "cburst", burst}
}

// htbBurst returns a sensible burst size for the given rate. Inputs are
// the tc rate string (e.g. "200kbit", "1mbit"). Falls back to "15k" on
// parse failure — a sane mid-range default.
func htbBurst(rate string) string {
	// Strip the unit suffix and convert to kbit.
	var n int
	var unit string
	if _, err := fmt.Sscanf(rate, "%d%s", &n, &unit); err != nil {
		return "15k"
	}
	var kbits int
	switch unit {
	case "kbit":
		kbits = n
	case "mbit":
		kbits = n * 1000
	case "gbit":
		kbits = n * 1000 * 1000
	case "bit":
		kbits = n / 1000
	default:
		return "15k"
	}
	// rate*10ms in bytes = kbits * 1000 / 8 * 10/1000 = kbits * 1.25
	bytes := kbits + kbits/4 // == kbits * 1.25
	const minBurst = 3000    // 2 MTU
	if bytes < minBurst {
		bytes = minBurst
	}
	return strconv.Itoa(bytes) + "b"
}

func argvDelHTBClass(iface, classID string) []string {
	return []string{"class", "del", "dev", iface, "classid", classID}
}

// Ingress qdisc on the real iface — needed before any redirect/mirror
// filter can be attached.
func argvAddIngressQdisc(iface string) []string {
	return []string{"qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"}
}

// argvAddEgressHTB attaches an HTB root qdisc to the egress (root) side
// of the real iface. We need this to throttle DOWNLOAD traffic: packets
// coming from the gateway, forwarded by our kernel, exit through the real
// iface's egress queue. `default ffff` routes unclassified traffic to a
// default class 1:ffff which MUST be created via argvAddDefaultHTBClass.
//
// Uses `replace` to handle pre-existing root qdiscs (noqueue on wireless,
// fq_codel on wired) safely.
func argvAddEgressHTB(iface string) []string {
	return []string{"qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb", "default", "ffff"}
}

func argvDelEgressHTB(iface string) []string {
	return []string{"qdisc", "del", "dev", iface, "root"}
}

// Filter that matches src_mac on ingress and redirects matched frames into
// the IFB iface for HTB shaping (UPLOAD throttle: victim → internet).
// Uses flower because tc-ingress fires BEFORE the nft netdev-ingress hook,
// so an nft-set fwmark isn't on the skb yet — flower matches L2 directly.
func argvAddRedirectFilterByMAC(iface, srcMAC, ifb string, prio uint32) []string {
	return []string{"filter", "add", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", strconv.FormatUint(uint64(prio), 10),
		"flower", "src_mac", srcMAC,
		"action", "mirred", "egress", "redirect", "dev", ifb}
}

// argvAddEgressShapeFilterByMAC matches dst_mac on the real iface's egress
// (root) qdisc and directs matching frames into an HTB class for shaping
// (DOWNLOAD throttle: gateway → victim, after our kernel forwards).
//
// This pairs with the ingress-side filter to enforce throttle bidirectionally:
// ingress side caps the victim's upload (frames leaving the victim),
// egress side caps the victim's download (frames our kernel forwards
// toward the victim's MAC).
func argvAddEgressShapeFilterByMAC(iface, dstMAC, classID string, prio uint32) []string {
	return []string{"filter", "add", "dev", iface, "protocol", "all", "parent", "1:",
		"prio", strconv.FormatUint(uint64(prio), 10),
		"flower", "dst_mac", dstMAC,
		"classid", classID}
}

// Mirror filter that matches src_mac on ingress and copies matched frames
// to the capture dummy iface (so pcapwriter sees them). Same flower-vs-fw
// rationale as argvAddRedirectFilterByMAC.
func argvAddMirrorFilterByMAC(iface, srcMAC, dummy string, prio uint32) []string {
	return []string{"filter", "add", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", strconv.FormatUint(uint64(prio), 10),
		"flower", "src_mac", srcMAC,
		"action", "mirred", "egress", "mirror", "dev", dummy}
}

// argvAddReturnMirrorFilterByMAC mirrors frames whose dst_mac is the
// victim, on the egress (root) side of the real iface. Pairs with the
// ingress src_mac mirror filter so pcap captures both directions of
// the victim's traffic.
func argvAddReturnMirrorFilterByMAC(iface, dstMAC, dummy string, prio uint32) []string {
	return []string{"filter", "add", "dev", iface, "protocol", "all", "parent", "1:",
		"prio", strconv.FormatUint(uint64(prio), 10),
		"flower", "dst_mac", dstMAC,
		"action", "mirred", "egress", "mirror", "dev", dummy}
}

// Delete a flower filter on the iface ingress qdisc by priority. Each
// target gets a unique prio so this removes only that target's filter.
func argvDelFilterByPrio(iface string, prio uint32) []string {
	return []string{"filter", "del", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", strconv.FormatUint(uint64(prio), 10)}
}

// argvDelEgressFilterByPrio deletes a filter on the real iface's root
// (egress) qdisc by priority.
func argvDelEgressFilterByPrio(iface string, prio uint32) []string {
	return []string{"filter", "del", "dev", iface, "parent", "1:",
		"protocol", "all", "prio", strconv.FormatUint(uint64(prio), 10)}
}

// Delete the ingress qdisc on the real iface. Removes every filter that
// was ever attached to it, so callers must clear per-target filters first
// only if they need to inspect them.
func argvDelIngressQdisc(iface string) []string {
	return []string{"qdisc", "del", "dev", iface, "ingress"}
}

// Flower classifier on the IFB qdisc that directs frames matching src_mac
// into a specific HTB class. `classid <id>` is the classifier directive
// (no `action ok` — that would treat this as an action chain rather than
// a classifier and cause flowid to be silently ignored, leaving traffic
// to fall through to the default class which is not created).
func argvAddFlowFilterByMAC(ifb, srcMAC, classID string, prio uint32) []string {
	return []string{"filter", "add", "dev", ifb, "protocol", "all", "parent", "1:",
		"prio", strconv.FormatUint(uint64(prio), 10),
		"flower", "src_mac", srcMAC,
		"classid", classID}
}

// Delete the IFB-side flower filter for a given priority.
func argvDelFlowFilterByPrio(ifb string, prio uint32) []string {
	return []string{"filter", "del", "dev", ifb, "protocol", "all", "parent", "1:",
		"prio", strconv.FormatUint(uint64(prio), 10)}
}
