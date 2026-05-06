package tcmgr

import "strconv"

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

func argvAddRootHTB(iface string) []string {
	return []string{"qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "ffff"}
}

func argvAddHTBClass(iface, classID, rate string) []string {
	return []string{"class", "add", "dev", iface, "parent", "1:", "classid", classID,
		"htb", "rate", rate, "ceil", rate}
}

func argvDelHTBClass(iface, classID string) []string {
	return []string{"class", "del", "dev", iface, "classid", classID}
}

func argvAddFlowFilterByMark(iface string, mark uint32, classID string) []string {
	return []string{"filter", "add", "dev", iface, "protocol", "all", "parent", "1:",
		"prio", "1", "handle", strconv.FormatUint(uint64(mark), 10), "fw", "flowid", classID}
}

// Ingress qdisc on the real iface — needed before any redirect/mirror
// filter can be attached.
func argvAddIngressQdisc(iface string) []string {
	return []string{"qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"}
}

// Filter that matches src_mac on ingress and redirects matched frames into
// the IFB iface for HTB shaping. Uses flower (which can match L2 fields
// directly) instead of `fw mark` because tc-ingress fires BEFORE the nft
// netdev-ingress hook in the kernel rx path — a fwmark set by nft is not
// yet on the skb when this filter checks it. flower matches the source MAC
// directly, so no mark intermediary is needed.
func argvAddRedirectFilterByMAC(iface, srcMAC, ifb string, prio uint32) []string {
	return []string{"filter", "add", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", strconv.FormatUint(uint64(prio), 10),
		"flower", "src_mac", srcMAC,
		"action", "mirred", "egress", "redirect", "dev", ifb}
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

// Delete a flower filter on the iface ingress qdisc by priority. Each
// target gets a unique prio so this removes only that target's filter.
func argvDelFilterByPrio(iface string, prio uint32) []string {
	return []string{"filter", "del", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", strconv.FormatUint(uint64(prio), 10)}
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
