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

// Filter that matches fwmark on ingress and redirects matched frames into
// the IFB iface for HTB shaping.
func argvAddRedirectFilter(iface string, mark uint32, ifb string) []string {
	return []string{"filter", "add", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", "1",
		"handle", strconv.FormatUint(uint64(mark), 10), "fw",
		"action", "mirred", "egress", "redirect", "dev", ifb}
}

// Filter that matches fwmark on ingress and mirrors matched frames to a
// dummy iface that pcapwriter reads. Mirror (not redirect) so the original
// frame still flows.
func argvAddMirrorFilter(iface string, mark uint32, dummy string) []string {
	return []string{"filter", "add", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", "2",
		"handle", strconv.FormatUint(uint64(mark), 10), "fw",
		"action", "mirred", "egress", "mirror", "dev", dummy}
}

// Delete all fw-handle filters for a given mark on the iface ingress.
func argvDelFilterByMark(iface string, mark uint32, prio string) []string {
	return []string{"filter", "del", "dev", iface, "parent", "ffff:",
		"protocol", "all", "prio", prio,
		"handle", strconv.FormatUint(uint64(mark), 10), "fw"}
}

// Delete the IFB-side fw-handle flow filter that maps fwmark → HTB class.
// Used by ClearThrottle so SetThrottle's filter doesn't accumulate on
// shardflow0 across set/clear cycles.
func argvDelFlowFilterByMark(iface string, mark uint32) []string {
	return []string{"filter", "del", "dev", iface, "protocol", "all", "parent", "1:",
		"prio", "1", "handle", strconv.FormatUint(uint64(mark), 10), "fw"}
}
