package nftmgr

import (
	"net"
	"strconv"
)

const (
	dropTableFamily = "inet"
	dropTableName   = "shardflow"
	dropChainName   = "forward_chain"

	markTableFamily = "netdev"
	markTableName   = "shardflow_ingress"
	markChainName   = "ingress"
)

func argvEnsureDropTable() []string {
	return []string{"add", "table", dropTableFamily, dropTableName}
}

func argvAddDropRule(targetMAC net.HardwareAddr) []string {
	return []string{"add", "rule", dropTableFamily, dropTableName, dropChainName,
		"ether", "saddr", targetMAC.String(), "drop",
		"comment", `"` + commentTagFor(targetMAC) + `"`}
}

// netdev ingress chain MUST be bound to a real iface; the iface name is
// part of the chain definition.
func argvEnsureMarkChain(realIface string) []string {
	return []string{"add", "chain", markTableFamily, markTableName, markChainName,
		"{ type filter hook ingress device " + realIface + " priority 0; policy accept; }"}
}

func argvAddMarkRule(targetMAC net.HardwareAddr, mark uint32) []string {
	return []string{"add", "rule", markTableFamily, markTableName, markChainName,
		"ether", "saddr", targetMAC.String(),
		"meta", "mark", "set", strconv.FormatUint(uint64(mark), 10),
		"comment", `"` + commentTagFor(targetMAC) + `"`}
}

// argvAddReturnMarkRule installs the second mark rule for bidirectional
// policies (pcap). Matches frames sourced from the gateway whose IP
// destination is the target. Tagged with the target MAC's comment so the
// rule is removed alongside its sibling.
func argvAddReturnMarkRule(targetMAC, gwMAC net.HardwareAddr, targetIP net.IP, mark uint32) []string {
	return []string{"add", "rule", markTableFamily, markTableName, markChainName,
		"ether", "saddr", gwMAC.String(),
		"ip", "daddr", targetIP.String(),
		"meta", "mark", "set", strconv.FormatUint(uint64(mark), 10),
		"comment", `"` + commentTagFor(targetMAC) + `"`}
}

func commentTagFor(mac net.HardwareAddr) string { return "shardflow:" + mac.String() }

func argvFlushDropTable() []string  { return []string{"flush", "table", dropTableFamily, dropTableName} }
func argvDeleteDropTable() []string { return []string{"delete", "table", dropTableFamily, dropTableName} }
func argvListDropTable() []string   { return []string{"-a", "list", "table", dropTableFamily, dropTableName} }

func argvFlushMarkTable() []string  { return []string{"flush", "table", markTableFamily, markTableName} }
func argvDeleteMarkTable() []string { return []string{"delete", "table", markTableFamily, markTableName} }
func argvListMarkTable() []string   { return []string{"-a", "list", "table", markTableFamily, markTableName} }
