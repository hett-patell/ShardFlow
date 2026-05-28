package tcmgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgvAddIFB(t *testing.T) {
	assert.Equal(t, []string{"link", "add", "shardflow0", "type", "ifb"}, argvAddIFB("shardflow0"))
}

func TestArgvAddDummy(t *testing.T) {
	assert.Equal(t, []string{"link", "add", "shardflow-cap", "type", "dummy"}, argvAddDummy("shardflow-cap"))
}

func TestArgvSetUpLink(t *testing.T) {
	assert.Equal(t, []string{"link", "set", "shardflow0", "up"}, argvSetUp("shardflow0"))
}

func TestArgvAddIngressQdisc(t *testing.T) {
	got := argvAddIngressQdisc("eth0")
	assert.Equal(t, []string{"qdisc", "add", "dev", "eth0", "handle", "ffff:", "ingress"}, got)
}

func TestArgvAddRedirectFilterByMAC(t *testing.T) {
	got := argvAddRedirectFilterByMAC("eth0", "02:00:00:00:99:42", "shardflow0", 42)
	assert.Equal(t, []string{
		"filter", "add", "dev", "eth0", "parent", "ffff:",
		"protocol", "all", "prio", "42",
		"flower", "src_mac", "02:00:00:00:99:42",
		"action", "mirred", "egress", "redirect", "dev", "shardflow0",
	}, got)
}

func TestArgvAddMirrorFilterByMAC(t *testing.T) {
	got := argvAddMirrorFilterByMAC("eth0", "02:00:00:00:99:42", "shardflow-cap", 42)
	assert.Equal(t, []string{
		"filter", "add", "dev", "eth0", "parent", "ffff:",
		"protocol", "all", "prio", "42",
		"flower", "src_mac", "02:00:00:00:99:42",
		"action", "mirred", "egress", "mirror", "dev", "shardflow-cap",
	}, got)
}

func TestArgvAddHTBClassWithBurst(t *testing.T) {
	got := argvAddHTBClass("shardflow0", "1:2a", "200kbit")
	assert.Equal(t, []string{
		"class", "add", "dev", "shardflow0", "parent", "1:", "classid", "1:2a",
		"htb", "rate", "200kbit", "ceil", "200kbit", "burst", "3000b", "cburst", "3000b",
	}, got)
}

func TestArgvAddEgressShapeFilterByMAC(t *testing.T) {
	got := argvAddEgressShapeFilterByMAC("eth0", "02:00:00:00:99:42", "1:2a", 42)
	assert.Equal(t, []string{
		"filter", "add", "dev", "eth0", "protocol", "all", "parent", "1:",
		"prio", "42",
		"flower", "dst_mac", "02:00:00:00:99:42",
		"classid", "1:2a",
	}, got)
}

func TestArgvAddReturnMirrorFilterByMAC(t *testing.T) {
	got := argvAddReturnMirrorFilterByMAC("eth0", "02:00:00:00:99:42", "shardflow-cap", 42)
	assert.Equal(t, []string{
		"filter", "add", "dev", "eth0", "protocol", "all", "parent", "1:",
		"prio", "42",
		"flower", "dst_mac", "02:00:00:00:99:42",
		"action", "mirred", "egress", "mirror", "dev", "shardflow-cap",
	}, got)
}

func TestClassIDForUsesHex(t *testing.T) {
	// mark=11 → hex "b"
	assert.Equal(t, "1:b", classIDFor(11))
	// mark=255 → hex "ff"
	assert.Equal(t, "1:ff", classIDFor(255))
	// mark=16 → hex "10"
	assert.Equal(t, "1:10", classIDFor(16))
}

func TestHtbBurst(t *testing.T) {
	// Low rate: should use min burst of 3000b
	assert.Equal(t, "3000b", htbBurst("10kbit"))
	assert.Equal(t, "3000b", htbBurst("100kbit"))
	
	// Higher rate: should compute rate*10ms
	// 1mbit = 1000kbit → 1000 + 250 = 1250 → still below 3000 → use 3000
	assert.Equal(t, "3000b", htbBurst("1mbit"))
	
	// 10mbit = 10000kbit → 10000 + 2500 = 12500b
	assert.Equal(t, "12500b", htbBurst("10mbit"))
	
	// Invalid: should return default
	assert.Equal(t, "15k", htbBurst("invalid"))
}
