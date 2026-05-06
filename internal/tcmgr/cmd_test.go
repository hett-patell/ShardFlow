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

func TestArgvAddHTBClass(t *testing.T) {
	got := argvAddHTBClass("shardflow0", "1:42", "200kbit")
	assert.Equal(t, []string{
		"class", "add", "dev", "shardflow0", "parent", "1:", "classid", "1:42",
		"htb", "rate", "200kbit", "ceil", "200kbit",
	}, got)
}
