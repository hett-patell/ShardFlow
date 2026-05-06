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

func TestArgvAddRedirectFilter(t *testing.T) {
	got := argvAddRedirectFilter("eth0", 42, "shardflow0")
	assert.Contains(t, got, "filter")
	assert.Contains(t, got, "fw")
	assert.Contains(t, got, "redirect")
	assert.Contains(t, got, "shardflow0")
}

func TestArgvAddMirrorFilter(t *testing.T) {
	got := argvAddMirrorFilter("eth0", 42, "shardflow-cap")
	assert.Contains(t, got, "mirror")
	assert.Contains(t, got, "shardflow-cap")
}

func TestArgvAddHTBClass(t *testing.T) {
	got := argvAddHTBClass("shardflow0", "1:42", "200kbit")
	assert.Contains(t, got, "class")
	assert.Contains(t, got, "200kbit")
	assert.Contains(t, got, "1:42")
}
