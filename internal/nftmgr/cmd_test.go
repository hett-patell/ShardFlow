package nftmgr

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgvEnsureDropTable(t *testing.T) {
	assert.Equal(t, []string{"add", "table", "inet", "shardflow"}, argvEnsureDropTable())
}

func TestArgvEnsureMarkChainBindsToIface(t *testing.T) {
	got := argvEnsureMarkChain("eth0")
	assert.Contains(t, got, "ingress")
	assert.Contains(t, got[len(got)-1], "device eth0")
}

func TestArgvAddDropRule(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	got := argvAddDropRule(mac)
	assert.Equal(t, []string{
		"add", "rule", "inet", "shardflow", "forward_chain",
		"ether", "saddr", "aa:bb:cc:dd:ee:01", "drop",
		"comment", `"shardflow:aa:bb:cc:dd:ee:01"`,
	}, got)
}

func TestArgvAddMarkRule(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	got := argvAddMarkRule(mac, 42)
	assert.Equal(t, []string{
		"add", "rule", "netdev", "shardflow_ingress", "ingress",
		"ether", "saddr", "aa:bb:cc:dd:ee:01",
		"meta", "mark", "set", "42",
		"comment", `"shardflow:aa:bb:cc:dd:ee:01"`,
	}, got)
}

type fakeRunner struct {
	calls   [][]string
	scripts []string
}

func (f *fakeRunner) Run(_ context.Context, args []string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{}, args...))
	return nil, nil
}

func (f *fakeRunner) RunScript(_ context.Context, s string) ([]byte, error) {
	f.scripts = append(f.scripts, s)
	return nil, nil
}

func TestManagerEnsureTablesPipesAtomicScript(t *testing.T) {
	f := &fakeRunner{}
	m := NewWithRunner(f)
	require.NoError(t, m.EnsureTables(context.Background(), "eth0"))
	require.Len(t, f.scripts, 1)
	s := f.scripts[0]
	assert.Contains(t, s, "add table inet shardflow")
	assert.Contains(t, s, "add table netdev shardflow_ingress")
	assert.Contains(t, s, "device eth0")
}

func TestParseRuleHandlesForMAC(t *testing.T) {
	out := []byte(`table inet shardflow {
	chain forward_chain {
		ether saddr aa:bb:cc:dd:ee:01 drop comment "shardflow:aa:bb:cc:dd:ee:01" # handle 7
		ether saddr aa:bb:cc:dd:ee:02 drop comment "shardflow:aa:bb:cc:dd:ee:02" # handle 8
		ether saddr aa:bb:cc:dd:ee:03 drop comment "user-note about shardflow:aa:bb:cc:dd:ee:01 deployment" # handle 9
	}
}
`)
	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")

	// mac1 should match exactly one rule (handle 7) — NOT handle 9, whose
	// comment merely mentions "shardflow:aa:bb:cc:dd:ee:01" inside other text.
	got1 := parseRuleHandlesForMAC(out, mac1)
	assert.Equal(t, []string{"7"}, got1)

	got2 := parseRuleHandlesForMAC(out, mac2)
	assert.Equal(t, []string{"8"}, got2)

	// Unknown MAC returns no handles.
	mac9, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	assert.Empty(t, parseRuleHandlesForMAC(out, mac9))
}
