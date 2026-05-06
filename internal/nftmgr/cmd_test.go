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
