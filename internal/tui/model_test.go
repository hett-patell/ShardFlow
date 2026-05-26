package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/assert"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func TestScanningStateShowsInStatusBar(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.width, m.height = 130, 50
	m.scanning = true
	m.scanStarted = time.Now().Add(-2 * time.Second)
	view := m.View()
	visible := stripANSI(view)
	assert.Contains(t, visible, "scanning", "scanning state must show in status bar")
	assert.Contains(t, visible, "(2s)", "elapsed seconds must show")
}

func TestModelHandlesQuit(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	assert.NotNil(t, cmd)
}

// TestCtrlCQuitsFromAnyState guards a real usability bug: in v1, the
// filter-mode branch of Update returned (m, nil) for any key it didn't
// recognise — including Ctrl+C — leaving the operator with no quit
// keystroke until they pressed Esc to drop filter mode first. Now
// Ctrl+C is handled at the top of the KeyMsg switch and works from
// every state.
func TestCtrlCQuitsFromAnyState(t *testing.T) {
	// From nav mode.
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	assert.NotNil(t, cmd, "Ctrl+C must return a quit command from nav mode")

	// From filter mode (the original bug).
	m = newModel(nil, 200, "/var/lib/shardflow/pcap")
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	if !assert.True(t, m.filterMode, "precondition: must be in filter mode") {
		return
	}
	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	assert.NotNil(t, cmd, "Ctrl+C must return a quit command from filter mode")

	// From help overlay.
	m = newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.showHelp = true
	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	assert.NotNil(t, cmd, "Ctrl+C must return a quit command with help overlay open")
}

func TestModelMovesSelectionDownUp(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.devices = []deviceRow{{ip: "10.0.0.42"}, {ip: "10.0.0.55"}}
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	assert.Equal(t, 1, m.cursor)
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	assert.Equal(t, 0, m.cursor)
}

func TestFilterMatchesIPAndHostname(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.devices = []deviceRow{
		{ip: "10.0.0.1", hostname: "router.local"},
		{ip: "10.0.0.42", hostname: "het-laptop.local"},
		{ip: "10.0.0.55", hostname: "phone.local"},
	}
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	assert.True(t, m.filterMode)
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("laptop")})
	vis := m.visibleDevices()
	if assert.Len(t, vis, 1) {
		assert.Equal(t, "het-laptop.local", vis[0].hostname)
	}
}

func TestEscClearsFilter(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.devices = []deviceRow{{ip: "10.0.0.1"}, {ip: "10.0.0.42"}}
	m.filter = "10.0.0.42"
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyEsc})
	assert.Equal(t, "", m.filter)
	assert.Len(t, m.visibleDevices(), 2)
}

func TestHelpToggle(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.width, m.height = 140, 60
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	assert.True(t, m.showHelp)
	visible := stripANSI(m.View())
	assert.Contains(t, visible, "HELP", "help panel must render after [?]")
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	assert.False(t, m.showHelp)
}

func TestArrowKeysMoveCursor(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.devices = []deviceRow{{ip: "10.0.0.1"}, {ip: "10.0.0.2"}, {ip: "10.0.0.3"}}
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyDown})
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyDown})
	assert.Equal(t, 2, m.cursor)
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyHome})
	assert.Equal(t, 0, m.cursor)
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyEnd})
	assert.Equal(t, 2, m.cursor)
}

func TestPolicyKeysActOnFilteredCursor(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.client = nil // applyPolicyCmd captures m.client; we just need it not to panic on creation
	m.devices = []deviceRow{
		{ip: "10.0.0.1", hostname: "router.local"},
		{ip: "10.0.0.42", hostname: "het-laptop.local"},
	}
	m.filter = "router"
	// cursor starts at 0; with filter, that maps to the first matching
	// row in visibleDevices(). Press D — applyPolicyCmd captures
	// vis[m.cursor].ip, which must be the filtered row, not m.devices[0].
	// We can't easily inspect the closure's captured target without
	// running the command, so just assert cursor stays valid for the
	// filtered list.
	vis := m.visibleDevices()
	assert.Len(t, vis, 1)
	assert.Equal(t, "10.0.0.1", vis[0].ip)
	_, cmd := m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	assert.NotNil(t, cmd, "D on a non-empty filtered list must produce an applyPolicy cmd")
}

func TestViewportScrollsForLongList(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.width, m.height = 140, 30 // small height -> tight viewport
	for i := 0; i < 50; i++ {
		m.devices = append(m.devices, deviceRow{ip: fmt.Sprintf("10.0.0.%d", i+1)})
	}
	// PageDown a couple times — viewportOffset should advance.
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyPgDown})
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyPgDown})
	assert.Greater(t, m.viewportOffset, 0, "viewport must scroll on PgDn")
	// End jumps to last row; viewport must include cursor.
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyEnd})
	assert.Equal(t, 49, m.cursor)
	height := m.devicesViewportHeight()
	assert.GreaterOrEqual(t, m.cursor, m.viewportOffset)
	assert.Less(t, m.cursor, m.viewportOffset+height)
}

// TestVisibleDevicesMemoised asserts that repeated visibleDevices() calls
// with no intervening filter/devices mutation return the same backing
// slice. The cache is the whole point: a render frame calls this from
// View → renderStatusBar, renderDevicesPanel, renderTargetPanel, and
// without the memo each call rescans + lowercases the whole list.
func TestVisibleDevicesMemoised(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.devices = []deviceRow{
		{ip: "10.0.0.1", hostname: "router.local"},
		{ip: "10.0.0.42", hostname: "het-laptop.local"},
		{ip: "10.0.0.55", hostname: "phone.local"},
	}
	m.filter = "laptop"
	a := m.visibleDevices()
	b := m.visibleDevices()
	// Same backing array = cache hit. Comparing slice headers via a[0] address.
	if len(a) == 0 || len(b) == 0 {
		t.Fatalf("expected non-empty filter result, got len(a)=%d len(b)=%d", len(a), len(b))
	}
	assert.Same(t, &a[0], &b[0], "second call must reuse cached slice")

	// Mutate filter → next call must recompute (different backing array
	// is expected since the filter result changed).
	m.filter = "router"
	m.invalidateVisible()
	c := m.visibleDevices()
	assert.Len(t, c, 1)
	assert.Equal(t, "router.local", c[0].hostname)
}

// TestVisibleDevicesEmptyFilterCached asserts that the empty-filter
// fast path (return m.devices directly) is also memoised — the second
// call mustn't be confused by the nil-vs-empty distinction.
func TestVisibleDevicesEmptyFilterCached(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.devices = []deviceRow{{ip: "10.0.0.1"}}
	a := m.visibleDevices()
	b := m.visibleDevices()
	assert.Equal(t, len(a), len(b))
	assert.Same(t, &a[0], &b[0])
}

// TestVisibleDevicesEmptyResultStillCached covers the case where a
// filter matches nothing — the result is a non-nil empty slice and the
// next call must still hit the memo rather than re-running the scan.
func TestVisibleDevicesEmptyResultStillCached(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.devices = []deviceRow{{ip: "10.0.0.1"}, {ip: "10.0.0.42"}}
	m.filter = "no-match-string"
	a := m.visibleDevices()
	assert.Empty(t, a)
	stamp := m.visibleCacheStamp
	_ = m.visibleDevices()
	assert.Equal(t, stamp, m.visibleCacheStamp, "second empty-result call must not bump cache stamp")
}

func TestRenderedViewFitsTerminalWidth(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.width, m.height = 250, 50
	m.devices = []deviceRow{
		{ip: "192.168.1.1", mac: "08:63:32:60:3f:63", vendor: "IEEE Reg. Authority", hostname: "router.local", policy: ""},
		{ip: "192.168.1.6", mac: "22:53:a5:32:06:6b", vendor: "", hostname: "", policy: "drop"},
		{ip: "192.168.1.10", mac: "e4:0d:36:92:84:57", vendor: "Intel Corporate", hostname: "het-laptop.local", policy: "throttle 200kbit"},
	}
	m.session = rpc.SessionDTO{
		Iface: "wlan0", IP: "192.168.1.42", CIDR: "192.168.1.42/24",
		Gateway: "192.168.1.1", GwMAC: "08:63:32:60:3f:63",
		Wireless: true, SSID: "HomeWiFi-5G", BSSID: "08:63:32:60:3f:63",
		SignalDBm: -52, TxRateMbit: 130.0, FreqMHz: 5180,
	}
	view := m.View()
	t.Logf("\n%s\n", view)
	// Dashboard now caps at maxRenderWidth (200) regardless of terminal width.
	for i, line := range strings.Split(view, "\n") {
		visible := stripANSI(line)
		if w := lipgloss.Width(visible); w > 205 {
			t.Errorf("line %d width %d exceeds 205 (cap is 200): %q", i, w, visible)
		}
	}
}

func stripANSI(s string) string {
	out := []byte{}
	in := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\x1b' {
			in = true
			continue
		}
		if in {
			if s[i] == 'm' {
				in = false
			}
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}
