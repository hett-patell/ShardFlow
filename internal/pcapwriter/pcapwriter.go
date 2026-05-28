// Package pcapwriter writes per-target pcap-ng files from libpcap on the
// shardflow-cap dummy iface, with a per-target BPF filter so concurrent
// pcap policies don't cross-contaminate each other's files. Rotates by
// size or age, and enforces a retention policy (max files per target).
package pcapwriter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Defaults from spec §11.
const (
	DefaultMaxBytes = 100 * 1024 * 1024 // 100 MB
	DefaultMaxAge   = 15 * time.Minute
	DefaultMaxFiles = 10                // retain at most 10 files per target (~1GB max)
)

// Manager owns one pcap writer goroutine per target MAC.
type Manager struct {
	mu      sync.Mutex
	writers map[string]*writer
}

type writer struct {
	mac      string
	dir      string
	cancel   context.CancelFunc
	finished chan struct{}
}

// New returns an empty Manager.
func New() *Manager { return &Manager{writers: map[string]*writer{}} }

// Open starts capturing for mac. Frames are pulled from libpcap on
// srcIface (the shardflow-cap dummy iface fed by tc act_mirred), filtered
// by a per-target BPF expression so concurrent pcap policies don't
// cross-contaminate each other's files, and written to rotating pcap-ng
// files under dir. Open blocks until libpcap is open and the first
// pcap-ng file has been created — an error here means "capture is not
// running"; nil means the policy is durably applied.
//
// Identity must include both the target's MAC (for egress: target→gateway)
// and the target's IP (for return: gateway→target). The two arguments
// together compose the BPF: `ether src <mac> or ip dst <ip>`.
func (m *Manager) Open(mac, ipStr, srcIface, dir string, maxBytes int64, maxAge time.Duration) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}

	ctx, cancel := context.WithCancel(context.Background())
	w := &writer{mac: mac, dir: dir, cancel: cancel, finished: make(chan struct{})}

	// Stake the slot under the mutex BEFORE spawning, so a duplicate Open
	// for the same MAC is rejected without leaking a goroutine/handle/file.
	m.mu.Lock()
	if _, exists := m.writers[mac]; exists {
		m.mu.Unlock()
		cancel()
		return fmt.Errorf("pcapwriter: already capturing %s", mac)
	}
	m.writers[mac] = w
	m.mu.Unlock()

	startup := make(chan error, 1)
	go func() {
		defer close(w.finished)
		// Recover panics from libpcap or pcapgo (rare but possible
		// under unusual link types or kernel-version skew). Without
		// this, a panic before runWriter sends on `startup` would
		// leave Open blocked forever waiting on the channel.
		defer func() {
			if r := recover(); r != nil {
				select {
				case startup <- fmt.Errorf("pcapwriter panic: %v", r):
				default:
				}
			}
		}()
		_ = runWriter(ctx, mac, ipStr, srcIface, dir, maxBytes, maxAge, startup)
	}()
	if err := <-startup; err != nil {
		// Roll back the staked slot on startup failure.
		m.mu.Lock()
		delete(m.writers, mac)
		m.mu.Unlock()
		cancel()
		<-w.finished
		return err
	}
	return nil
}

func (m *Manager) Close(mac string) error {
	m.mu.Lock()
	w, ok := m.writers[mac]
	delete(m.writers, mac)
	m.mu.Unlock()
	if !ok {
		return nil
	}
	w.cancel()
	<-w.finished
	return nil
}

// CloseAll cancels every active writer and waits for its goroutine to
// exit. Called by the daemon on shutdown so pcap-ng buffers are flushed
// rather than truncated when the process exits.
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	macs := make([]string, 0, len(m.writers))
	for mac := range m.writers {
		macs = append(macs, mac)
	}
	m.mu.Unlock()
	for _, mac := range macs {
		_ = m.Close(mac)
	}
	return nil
}

func runWriter(ctx context.Context, mac, ipStr, srcIface, dir string, maxBytes int64, maxAge time.Duration, startup chan<- error) error {
	handle, err := pcap.OpenLive(srcIface, 65536, true, pcap.BlockForever)
	if err != nil {
		startup <- fmt.Errorf("pcap open %s: %w", srcIface, err)
		return err
	}
	defer handle.Close()
	// Per-target BPF: capture egress (frames from target's MAC) AND
	// return direction (frames whose IP destination is the target). This
	// keeps multiple concurrent pcap policies separate even though they
	// all read from the same shardflow-cap dummy iface.
	bpf := fmt.Sprintf("ether src %s or ip dst %s", mac, ipStr)
	if err := handle.SetBPFFilter(bpf); err != nil {
		startup <- fmt.Errorf("bpf %q: %w", bpf, err)
		return err
	}

	open := func() (*os.File, *pcapgo.NgWriter, rotation, error) {
		path := nextFilename(dir, mac, time.Now())
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, nil, rotation{}, err
		}
		w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
		if err != nil {
			_ = f.Close()
			return nil, nil, rotation{}, err
		}
		// Enforce retention policy: delete oldest files if over limit.
		enforceRetention(dir, mac, DefaultMaxFiles)
		return f, w, rotation{maxBytes: maxBytes, maxAge: maxAge, started: time.Now()}, nil
	}
	f, w, r, err := open()
	if err != nil {
		startup <- err
		return err
	}
	defer f.Close()
	startup <- nil // signal Open() that capture is running

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	// `written` tracks payload bytes only; pcap-ng framing adds ~28 bytes per
	// packet plus fixed headers, so the on-disk file may exceed maxBytes by a
	// small margin. v1 treats maxBytes as advisory; tightening to a hard cap
	// would require querying the file offset on each rotation check.
	var written int64
	for {
		select {
		case <-ctx.Done():
			_ = w.Flush()
			return nil
		case pkt, ok := <-src.Packets():
			if !ok {
				_ = w.Flush()
				return nil
			}
			data := pkt.Data()
			if r.shouldRotate(written) {
				_ = w.Flush()
				_ = f.Close()
				f, w, r, err = open()
				if err != nil {
					return err
				}
				written = 0
			}
			if err := w.WritePacket(pkt.Metadata().CaptureInfo, data); err != nil {
				_ = w.Flush()
				return err
			}
			written += int64(len(data))
		}
	}
}

// enforceRetention deletes oldest pcap files for the given MAC if there are
// more than maxFiles. Files are identified by the MAC prefix pattern.
func enforceRetention(dir, mac string, maxFiles int) {
	macSafe := strings.ReplaceAll(mac, ":", "-")
	pattern := filepath.Join(dir, macSafe+"-*.pcapng")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) <= maxFiles {
		return
	}
	// Sort by name (which includes timestamp, so lexicographic = chronological).
	sort.Strings(matches)
	// Delete oldest files until we're at maxFiles.
	toDelete := len(matches) - maxFiles
	for i := 0; i < toDelete; i++ {
		_ = os.Remove(matches[i])
	}
}
