package pcapwriter

import (
	"path/filepath"
	"strings"
	"time"
)

type rotation struct {
	maxBytes int64
	maxAge   time.Duration
	started  time.Time
}

func (r rotation) shouldRotate(bytesWritten int64) bool {
	if bytesWritten >= r.maxBytes {
		return true
	}
	if time.Since(r.started) >= r.maxAge {
		return true
	}
	return false
}

func nextFilename(dir, mac string, when time.Time) string {
	macSafe := strings.ReplaceAll(mac, ":", "-")
	// Format includes nanoseconds (.000000000) so a high-throughput target
	// rotating multiple files within a single second never collides on the
	// previous file. Extension is .pcapng — pcapwriter writes pcap-ng format
	// (per spec §7.3), not classic pcap.
	return filepath.Join(dir, macSafe+"-"+when.UTC().Format("20060102T150405.000000000Z")+".pcapng")
}
