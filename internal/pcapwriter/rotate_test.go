package pcapwriter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestShouldRotateBySize(t *testing.T) {
	r := rotation{maxBytes: 100, maxAge: time.Hour, started: time.Now()}
	assert.False(t, r.shouldRotate(50))
	assert.True(t, r.shouldRotate(150))
}

func TestShouldRotateByAge(t *testing.T) {
	r := rotation{maxBytes: 1 << 30, maxAge: time.Second, started: time.Now().Add(-2 * time.Second)}
	assert.True(t, r.shouldRotate(0))
}

func TestNextFilename(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:01"
	tt := time.Date(2026, 5, 6, 12, 4, 11, 123456789, time.UTC)
	got := nextFilename("/var/lib/shardflow/pcap/eng-1", mac, tt)
	assert.Equal(t, "/var/lib/shardflow/pcap/eng-1/aa-bb-cc-dd-ee-01-20260506T120411.123456789Z.pcapng", got)
}

func TestNextFilenameSubSecondRotationsDontCollide(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:01"
	t1 := time.Date(2026, 5, 6, 12, 4, 11, 1, time.UTC)
	t2 := time.Date(2026, 5, 6, 12, 4, 11, 2, time.UTC)
	assert.NotEqual(t, nextFilename("/x", mac, t1), nextFilename("/x", mac, t2))
}
