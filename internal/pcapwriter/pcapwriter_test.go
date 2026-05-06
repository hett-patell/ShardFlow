package pcapwriter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenRejectsDuplicateMAC(t *testing.T) {
	// Without a real iface we can't successfully start a writer, but we
	// can verify the duplicate-rejection path: pre-populate the map with
	// a sentinel writer for `mac`, call Open with the same MAC, expect
	// "already capturing" error.
	m := New()
	m.writers["aa:bb:cc:dd:ee:01"] = &writer{
		mac:      "aa:bb:cc:dd:ee:01",
		finished: make(chan struct{}),
	}
	err := m.Open("aa:bb:cc:dd:ee:01", "10.0.0.42", "lo", t.TempDir(), 0, 0)
	if err == nil {
		t.Fatal("expected error for duplicate Open")
	}
	assert.Contains(t, err.Error(), "already capturing")
}
