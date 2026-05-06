// Package devicestore is the in-memory map of devices observed on the LAN.
// MAC addresses are the canonical identifier; IPs may change over time.
package devicestore

import (
	"bytes"
	"net"
	"sort"
	"sync"
	"time"
)

// Device is the public record for a host we have observed.
type Device struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Hostname string
	Vendor   string
	LastSeen time.Time
	// Policy is set by policycompiler; nil means "no policy".
	Policy any // typed by callers; the store doesn't interpret it
}

// Observation is one fact about a device, fed in by a scanner.
// Empty fields mean "no new information"; the store will preserve prior values.
type Observation struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Hostname string
	Vendor   string
	Seen     time.Time
}

// EventKind enumerates store mutations broadcast to subscribers.
type EventKind int

const (
	EventDiscovered EventKind = iota
	EventUpdated
)

// Event is what subscribers receive.
type Event struct {
	Kind   EventKind
	Device Device
}

// Store is the device map. Safe for concurrent use.
type Store struct {
	mu     sync.RWMutex
	byMAC  map[string]*Device
	subsMu sync.Mutex
	subs   map[chan Event]struct{}
}

// New returns an empty store.
func New() *Store {
	return &Store{byMAC: make(map[string]*Device), subs: map[chan Event]struct{}{}}
}

// Upsert merges an observation into the store. New MAC = discovery; existing
// MAC = update (only non-empty fields overwrite).
func (s *Store) Upsert(o Observation) {
	if len(o.MAC) == 0 {
		return
	}
	key := o.MAC.String()
	s.mu.Lock()
	d, existed := s.byMAC[key]
	if !existed {
		d = &Device{MAC: append(net.HardwareAddr{}, o.MAC...)}
		s.byMAC[key] = d
	}
	if o.IP != nil {
		d.IP = append(net.IP{}, o.IP...)
	}
	if o.Hostname != "" {
		d.Hostname = o.Hostname
	}
	if o.Vendor != "" {
		d.Vendor = o.Vendor
	}
	if !o.Seen.IsZero() {
		d.LastSeen = o.Seen
	}
	snapshot := *d
	s.mu.Unlock()

	kind := EventUpdated
	if !existed {
		kind = EventDiscovered
	}
	s.broadcast(Event{Kind: kind, Device: snapshot})
}

// Get returns a device by MAC, or (zero, false) if unknown.
func (s *Store) Get(m net.HardwareAddr) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.byMAC[m.String()]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// ResolveIP looks up the MAC currently associated with the given IP.
// Returns (mac, true) on hit, (nil, false) on miss.
func (s *Store) ResolveIP(ip net.IP) (net.HardwareAddr, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.byMAC {
		if d.IP.Equal(ip) {
			return append(net.HardwareAddr{}, d.MAC...), true
		}
	}
	return nil, false
}

// List returns a snapshot of all known devices, sorted by IP for stable output.
func (s *Store) List() []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Device, 0, len(s.byMAC))
	for _, d := range s.byMAC {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].IP, out[j].IP) < 0
	})
	return out
}

// SetPolicy updates the typed-as-any policy field for a known MAC.
// Returns false if the MAC is unknown.
func (s *Store) SetPolicy(m net.HardwareAddr, p any) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byMAC[m.String()]
	if !ok {
		return false
	}
	d.Policy = p
	snapshot := *d
	go s.broadcast(Event{Kind: EventUpdated, Device: snapshot})
	return true
}

// Subscribe returns a channel that receives every event. Buffer size 64 —
// slow consumers drop oldest events (best-effort). Caller should call
// Unsubscribe with the returned channel when done to avoid a goroutine
// leak.
func (s *Store) Subscribe() chan Event {
	ch := make(chan Event, 64)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	return ch
}

// Unsubscribe removes ch from the subscriber set and closes it. Safe to
// call multiple times; subsequent calls are no-ops.
func (s *Store) Unsubscribe(ch chan Event) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	if _, ok := s.subs[ch]; !ok {
		return
	}
	delete(s.subs, ch)
	close(ch)
}

func (s *Store) broadcast(e Event) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
			// drop on full buffer; the consumer is slow
		}
	}
}
