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
//
// Vendor and Model are deliberately separate. Vendor is the IEEE OUI
// vendor of the MAC's manufacturer (always the silicon maker — Apple,
// Samsung, Intel). Model is the SSDP/UPnP server string ("Linux/3.10
// UPnP/1.0 SSDP/1.6 PhilipsHue/1.0") which describes the firmware /
// device kind. Conflating them — as the v1 SSDP scanner did — would
// overwrite the OUI lookup every time a device announced itself, hiding
// the manufacturer from the operator.
type Device struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Hostname string
	Vendor   string
	Model    string
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
	Model    string
	Seen     time.Time
}

// EventKind enumerates store mutations broadcast to subscribers.
type EventKind int

const (
	EventDiscovered EventKind = iota
	EventUpdated
	EventEvicted // device removed by TTL sweep; sent to subscribers so UIs can drop the row
)

// Event is what subscribers receive.
type Event struct {
	Kind   EventKind
	Device Device
}

// Store is the device map. Safe for concurrent use.
//
// Indexes:
//   - byMAC: canonical map (MAC string → *Device)
//   - byIP:  reverse index (IP string → MAC string), kept in sync with
//     byMAC[mac].IP. ResolveIP used to be O(N) over byMAC; on a busy
//     LAN with hundreds of devices, called from every Policy.Set/Clear
//     handler, that scan was a real cost. byIP makes it O(1).
type Store struct {
	mu     sync.RWMutex
	byMAC  map[string]*Device
	byIP   map[string]string
	subsMu sync.Mutex
	subs   map[chan Event]struct{}
}

// New returns an empty store.
func New() *Store {
	return &Store{
		byMAC: make(map[string]*Device),
		byIP:  make(map[string]string),
		subs:  map[chan Event]struct{}{},
	}
}

// copyDevice returns a deep copy of d so callers can't mutate store-internal
// slice memory. MAC and IP are []byte slice headers; without this every
// returned Device aliases the byMAC entry.
func copyDevice(d Device) Device {
	out := d
	if d.MAC != nil {
		out.MAC = append(net.HardwareAddr{}, d.MAC...)
	}
	if d.IP != nil {
		out.IP = append(net.IP{}, d.IP...)
	}
	return out
}

// trySend is broadcast's per-subscriber send wrapper. It recovers from a
// panic if a misbehaving caller closed the channel themselves — the daemon
// survives, the bad subscriber simply stops receiving events.
func trySend(ch chan Event, e Event) {
	defer func() { _ = recover() }()
	select {
	case ch <- e:
	default:
		// drop on full buffer; the consumer is slow
	}
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
		// Keep byIP in sync: drop the old reverse entry, install the new.
		// Two MACs claiming the same IP can happen on misconfigured LANs;
		// last writer wins, matching the byMAC behaviour above.
		if existed && d.IP != nil {
			delete(s.byIP, d.IP.String())
		}
		d.IP = append(net.IP{}, o.IP...)
		s.byIP[d.IP.String()] = key
	}
	if o.Hostname != "" {
		d.Hostname = o.Hostname
	}
	if o.Vendor != "" {
		d.Vendor = o.Vendor
	}
	if o.Model != "" {
		d.Model = o.Model
	}
	if !o.Seen.IsZero() {
		d.LastSeen = o.Seen
	}
	snapshot := copyDevice(*d)
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
	return copyDevice(*d), true
}

// ResolveIP looks up the MAC currently associated with the given IP.
// O(1) via the byIP reverse index. Returns (mac, true) on hit, (nil, false)
// on miss.
func (s *Store) ResolveIP(ip net.IP) (net.HardwareAddr, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	macKey, ok := s.byIP[ip.String()]
	if !ok {
		return nil, false
	}
	d, ok := s.byMAC[macKey]
	if !ok {
		return nil, false
	}
	return append(net.HardwareAddr{}, d.MAC...), true
}

// List returns a snapshot of all known devices, sorted by IP for stable output.
func (s *Store) List() []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Device, 0, len(s.byMAC))
	for _, d := range s.byMAC {
		out = append(out, copyDevice(*d))
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].IP, out[j].IP) < 0
	})
	return out
}

// SetPolicy updates the typed-as-any policy field for a known MAC.
// Returns false if the MAC is unknown.
//
// Earlier versions spawned a goroutine for each broadcast (`go
// s.broadcast(...)`) to avoid holding s.mu across subscriber sends.
// That created an unbounded goroutine spawn rate under sustained
// policy churn. broadcast itself uses non-blocking sends per
// subscriber (trySend), so calling it inline can never block on a
// slow consumer — we just need to release s.mu before taking
// s.subsMu.
func (s *Store) SetPolicy(m net.HardwareAddr, p any) bool {
	s.mu.Lock()
	d, ok := s.byMAC[m.String()]
	if !ok {
		s.mu.Unlock()
		return false
	}
	d.Policy = p
	snapshot := copyDevice(*d)
	s.mu.Unlock()
	s.broadcast(Event{Kind: EventUpdated, Device: snapshot})
	return true
}

// Subscribe returns a channel that receives every event. Buffer size 64.
// When a slow consumer's buffer fills, the newest incoming event is
// dropped. Caller MUST call Unsubscribe with the returned channel when
// done.
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
		trySend(ch, e)
	}
}

// Evict removes every device whose LastSeen is older than now-ttl. A
// device with an active policy is preserved regardless of ttl: the
// poison/throttle/pcap path holds the canonical reference and we don't
// want to silently drop a target the operator is actively manipulating.
// Returns the number of devices evicted.
//
// Intended to be called periodically (e.g. once a minute) by the daemon
// so the device map doesn't grow unbounded on long-running sessions —
// roaming guests with privacy-randomised MACs, IoT devices that come and
// go, etc.
func (s *Store) Evict(now time.Time, ttl time.Duration) int {
	if ttl <= 0 {
		return 0
	}
	cutoff := now.Add(-ttl)
	s.mu.Lock()
	var evicted []Device
	for k, d := range s.byMAC {
		if d.Policy != nil {
			continue
		}
		if d.LastSeen.IsZero() || d.LastSeen.After(cutoff) {
			continue
		}
		if d.IP != nil {
			delete(s.byIP, d.IP.String())
		}
		delete(s.byMAC, k)
		evicted = append(evicted, copyDevice(*d))
	}
	s.mu.Unlock()
	for _, d := range evicted {
		s.broadcast(Event{Kind: EventEvicted, Device: d})
	}
	return len(evicted)
}
