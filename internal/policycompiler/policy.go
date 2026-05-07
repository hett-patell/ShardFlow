// Package policycompiler computes effector operations from a desired
// target→policy map and the daemon's current state. Order of operations is
// rigid (see spec §7.4) and reverse-order rollback runs on any failure.
package policycompiler

import (
	"context"
	"net"
	"time"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
)

// Kind is the policy variant.
type Kind int

const (
	KindNone Kind = iota
	KindDrop
	KindThrottle
	KindPcap
)

// Spec is the desired policy for a target. Target is an arpengine.Target
// so the same value flows directly into ARP.Start without a conversion.
type Spec struct {
	Target arpengine.Target
	Kind   Kind

	// Throttle:
	RateKbit int

	// Pcap:
	PcapDir  string
	MaxBytes int64
	MaxAge   time.Duration
}

// Effectors

// NFT and TC interfaces are deliberately scoped to what the compiler
// actually calls: per-target rule add/clear. Daemon-lifecycle methods
// (EnsureTables, EnsureIFB, EnsureRedirect, Teardown) are concrete
// methods on the *Manager structs in nftmgr/tcmgr and called directly
// from the daemon main, not via these interfaces. Keeping the interface
// thin makes the compiler trivially mockable and prevents the test
// stubs from drifting when daemon-lifecycle methods evolve.
type NFT interface {
	AddTargetDrop(ctx context.Context, mac net.HardwareAddr) error
	AddTargetMark(ctx context.Context, mac net.HardwareAddr, mark uint32) error
	AddReturnMark(ctx context.Context, mac, gwMAC net.HardwareAddr, targetIP net.IP, mark uint32) error
	RemoveTarget(ctx context.Context, mac net.HardwareAddr) error
}

type TC interface {
	SetThrottle(ctx context.Context, realIface, mac, rate string, mark uint32) error
	ClearThrottle(ctx context.Context, realIface, mac string, mark uint32) error
	SetCapture(ctx context.Context, realIface, mac string, mark uint32) error
	ClearCapture(ctx context.Context, realIface string, mark uint32) error
}

type Pcap interface {
	Open(mac, ipStr, srcIface, dir string, maxBytes int64, maxAge time.Duration) error
	Close(mac string) error
}

// ARP uses arpengine.Target so the implementation (arpengine.Engine)
// satisfies this interface by structural typing without an adapter.
type ARP interface {
	Start(t arpengine.Target) error
	Stop(t arpengine.Target) error
	StopAll() error
}
