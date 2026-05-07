package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
	"github.com/hett-patell/ShardFlow/internal/devicestore"
	"github.com/hett-patell/ShardFlow/internal/policycompiler"
)

// HandlerDeps is the bundle the daemon constructs to wire the RPC handlers.
type HandlerDeps struct {
	Store    *devicestore.Store
	Compiler *policycompiler.Compiler
	Scanner  func(ctx context.Context) error // a single-shot scan

	// GwMAC and GwIP are the LAN gateway, looked up at daemon startup and
	// passed in here so handlers don't have to re-resolve. Used to build
	// the Target tuple for new policies.
	GwMAC net.HardwareAddr
	GwIP  net.IP

	// Broadcaster pushes a server-initiated event to all connected clients.
	// Concretely this is bound to *Server.Broadcast in the daemon main; it
	// is a function rather than the server struct itself so handlers don't
	// need to know about the transport.
	Broadcaster func(method string, params any)

	// ActivePoisons returns the current count of in-flight poisons (used
	// by Stats). The daemon main wires this to arpengine.Engine.Active.
	ActivePoisons func() int

	// DefaultPcapDir is applied when Policy.Set's pcap_dir is empty. If
	// also empty the handler rejects the request with InvalidParams.
	DefaultPcapDir string

	// Session returns the operator's current connection state (iface,
	// gateway, WiFi association, scan diagnostics). Provided as a
	// callback rather than a snapshot field so the daemon can update
	// scan counters/poison counts without re-wiring deps. Optional —
	// handlers tolerate Session==nil and respond with an empty DTO.
	Session func() SessionDTO

	// applyMu serialises the snapshot→modify→Apply sequence in setPolicy
	// and clearPolicy so concurrent handler invocations can't clobber each
	// other with stale snapshots. Compiler.Apply has its own mutex, but
	// that only makes each Apply atomic — it doesn't cover the handler-
	// level RMW.
	applyMu sync.Mutex

	// shuttingDown, set under applyMu before shutdown begins, prevents
	// new Policy.Set / Policy.Clear from racing the corrective-ARP path.
	// Spec §9.1: every active poison must receive corrective ARPs before
	// daemon exit; a setPolicy that lands between Apply(empty) and
	// arp.StopAll would otherwise leave the new target uncorrected.
	shuttingDown bool

	// scanMu is held while a Scanner is in flight. Now that the RPC server
	// dispatches each request in its own goroutine, a misbehaving (or
	// retry-happy) client could fan out concurrent Scan requests; the
	// underlying scanner opens a pcap handle and floods the LAN with
	// ARP, so running two in parallel doubles the RF/CPU load for no
	// gain. We TryLock here and reject overlapping requests with a clear
	// error rather than queue them.
	scanMu sync.Mutex
}

// scanHardTimeout is the absolute upper bound on a single Scan. Internally
// the scanner already gives each phase its own ctx deadline (5s active
// sweep, 3s per multicast probe) so this is a safety net for pathological
// cases — kernel TX backpressure on a contended Wi-Fi link can push a
// /16 sweep past its phase deadline because each WritePacketData blocks
// for tens of milliseconds. Without an outer cap one Scan call could
// otherwise run for minutes and the TUI would freeze on c.Call.
const scanHardTimeout = 15 * time.Second

// MarkShuttingDown blocks new Policy.Set/Policy.Clear handler invocations.
// Called from the daemon's signal handler before tearing down state.
func (d *HandlerDeps) MarkShuttingDown() {
	d.applyMu.Lock()
	d.shuttingDown = true
	d.applyMu.Unlock()
}

// BuildHandlers returns the method table from a HandlerDeps. The deps are
// taken by pointer so the embedded applyMu is shared across closures.
func BuildHandlers(d *HandlerDeps) map[string]Handler {
	return map[string]Handler{
		MethodScan: func(ctx context.Context, _ json.RawMessage) (any, *Error) {
			if !d.scanMu.TryLock() {
				return nil, &Error{Code: CodeInternalError, Message: "scan already in progress"}
			}
			defer d.scanMu.Unlock()
			sCtx, cancel := context.WithTimeout(ctx, scanHardTimeout)
			defer cancel()
			if err := d.Scanner(sCtx); err != nil {
				return nil, &Error{Code: CodeInternalError, Message: err.Error()}
			}
			return map[string]string{"status": "ok"}, nil
		},
		MethodDevicesList: func(_ context.Context, _ json.RawMessage) (any, *Error) {
			devs := d.Store.List()
			snap := d.Compiler.Snapshot()
			out := make([]DeviceDTO, 0, len(devs))
			for _, dev := range devs {
				dto := deviceToDTO(dev)
				if s, ok := snap[dev.MAC.String()]; ok {
					dto.Policy = formatPolicy(s)
				}
				out = append(out, dto)
			}
			return out, nil
		},
		MethodDevicesGet: func(_ context.Context, params json.RawMessage) (any, *Error) {
			var p struct {
				MAC string `json:"mac"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, &Error{Code: CodeInvalidParams, Message: err.Error()}
			}
			mac, err := net.ParseMAC(p.MAC)
			if err != nil {
				return nil, &Error{Code: CodeInvalidParams, Message: err.Error()}
			}
			dev, ok := d.Store.Get(mac)
			if !ok {
				return nil, &Error{Code: CodeUnknownTarget, Message: "no such device"}
			}
			dto := deviceToDTO(dev)
			if s, ok := d.Compiler.Snapshot()[mac.String()]; ok {
				dto.Policy = formatPolicy(s)
			}
			return dto, nil
		},
		MethodPolicySet: func(ctx context.Context, params json.RawMessage) (any, *Error) {
			var p PolicySpec
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, &Error{Code: CodeInvalidParams, Message: err.Error()}
			}
			return setPolicy(ctx, d, p)
		},
		MethodPolicyClear: func(ctx context.Context, params json.RawMessage) (any, *Error) {
			var p struct {
				Target string `json:"target"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, &Error{Code: CodeInvalidParams, Message: err.Error()}
			}
			return clearPolicy(ctx, d, p.Target)
		},
		MethodPolicyList: func(_ context.Context, _ json.RawMessage) (any, *Error) {
			snap := d.Compiler.Snapshot()
			out := make([]PolicyEntryDTO, 0, len(snap))
			for mac, s := range snap {
				out = append(out, PolicyEntryDTO{
					MAC:      mac,
					Kind:     kindToString(s.Kind),
					RateKbit: s.RateKbit,
					PcapDir:  s.PcapDir,
				})
			}
			return out, nil
		},
		MethodStats: func(_ context.Context, _ json.RawMessage) (any, *Error) {
			return map[string]any{
				"devices":  len(d.Store.List()),
				"policies": len(d.Compiler.Snapshot()),
				"poisoned": d.ActivePoisons(),
			}, nil
		},
		MethodSessionGet: func(_ context.Context, _ json.RawMessage) (any, *Error) {
			if d.Session == nil {
				return SessionDTO{}, nil
			}
			return d.Session(), nil
		},
	}
}

func setPolicy(ctx context.Context, d *HandlerDeps, p PolicySpec) (any, *Error) {
	mac, ferr := resolveTarget(d.Store, p.Target)
	if ferr != nil {
		return nil, ferr
	}
	dev, _ := d.Store.Get(mac)
	kind := kindOf(p.Kind)
	if kind == policycompiler.KindNone {
		return nil, &Error{Code: CodeInvalidParams, Message: "unknown policy kind " + string(p.Kind) + " (drop|throttle|pcap)"}
	}
	spec := policycompiler.Spec{
		Target: arpengine.Target{MAC: mac, IP: dev.IP, GwMAC: d.GwMAC, GwIP: d.GwIP},
		Kind:   kind,
	}
	switch p.Kind {
	case PolicyThrottle:
		if p.RateKbit <= 0 {
			return nil, &Error{Code: CodeInvalidParams, Message: "throttle rate_kbit must be > 0"}
		}
		spec.RateKbit = p.RateKbit
	case PolicyPcap:
		if p.PcapDir == "" {
			if d.DefaultPcapDir == "" {
				return nil, &Error{Code: CodeInvalidParams, Message: "pcap_dir is required (no daemon default configured)"}
			}
			spec.PcapDir = d.DefaultPcapDir
		} else {
			spec.PcapDir = p.PcapDir
		}
	}

	// Serialise the RMW: another handler invocation cannot Snapshot before
	// our Apply commits.
	d.applyMu.Lock()
	if d.shuttingDown {
		d.applyMu.Unlock()
		return nil, &Error{Code: CodeInternalError, Message: "daemon shutting down"}
	}
	desired := d.Compiler.Snapshot()
	desired[mac.String()] = spec
	err := d.Compiler.Apply(ctx, desired)
	d.applyMu.Unlock()
	if err != nil {
		return nil, &Error{Code: CodeInternalError, Message: err.Error()}
	}
	if d.Broadcaster != nil {
		d.Broadcaster(EventPolicyApplied, map[string]any{
			"target": mac.String(),
			"kind":   string(p.Kind),
		})
	}
	return map[string]string{"status": "applied"}, nil
}

func clearPolicy(ctx context.Context, d *HandlerDeps, target string) (any, *Error) {
	mac, ferr := resolveTarget(d.Store, target)
	if ferr != nil {
		return nil, ferr
	}

	d.applyMu.Lock()
	if d.shuttingDown {
		d.applyMu.Unlock()
		return nil, &Error{Code: CodeInternalError, Message: "daemon shutting down"}
	}
	desired := d.Compiler.Snapshot()
	delete(desired, mac.String())
	err := d.Compiler.Apply(ctx, desired)
	d.applyMu.Unlock()
	if err != nil {
		return nil, &Error{Code: CodeInternalError, Message: err.Error()}
	}
	if d.Broadcaster != nil {
		d.Broadcaster(EventPolicyApplied, map[string]any{
			"target": mac.String(),
			"kind":   "cleared",
		})
	}
	return map[string]string{"status": "cleared"}, nil
}

func resolveTarget(store *devicestore.Store, target string) (net.HardwareAddr, *Error) {
	if mac, err := net.ParseMAC(target); err == nil {
		if _, ok := store.Get(mac); !ok {
			return nil, &Error{Code: CodeUnknownTarget, Message: "no such device — run scan first"}
		}
		return mac, nil
	}
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, &Error{Code: CodeInvalidParams, Message: "target must be IP or MAC"}
	}
	mac, ok := store.ResolveIP(ip)
	if !ok {
		return nil, &Error{Code: CodeUnknownTarget, Message: "no MAC known for that IP — run scan first"}
	}
	return mac, nil
}

func kindOf(k PolicyKind) policycompiler.Kind {
	switch k {
	case PolicyDrop:
		return policycompiler.KindDrop
	case PolicyThrottle:
		return policycompiler.KindThrottle
	case PolicyPcap:
		return policycompiler.KindPcap
	}
	return policycompiler.KindNone
}

func kindToString(k policycompiler.Kind) string {
	switch k {
	case policycompiler.KindDrop:
		return "drop"
	case policycompiler.KindThrottle:
		return "throttle"
	case policycompiler.KindPcap:
		return "pcap"
	}
	return ""
}

// deviceToDTO converts the typed store record to the wire form.
func deviceToDTO(dev devicestore.Device) DeviceDTO {
	return DeviceDTO{
		MAC:      dev.MAC.String(),
		IP:       dev.IP.String(),
		Hostname: dev.Hostname,
		Vendor:   dev.Vendor,
		Model:    dev.Model,
		LastSeen: dev.LastSeen.Format(time.RFC3339),
	}
}

// formatPolicy renders a compiler Spec into a short human-readable form
// for the Policy column in DeviceDTO. Matches what the TUI and the CLI
// `devices list` table expect: "drop" / "throttle 200kbit" / "pcap".
func formatPolicy(s policycompiler.Spec) string {
	switch s.Kind {
	case policycompiler.KindDrop:
		return "drop"
	case policycompiler.KindThrottle:
		if s.RateKbit > 0 {
			return "throttle " + formatKbit(s.RateKbit)
		}
		return "throttle"
	case policycompiler.KindPcap:
		return "pcap"
	}
	return ""
}

// formatKbit renders kbit as either "Nkbit" or "Nmbit" using the
// networking-SI convention (1 mbit = 1000 kbit) that matches the rest
// of the CLI's parseRate.
func formatKbit(k int) string {
	if k >= 1000 && k%1000 == 0 {
		return fmt.Sprintf("%dmbit", k/1000)
	}
	return fmt.Sprintf("%dkbit", k)
}
