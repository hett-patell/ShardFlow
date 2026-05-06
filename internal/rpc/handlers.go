package rpc

import (
	"context"
	"encoding/json"
	"net"
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
}

// BuildHandlers returns the method table from a HandlerDeps.
func BuildHandlers(d HandlerDeps) map[string]Handler {
	return map[string]Handler{
		MethodScan: func(ctx context.Context, _ json.RawMessage) (any, *Error) {
			if err := d.Scanner(ctx); err != nil {
				return nil, &Error{Code: CodeInternalError, Message: err.Error()}
			}
			return map[string]string{"status": "ok"}, nil
		},
		MethodDevicesList: func(_ context.Context, _ json.RawMessage) (any, *Error) {
			devs := d.Store.List()
			out := make([]DeviceDTO, 0, len(devs))
			for _, dev := range devs {
				out = append(out, deviceToDTO(dev))
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
			return deviceToDTO(dev), nil
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
	}
}

func setPolicy(ctx context.Context, d HandlerDeps, p PolicySpec) (any, *Error) {
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
	desired := d.Compiler.Snapshot()
	desired[mac.String()] = spec
	if err := d.Compiler.Apply(ctx, desired); err != nil {
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

func clearPolicy(ctx context.Context, d HandlerDeps, target string) (any, *Error) {
	mac, ferr := resolveTarget(d.Store, target)
	if ferr != nil {
		return nil, ferr
	}
	desired := d.Compiler.Snapshot()
	delete(desired, mac.String())
	if err := d.Compiler.Apply(ctx, desired); err != nil {
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
		LastSeen: dev.LastSeen.Format(time.RFC3339),
	}
}
