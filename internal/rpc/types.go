// Package rpc defines the JSON-RPC 2.0 wire types and method/event constants
// shared between shardflowd's server and shardflow's client.
package rpc

import "encoding/json"

// Request is a JSON-RPC 2.0 request frame.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response frame. Exactly one of Result or Error is set.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Event is a server-initiated notification frame (no ID per JSON-RPC §4.1).
type Event struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Error is the JSON-RPC 2.0 error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// JSON-RPC 2.0 standard error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// ShardFlow-specific error codes (range -32000..-32099 per §5.1).
const (
	CodeUnknownTarget   = -32000
	CodeOutOfCIDR       = -32001
	CodeGatewayIsSelf   = -32002
	CodeIfaceDown       = -32003
	CodePcapPathInvalid = -32004
)

// DeviceDTO is the wire form of devicestore.Device. Necessary because
// net.HardwareAddr and net.IP marshal as base64 byte arrays in JSON, while
// every consumer (CLI table, --json, TUI, integration tests) expects the
// dotted/colon string form. Wire conversion happens in the RPC handlers.
type DeviceDTO struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
	LastSeen string `json:"last_seen"` // RFC 3339; time.Time also marshals OK but string keeps the wire stable
	Policy   string `json:"policy,omitempty"`
}

// PolicyEntryDTO is the wire form of one policycompiler.Spec.
type PolicyEntryDTO struct {
	MAC      string `json:"mac"`
	Kind     string `json:"kind"` // "drop" | "throttle" | "pcap"
	RateKbit int    `json:"rate_kbit,omitempty"`
	PcapDir  string `json:"pcap_dir,omitempty"`
}

// PolicyKind enumerates the three v1 policy types.
type PolicyKind string

const (
	PolicyDrop     PolicyKind = "drop"
	PolicyThrottle PolicyKind = "throttle"
	PolicyPcap     PolicyKind = "pcap"
)

// PolicySpec is the params shape for Policy.Set.
type PolicySpec struct {
	// Target accepts either an IPv4 address or a MAC. The daemon resolves
	// IP→MAC at command time via devicestore.
	Target   string     `json:"target"`
	Kind     PolicyKind `json:"kind"`
	RateKbit int        `json:"rate_kbit,omitempty"` // throttle only
	PcapDir  string     `json:"pcap_dir,omitempty"`  // pcap only; empty = default
}

// Method names, exported as constants so client and server can't drift.
const (
	MethodScan        = "Scan"
	MethodDevicesList = "Devices.List"
	MethodDevicesGet  = "Devices.Get"
	MethodPolicySet   = "Policy.Set"
	MethodPolicyClear = "Policy.Clear"
	MethodPolicyList  = "Policy.List"
	MethodStats       = "Stats"
)

// Event method names.
const (
	EventDeviceDiscovered = "device.discovered"
	EventDeviceUpdated    = "device.updated"
	EventPolicyApplied    = "policy.applied"
	EventCountersTick     = "counters.tick"
	EventPcapRotated      = "pcap.rotated"
	EventIfaceDown        = "iface.down"
	EventIfaceUp          = "iface.up"
)
