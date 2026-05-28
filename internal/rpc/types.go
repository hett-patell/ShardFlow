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
	Vendor   string `json:"vendor"` // OUI vendor (silicon maker)
	Model    string `json:"model,omitempty"` // SSDP SERVER (firmware/device kind)
	LastSeen string `json:"last_seen"`       // RFC 3339; time.Time also marshals OK but string keeps the wire stable
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

// SessionDTO describes the operator's connection at a moment in time:
// the network they're pentesting (iface, IP, gateway, optionally WiFi
// SSID/BSSID/signal) plus diagnostic counters from the most recent scan.
type SessionDTO struct {
	Iface   string `json:"iface"`
	MAC     string `json:"mac"`
	IP      string `json:"ip"`
	CIDR    string `json:"cidr"` // e.g. "10.0.0.42/24"
	Gateway string `json:"gateway"`
	GwMAC   string `json:"gw_mac"`

	Wireless   bool    `json:"wireless"`
	SSID       string  `json:"ssid,omitempty"`
	BSSID      string  `json:"bssid,omitempty"`
	SignalDBm  int     `json:"signal_dbm,omitempty"`
	TxRateMbit float64 `json:"tx_rate_mbit,omitempty"`
	FreqMHz    int     `json:"freq_mhz,omitempty"`

	PoisonsActive       int    `json:"poisons_active"`
	ArpWriteFailures    int    `json:"arp_write_failures"`
	ApIsolationLikely   bool   `json:"ap_isolation_likely"`
	SendRedirectsActive bool   `json:"send_redirects_active"`
	ForwardingEnabled   bool   `json:"forwarding_enabled"`
	DevicesTotal        int    `json:"devices_total"`
	LastScanAt          string `json:"last_scan_at,omitempty"` // RFC 3339
	LastScanReplies     int    `json:"last_scan_replies"`      // unique reply MACs
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
	MethodSessionGet  = "Session.Get"
)

// Event method names.
const (
	EventDeviceDiscovered = "device.discovered"
	EventDeviceUpdated    = "device.updated"
	EventDeviceEvicted    = "device.evicted"
	EventPolicyApplied    = "policy.applied"
	EventCountersTick     = "counters.tick"
	EventPcapRotated      = "pcap.rotated"
	EventIfaceDown        = "iface.down"
	EventIfaceUp          = "iface.up"
)
