package rpc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestRoundTrip(t *testing.T) {
	r := Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "Policy.Set",
		Params:  json.RawMessage(`{"target":"10.0.0.42","kind":"throttle","rate_kbit":200}`),
	}
	b, err := json.Marshal(r)
	require.NoError(t, err)

	var back Request
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, "Policy.Set", back.Method)
}

func TestPolicyKindMarshal(t *testing.T) {
	for _, k := range []PolicyKind{PolicyDrop, PolicyThrottle, PolicyPcap} {
		b, err := json.Marshal(k)
		require.NoError(t, err)
		var back PolicyKind
		require.NoError(t, json.Unmarshal(b, &back))
		assert.Equal(t, k, back)
	}
}

func TestEventEnvelope(t *testing.T) {
	ev := Event{
		JSONRPC: "2.0",
		Method:  "device.discovered",
		Params:  json.RawMessage(`{"mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.42"}`),
	}
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"method":"device.discovered"`)
	// Events have no "id" field (notification per JSON-RPC 2.0 §4.1).
	assert.NotContains(t, string(b), `"id"`)
}

func TestResponseIDNullWhenNil(t *testing.T) {
	// JSON-RPC 2.0 §5 requires every response to include the id member,
	// emitting null when the request id could not be determined. Because
	// json.RawMessage is []byte, a nil value without `omitempty` serialises
	// as "id":null. If a future maintainer adds omitempty to Response.ID,
	// this test fires.
	r := Response{
		JSONRPC: "2.0",
		ID:      nil,
		Error:   &Error{Code: CodeInternalError, Message: "boom"},
	}
	b, err := json.Marshal(r)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"id":null`,
		"Response.ID must not be omitted even when nil (JSON-RPC 2.0 §5)")
}

func TestRequestNotificationOmitsID(t *testing.T) {
	notif := Request{JSONRPC: "2.0", Method: "foo"}
	b, err := json.Marshal(notif)
	require.NoError(t, err)
	assert.NotContains(t, string(b), `"id"`,
		"Request without ID must serialise as a notification (no id key)")
}
