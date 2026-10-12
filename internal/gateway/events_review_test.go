package gateway

import (
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEventUnsubscribeAbsentIsIdempotent(t *testing.T) {
	f := newEventFixture(t, true)
	tokens, _ := f.login(t, "dots")
	_, out := f.rpc(t, tokens.AccessToken, "events/unsubscribe", subscriptionParams("dots"))
	if code := rpcCode(out); code != 0 {
		t.Fatal(out)
	}
}

func TestEventOptionalClientInfoMatchesSDKDiscovery(t *testing.T) {
	f := newEventFixture(t, true)
	tokens, _ := f.login(t, "dots")
	for _, method := range []string{"server/discover", "events/list"} {
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": map[string]any{"_meta": map[string]any{mcp.MetaKeyProtocolVersion: "2026-07-28", mcp.MetaKeyClientCapabilities: map[string]any{}}}})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, eventResource, strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Mcp-Protocol-Version", "2026-07-28")
		r.Header.Set("Mcp-Method", method)
		w := httptest.NewRecorder()
		f.g.Handler().ServeHTTP(w, r)
		var out map[string]any
		if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err, w.Body)
		}
		if code := rpcCode(out); code != 0 {
			t.Fatal(method, out)
		}
	}
}

func TestEventStaleGoneCannotRevokeResubscription(t *testing.T) {
	f, p, sub, _ := workerPending(t)
	s := &workerSender{status: 410, onSend: func() {
		if err := f.store.DeleteEventSubscription(t.Context(), p.ID, sub.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.PutEventSubscription(t.Context(), sub); err != nil {
			t.Fatal(err)
		}
	}}
	if err := NewEventDeliveryWorker(f.store, f.oauth, s).DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	subs, err := f.store.EventSubscriptions(t.Context(), p.ID, "dots")
	if err != nil || len(subs) != 1 {
		t.Fatal(subs, err)
	}
}

func TestEventStaleGoneCannotRevokeVerifiedRefresh(t *testing.T) {
	f, p, sub, _ := workerPending(t)
	s := &workerSender{status: 410, onSend: func() {
		sub.Secret = "replacement fixture key"
		if _, err := f.store.PutEventSubscription(t.Context(), sub); err != nil {
			t.Fatal(err)
		}
	}}
	if err := NewEventDeliveryWorker(f.store, f.oauth, s).DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	subs, err := f.store.EventSubscriptions(t.Context(), p.ID, "dots")
	if err != nil || len(subs) != 1 || subs[0].Revision <= sub.Revision {
		t.Fatal(subs, err)
	}
}
