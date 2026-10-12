package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mvanhorn/agent-tincan/internal/store"
)

// EventSubscriptionStore is the persistent mailbox subscription state. Event
// production and delivery leases stay in the relay's existing SQLite store.
type EventSubscriptionStore interface {
	PutEventSubscription(context.Context, store.EventSubscription) (store.EventSubscription, error)
	EventSubscriptions(context.Context, string, string) ([]store.EventSubscription, error)
	DeleteEventSubscription(context.Context, string, string) error
}

type eventService struct {
	store    EventSubscriptionStore
	sender   WebhookSender
	mu       sync.Mutex
	verified map[string]time.Time
}

// ConfigureEventStore enables native event methods for event-only principals.
// Call before Handler is served. A nil sender uses the SSRF-safe HTTPS sender.
func (g *Gateway) ConfigureEventStore(s EventSubscriptionStore, sender WebhookSender) {
	if sender == nil {
		sender = NewWebhookSender()
	}
	g.events = &eventService{store: s, sender: sender, verified: make(map[string]time.Time)}
}

type eventRPC struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func eventRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string, data any) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	e := map[string]any{"code": code, "message": message}
	if data != nil {
		e["data"] = data
	}
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
}

func eventRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

// The SDK already handles MCP 2 discovery but has no Events API. This narrow
// wrapper adds its three methods on the same authenticated endpoint, while
// letting the SDK validate and serve discovery and existing tool traffic.
func (g *Gateway) eventDispatch(next, discovery http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := r.Context().Value(principalKey{}).(Principal)
		if p.Scope != ScopeEvents {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "event-only MCP accepts POST", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			status := http.StatusBadRequest
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			http.Error(w, "bad MCP body", status)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var in eventRPC
		if err := json.Unmarshal(body, &in); err != nil {
			eventRPCError(w, nil, -32700, "invalid JSON request", nil)
			return
		}
		if in.JSONRPC != "2.0" || in.Method == "" {
			eventRPCError(w, in.ID, -32600, "invalid JSON-RPC request", nil)
			return
		}
		switch in.Method {
		case "events/list", "events/subscribe", "events/unsubscribe":
			if g.events == nil || g.events.store == nil {
				eventRPCError(w, in.ID, -32601, "events are not configured", nil)
				return
			}
			if !validEventProtocol(w, r, in) {
				return
			}
			g.serveEvent(w, r, p, in)
		case "server/discover":
			rec := httptest.NewRecorder()
			discovery.ServeHTTP(rec, r)
			if g.events != nil && g.events.store != nil && rec.Code == http.StatusOK {
				var out map[string]any
				if json.Unmarshal(rec.Body.Bytes(), &out) == nil {
					if result, ok := out["result"].(map[string]any); ok {
						caps, ok := result["capabilities"].(map[string]any)
						if !ok {
							caps = make(map[string]any)
							result["capabilities"] = caps
						}
						caps["events"] = map[string]any{}
						delete(caps, "tools")
						writeJSON(w, http.StatusOK, out)
						return
					}
				}
			}
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
		case "initialize", "ping", "tools/list", "notifications/initialized", "notifications/cancelled":
			next.ServeHTTP(w, r)
		default:
			// A method allowlist covers all operational methods, including future
			// tools/resources, rather than relying on per-tool checks.
			eventRPCError(w, in.ID, -32601, "method unavailable for events-only grant", nil)
		}
	})
}

func validEventProtocol(w http.ResponseWriter, r *http.Request, in eventRPC) bool {
	if len(in.ID) == 0 || bytes.Equal(in.ID, []byte("null")) {
		eventRPCError(w, in.ID, -32600, "event methods require a request id", nil)
		return false
	}
	var params struct {
		Meta map[string]any `json:"_meta"`
	}
	if json.Unmarshal(in.Params, &params) != nil {
		eventRPCError(w, in.ID, -32602, "invalid params", nil)
		return false
	}
	if r.Header.Get("Mcp-Protocol-Version") != "2026-07-28" || params.Meta[mcp.MetaKeyProtocolVersion] != "2026-07-28" {
		eventRPCError(w, in.ID, -32602, "events require MCP 2.0 protocol version 2026-07-28 in header and metadata", nil)
		return false
	}
	_, hasCaps := params.Meta[mcp.MetaKeyClientCapabilities].(map[string]any)
	if !hasCaps {
		eventRPCError(w, in.ID, -32602, "MCP 2.0 client metadata required", nil)
		return false
	}
	// Match SDK v1.8: clientInfo is optional. If supplied it must be a
	// valid object; omitting it cannot make discovery and events disagree.
	if rawInfo, present := params.Meta[mcp.MetaKeyClientInfo]; present {
		var info mcp.Implementation
		encoded, err := json.Marshal(rawInfo)
		if rawInfo == nil || err != nil || json.Unmarshal(encoded, &info) != nil {
			eventRPCError(w, in.ID, -32602, "invalid optional clientInfo", nil)
			return false
		}
	}
	if method := r.Header.Get("Mcp-Method"); method != "" && method != in.Method {
		eventRPCError(w, in.ID, mcp.CodeHeaderMismatch, "Mcp-Method does not match request", nil)
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		eventRPCError(w, in.ID, -32600, "application/json required", nil)
		return false
	}
	acceptsJSON := false
	for _, accepted := range strings.Split(r.Header.Get("Accept"), ",") {
		media, _, err := mime.ParseMediaType(strings.TrimSpace(accepted))
		if err == nil && (media == "application/json" || media == "*/*") {
			acceptsJSON = true
		}
	}
	if !acceptsJSON {
		eventRPCError(w, in.ID, -32600, "Accept must include application/json", nil)
		return false
	}
	return true
}

type eventArgs struct {
	Mailbox string `json:"mailbox"`
}
type eventParams struct {
	Meta      map[string]any `json:"_meta,omitempty"`
	Name      string         `json:"name"`
	Arguments eventArgs      `json:"arguments"`
	Delivery  struct {
		Mode   string `json:"mode"`
		URL    string `json:"url"`
		Secret string `json:"secret,omitempty"`
	} `json:"delivery"`
	TTLMs  json.RawMessage `json:"ttlMs,omitempty"`
	Cursor json.RawMessage `json:"cursor,omitempty"`
}

func eventDefinitions(mailbox string) []any {
	input := map[string]any{"type": "object", "properties": map[string]any{"mailbox": map[string]any{"type": "string", "const": mailbox}}, "required": []string{"mailbox"}, "additionalProperties": false}
	payload := map[string]any{"type": "object", "properties": map[string]any{
		"request_id": map[string]any{"type": "string"},
		"status":     map[string]any{"type": "string"}, "generation": map[string]any{"type": "integer", "minimum": 0},
	}, "required": []string{"request_id", "status", "generation"}, "additionalProperties": false}
	return []any{
		map[string]any{"name": store.EventRequestQueued, "description": "A request is queued for this mailbox. Contains IDs and status only.", "delivery": []string{"webhook"}, "inputSchema": input, "payloadSchema": payload},
		map[string]any{"name": store.EventReplyCreated, "description": "A reply arrives for a request sent by this mailbox. Contains IDs and status only.", "delivery": []string{"webhook"}, "inputSchema": input, "payloadSchema": payload},
	}
}

func (g *Gateway) serveEvent(w http.ResponseWriter, r *http.Request, p Principal, in eventRPC) {
	if in.Method == "events/list" {
		var params struct {
			Meta   map[string]any `json:"_meta"`
			Cursor string         `json:"cursor"`
		}
		if json.Unmarshal(in.Params, &params) != nil || params.Cursor != "" {
			eventRPCError(w, in.ID, -32602, "invalid catalog cursor", nil)
			return
		}
		eventRPCResult(w, in.ID, map[string]any{"events": eventDefinitions(p.Agent)})
		return
	}
	var params eventParams
	dec := json.NewDecoder(bytes.NewReader(in.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil {
		eventRPCError(w, in.ID, -32602, "invalid event parameters", nil)
		return
	}
	if params.Arguments.Mailbox != p.Agent {
		eventRPCError(w, in.ID, -32001, "mailbox is not owned by this connection", nil)
		return
	}
	if params.Name != store.EventRequestQueued && params.Name != store.EventReplyCreated {
		eventRPCError(w, in.ID, -32602, "unknown event name", nil)
		return
	}
	if params.Delivery.Mode != "webhook" {
		eventRPCError(w, in.ID, -32602, "only webhook delivery is supported", nil)
		return
	}
	if err := ValidateCallbackURL(params.Delivery.URL); err != nil {
		eventCallbackRPCError(w, in.ID, err)
		return
	}
	canonicalArgs, _ := json.Marshal(params.Arguments)
	identity, _ := json.Marshal([]string{p.ID, params.Delivery.URL, params.Name, string(canonicalArgs)})
	id := "sub_" + hash(string(identity))
	if in.Method == "events/unsubscribe" {
		if err := g.events.store.DeleteEventSubscription(r.Context(), p.ID, id); err != nil {
			eventRPCError(w, in.ID, -32603, "could not stop subscription", nil)
			return
		}
		eventRPCResult(w, in.ID, map[string]any{})
		return
	}
	// A refresh may omit a replacement key. Only an existing subscription of
	// this principal can supply it; a new subscription always needs a key.
	if params.Delivery.Secret == "" {
		subs, err := g.events.store.EventSubscriptions(r.Context(), p.ID, p.Agent)
		if err != nil {
			eventRPCError(w, in.ID, -32603, "could not read subscription", nil)
			return
		}
		for _, sub := range subs {
			if sub.ID == id {
				params.Delivery.Secret = sub.Secret
				break
			}
		}
	}
	if err := ValidateWebhookSecret(params.Delivery.Secret); err != nil {
		eventCallbackRPCError(w, in.ID, err)
		return
	}
	ttl := 24 * time.Hour
	if len(params.TTLMs) > 0 {
		if bytes.Equal(params.TTLMs, []byte("null")) {
			ttl = 7 * 24 * time.Hour
		} else {
			var ms int64
			if json.Unmarshal(params.TTLMs, &ms) != nil || ms <= 0 {
				eventRPCError(w, in.ID, -32602, "ttlMs must be positive or null", nil)
				return
			}
			if ms > (7 * 24 * time.Hour).Milliseconds() {
				ttl = 7 * 24 * time.Hour
			} else {
				ttl = time.Duration(ms) * time.Millisecond
			}
		}
	}
	if len(params.Cursor) > 0 && !bytes.Equal(params.Cursor, []byte("null")) {
		eventRPCError(w, in.ID, -32602, "these event types do not support replay cursors", nil)
		return
	}
	if err := g.events.verify(r.Context(), p.ID, id, params.Delivery.URL, params.Delivery.Secret, g.oauth.now()); err != nil {
		eventCallbackRPCError(w, in.ID, err)
		return
	}
	// Verification may take seconds. Recheck revocation before persisting.
	active, err := g.oauth.PrincipalActive(r.Context(), p.ID)
	if err != nil || !active {
		eventRPCError(w, in.ID, -32001, "connection was revoked", nil)
		return
	}
	sub, err := g.events.store.PutEventSubscription(r.Context(), store.EventSubscription{ID: id, Principal: p.ID, Mailbox: p.Agent, Name: params.Name, URL: params.Delivery.URL, Secret: params.Delivery.Secret, ExpiresAt: g.oauth.now().Add(ttl)})
	if err != nil {
		eventRPCError(w, in.ID, -32603, "could not save subscription", nil)
		return
	}
	eventRPCResult(w, in.ID, map[string]any{"id": sub.ID, "refreshBefore": sub.ExpiresAt.UTC().Format(time.RFC3339Nano), "cursor": nil, "truncated": false})
}

func eventCallbackRPCError(w http.ResponseWriter, id json.RawMessage, err error) {
	reason := "challenge_failed"
	var endpoint *CallbackEndpointError
	if errors.As(err, &endpoint) {
		reason = endpoint.Reason
	}
	eventRPCError(w, id, -32015, "callback endpoint verification failed", map[string]string{"reason": reason})
}

func (s *eventService) verify(ctx context.Context, principal, id, callback, secret string, now time.Time) error {
	// Include the key hash so a replacement signing key must prove control.
	key := principal + "\x00" + callback + "\x00" + hash(secret)
	s.mu.Lock()
	for k, until := range s.verified {
		if !now.Before(until) {
			delete(s.verified, k)
		}
	}
	until, ok := s.verified[key]
	s.mu.Unlock()
	if ok && now.Before(until) {
		return nil
	}
	if err := s.sender.Verify(ctx, id, callback, secret); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.verified) >= 256 {
		clear(s.verified)
	}
	s.verified[key] = now.Add(5 * time.Minute)
	return nil
}
