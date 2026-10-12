package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mvanhorn/agent-tincan/internal/identity"
	"github.com/mvanhorn/agent-tincan/internal/identity/identitytest"
	"github.com/mvanhorn/agent-tincan/internal/store"
)

const eventBase = "https://gateway.example"
const eventResource = eventBase + "/mcp"
const eventRedirect = "https://chatgpt.example/redirect"
const eventVerifier = "random-test-verifier-that-is-long-enough-for-pkce-123456"

type testEventSender struct {
	verifications int
	fail          error
}

func (s *testEventSender) Verify(context.Context, string, string, string) error {
	s.verifications++
	return s.fail
}
func (*testEventSender) Send(context.Context, string, string, string, string, string, []byte) (int, error) {
	return 204, nil
}

type eventFixture struct {
	store      *store.Store
	oauth      *OAuth
	g          *Gateway
	dir        *identity.Directory
	sender     *testEventSender
	now        time.Time
	relayCalls int
}

func newEventFixture(t *testing.T, policy bool) *eventFixture {
	t.Helper()
	f := &eventFixture{now: time.Now().UTC(), sender: &testEventSender{}}
	var err error
	f.store, err = store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	if err := f.store.InitEvents(); err != nil {
		t.Fatal(err)
	}
	if err := f.store.PutAgent(t.Context(), identity.Agent{Name: "dots", NodeID: "node-backend", NodeName: "backend", NodeUser: "owner@example.com", Kind: "codex", JoinedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	f.dir = identity.NewDirectory(f.store, identitytest.New(nil), identity.Config{})
	f.oauth, err = NewOAuth(f.store.DB(), func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	if policy {
		if err := f.oauth.ConfigureEvents(eventResource, []string{"dots"}); err != nil {
			t.Fatal(err)
		}
	}
	f.g = New(eventBase, f.oauth, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.relayCalls++
		http.Error(w, "unexpected relay call", 500)
	}), "test")
	f.g.ConfigureEventStore(f.store, f.sender)
	return f
}

func (f *eventFixture) login(t *testing.T, agent string) (Tokens, Principal) {
	t.Helper()
	code, err := f.oauth.MintLoginCode(t.Context(), agent)
	if err != nil {
		t.Fatal(err)
	}
	cid, err := f.oauth.RegisterClient(t.Context(), eventRedirect)
	if err != nil {
		t.Fatal(err)
	}
	resource := ""
	if f.oauth.EventsOnly(agent) {
		resource = eventResource
	}
	auth, err := f.oauth.ExchangeLoginResource(t.Context(), code, cid, eventRedirect, pkce(eventVerifier), resource)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := f.oauth.ExchangeAuthCodeResource(t.Context(), auth, cid, eventRedirect, eventVerifier, resource)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.oauth.ValidatePrincipal(t.Context(), tokens.AccessToken, eventResource)
	if err != nil {
		t.Fatal(err)
	}
	return tokens, p
}

func (f *eventFixture) rpc(t *testing.T, token, method string, params map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{mcp.MetaKeyProtocolVersion: "2026-07-28", mcp.MetaKeyClientInfo: map[string]any{"name": "chatgpt", "version": "test"}, mcp.MetaKeyClientCapabilities: map[string]any{}}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, eventResource, strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	r.Header.Set("Mcp-Method", method)
	w := httptest.NewRecorder()
	f.g.Handler().ServeHTTP(w, r)
	var out map[string]any
	content := w.Body.Bytes()
	if strings.Contains(w.Header().Get("Content-Type"), "text/event-stream") {
		for line := range strings.SplitSeq(w.Body.String(), "\n") {
			if data, ok := strings.CutPrefix(line, "data: "); ok {
				content = []byte(data)
				break
			}
		}
	}
	if w.Code == 200 && json.Unmarshal(content, &out) != nil {
		t.Fatalf("invalid response: %s", w.Body)
	}
	return w, out
}

func subscriptionParams(mailbox string) map[string]any {
	return map[string]any{"name": store.EventRequestQueued, "arguments": map[string]any{"mailbox": mailbox}, "delivery": map[string]any{"mode": "webhook", "url": "https://receiver.example/events", "secret": "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 32))}}
}

func rpcCode(out map[string]any) int {
	if e, ok := out["error"].(map[string]any); ok {
		return int(e["code"].(float64))
	}
	return 0
}

func TestEventConnectPreservesBackendBinding(t *testing.T) {
	f := newEventFixture(t, true)
	before, _, _ := f.dir.Agent(t.Context(), "dots")
	conn := Connector{Dir: f.dir, OAuth: f.oauth, Base: eventBase}
	code, endpoint, err := conn.Connect(t.Context(), "dots")
	if err != nil || code == "" || endpoint != eventResource {
		t.Fatalf("connect: %s %s %v", code, endpoint, err)
	}
	after, _, _ := f.dir.Agent(t.Context(), "dots")
	if before != after {
		t.Fatalf("event login rebound mailbox: before=%+v after=%+v", before, after)
	}
	if err := f.oauth.ConfigureEvents(eventResource, []string{"dots", "missing"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Connect(t.Context(), "missing"); !errors.Is(err, identity.ErrUnknownAgent) {
		t.Fatalf("missing mailbox: %v", err)
	}
}

func TestEventOnlyDiscoveryAndForbiddenOperationalMethods(t *testing.T) {
	f := newEventFixture(t, true)
	tokens, _ := f.login(t, "dots")
	w, out := f.rpc(t, tokens.AccessToken, "server/discover", nil)
	if w.Code != 200 || rpcCode(out) != 0 {
		t.Fatalf("discover: %d %s", w.Code, w.Body)
	}
	result := out["result"].(map[string]any)
	caps := result["capabilities"].(map[string]any)
	if _, ok := caps["events"]; !ok {
		t.Fatalf("missing native events: %s", w.Body)
	}
	if _, ok := caps["tools"]; ok {
		t.Fatalf("event principal exposes tools: %s", w.Body)
	}
	_, out = f.rpc(t, tokens.AccessToken, "tools/list", nil)
	if rpcCode(out) != 0 || len(out["result"].(map[string]any)["tools"].([]any)) != 0 {
		t.Fatalf("tools list: %+v", out)
	}
	for _, method := range []string{"tools/call", "resources/read", "resources/list", "prompts/get", "future/write"} {
		_, out := f.rpc(t, tokens.AccessToken, method, map[string]any{"name": "check_inbox", "arguments": map[string]any{}})
		if rpcCode(out) != -32601 {
			t.Errorf("%s not denied: %+v", method, out)
		}
	}
	if f.relayCalls != 0 {
		t.Fatalf("event principal invoked relay %d times", f.relayCalls)
	}
}

func TestEventSubscriptionsOwnMailboxAndAreIdempotent(t *testing.T) {
	f := newEventFixture(t, true)
	tokens, p := f.login(t, "dots")
	_, out := f.rpc(t, tokens.AccessToken, "events/list", nil)
	if rpcCode(out) != 0 || len(out["result"].(map[string]any)["events"].([]any)) != 2 {
		t.Fatalf("catalog: %+v", out)
	}
	_, out = f.rpc(t, tokens.AccessToken, "events/subscribe", subscriptionParams("other"))
	if rpcCode(out) != -32001 || f.sender.verifications != 0 {
		t.Fatalf("foreign mailbox: %+v", out)
	}
	_, out = f.rpc(t, tokens.AccessToken, "events/subscribe", subscriptionParams("dots"))
	if rpcCode(out) != 0 {
		t.Fatalf("subscribe: %+v", out)
	}
	id := out["result"].(map[string]any)["id"]
	params := subscriptionParams("dots")
	params["ttlMs"] = 1000
	_, out = f.rpc(t, tokens.AccessToken, "events/subscribe", params)
	if rpcCode(out) != 0 || out["result"].(map[string]any)["id"] != id || f.sender.verifications != 1 {
		t.Fatalf("retry duplicated subscription/verification: %+v count=%d", out, f.sender.verifications)
	}
	subs, err := f.store.EventSubscriptions(t.Context(), p.ID, "dots")
	if err != nil || len(subs) != 1 || subs[0].ExpiresAt.Sub(f.now) > time.Second {
		t.Fatalf("ttl or identity: %+v %v", subs, err)
	}
	params = subscriptionParams("dots")
	params["delivery"].(map[string]any)["secret"] = "whsec_" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	_, out = f.rpc(t, tokens.AccessToken, "events/subscribe", params)
	if rpcCode(out) != 0 || f.sender.verifications != 2 {
		t.Fatalf("secret rotation must reverify: %+v", out)
	}
	subs, err = f.store.EventSubscriptions(t.Context(), p.ID, "dots")
	if err != nil || subs[0].PreviousSecret == "" {
		t.Fatalf("no secret overlap: %+v %v", subs, err)
	}
	params = subscriptionParams("dots")
	delete(params["delivery"].(map[string]any), "secret")
	for range 2 {
		_, out = f.rpc(t, tokens.AccessToken, "events/unsubscribe", params)
		if rpcCode(out) != 0 {
			t.Fatalf("unsubscribe: %+v", out)
		}
	}
	subs, err = f.store.EventSubscriptions(t.Context(), p.ID, "dots")
	if err != nil || len(subs) != 0 {
		t.Fatalf("still subscribed: %+v %v", subs, err)
	}
}

func TestEventCallbackFailureDoesNotPersist(t *testing.T) {
	f := newEventFixture(t, true)
	tokens, p := f.login(t, "dots")
	f.sender.fail = &CallbackEndpointError{Reason: "challenge_failed"}
	_, out := f.rpc(t, tokens.AccessToken, "events/subscribe", subscriptionParams("dots"))
	if rpcCode(out) != -32015 {
		t.Fatalf("callback error: %+v", out)
	}
	subs, err := f.store.EventSubscriptions(t.Context(), p.ID, "dots")
	if err != nil || len(subs) != 0 {
		t.Fatalf("failed callback activated subscription: %+v %v", subs, err)
	}
}

func TestEventPolicyRejectsOldFullLoginRefreshAndDispatch(t *testing.T) {
	f := newEventFixture(t, false)
	tokens, p := f.login(t, "dots")
	other, otherP := f.login(t, "other")
	oldAuthLogin, err := f.oauth.MintLoginCode(t.Context(), "dots")
	if err != nil {
		t.Fatal(err)
	}
	oldAuth, err := f.oauth.ExchangeLogin(t.Context(), oldAuthLogin, p.ClientID, eventRedirect, pkce(eventVerifier))
	if err != nil {
		t.Fatal(err)
	}
	oldCode, err := f.oauth.MintLoginCode(t.Context(), "dots")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.oauth.ConfigureEvents(eventResource, []string{"dots"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.oauth.ExchangeLoginResource(t.Context(), oldCode, "client", eventRedirect, pkce(eventVerifier), eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("old login accepted: %v", err)
	}
	if _, err := f.oauth.ExchangeAuthCodeResource(t.Context(), oldAuth, p.ClientID, eventRedirect, eventVerifier, eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("old auth code accepted: %v", err)
	}
	if _, err := f.oauth.RefreshResource(t.Context(), tokens.RefreshToken, p.ClientID, eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("old refresh accepted: %v", err)
	}
	w, _ := f.rpc(t, tokens.AccessToken, "tools/call", map[string]any{"name": "ask"})
	if w.Code != 401 {
		t.Fatalf("old full grant bypassed policy: %d %s", w.Code, w.Body)
	}
	if _, err := f.oauth.ValidatePrincipal(t.Context(), other.AccessToken, eventResource); err != nil {
		t.Fatalf("unrelated full mailbox rejected: %v", err)
	}
	if _, err := f.oauth.Refresh(t.Context(), other.RefreshToken, otherP.ClientID); err != nil {
		t.Fatalf("unrelated full refresh rejected: %v", err)
	}
}

func TestEventResourceBindingAndFailedExchangeRetry(t *testing.T) {
	f := newEventFixture(t, true)
	cid, err := f.oauth.RegisterClient(t.Context(), eventRedirect)
	if err != nil {
		t.Fatal(err)
	}
	code, err := f.oauth.MintLoginCode(t.Context(), "dots")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.oauth.ExchangeLogin(t.Context(), code, cid, eventRedirect, pkce(eventVerifier)); !errors.Is(err, errInvalid) {
		t.Fatalf("missing login audience: %v", err)
	}
	auth, err := f.oauth.ExchangeLoginResource(t.Context(), code, cid, eventRedirect, pkce(eventVerifier), eventResource)
	if err != nil {
		t.Fatalf("audience failure consumed login: %v", err)
	}
	if _, err := f.oauth.ExchangeAuthCodeResource(t.Context(), auth, cid, eventRedirect, eventVerifier, eventResource+"-wrong"); !errors.Is(err, errInvalid) {
		t.Fatalf("wrong auth audience: %v", err)
	}
	if _, err := f.oauth.ExchangeAuthCodeResource(t.Context(), auth, cid, eventRedirect, "bad verifier", eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("wrong PKCE: %v", err)
	}
	if _, err := f.store.DB().Exec(`CREATE TRIGGER fail_token BEFORE INSERT ON gw_tokens WHEN NEW.kind = 'refresh' BEGIN SELECT RAISE(FAIL, 'injected token write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.oauth.ExchangeAuthCodeResource(t.Context(), auth, cid, eventRedirect, eventVerifier, eventResource); err == nil {
		t.Fatal("expected token insert failure")
	}
	var n int
	if err := f.store.DB().QueryRow(`SELECT count(*) FROM gw_tokens`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial token commit: %d %v", n, err)
	}
	if _, err := f.store.DB().Exec(`DROP TRIGGER fail_token`); err != nil {
		t.Fatal(err)
	}
	tokens, err := f.oauth.ExchangeAuthCodeResource(t.Context(), auth, cid, eventRedirect, eventVerifier, eventResource)
	if err != nil {
		t.Fatalf("failed exchange consumed authorization code: %v", err)
	}
	if _, err := f.oauth.ValidatePrincipal(t.Context(), tokens.AccessToken, eventResource+"-wrong"); !errors.Is(err, errInvalid) {
		t.Fatalf("wrong dispatch audience: %v", err)
	}
}

func TestEventRefreshRollbackStablePrincipalAndRevocation(t *testing.T) {
	f := newEventFixture(t, true)
	tokens, p := f.login(t, "dots")
	second, p2 := f.login(t, "dots")
	if p.ID == p2.ID {
		t.Fatal("separate connections share a principal")
	}
	if _, err := f.oauth.RefreshResource(t.Context(), tokens.RefreshToken, p.ClientID, ""); !errors.Is(err, errInvalid) {
		t.Fatalf("missing refresh resource: %v", err)
	}
	if _, err := f.store.DB().Exec(`CREATE TRIGGER fail_refresh BEFORE INSERT ON gw_tokens WHEN NEW.kind = 'refresh' BEGIN SELECT RAISE(FAIL, 'injected refresh failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.oauth.RefreshResource(t.Context(), tokens.RefreshToken, p.ClientID, eventResource); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := f.oauth.ValidatePrincipal(t.Context(), tokens.AccessToken, eventResource); err != nil {
		t.Fatalf("refresh failure revoked valid access: %v", err)
	}
	if _, err := f.store.DB().Exec(`DROP TRIGGER fail_refresh`); err != nil {
		t.Fatal(err)
	}
	fresh, err := f.oauth.RefreshResource(t.Context(), tokens.RefreshToken, p.ClientID, eventResource)
	if err != nil {
		t.Fatalf("refresh failure consumed token: %v", err)
	}
	pFresh, err := f.oauth.ValidatePrincipal(t.Context(), fresh.AccessToken, eventResource)
	if err != nil || pFresh.ID != p.ID {
		t.Fatalf("principal changed on refresh: %+v %v", pFresh, err)
	}
	if _, err := f.oauth.RefreshResource(t.Context(), tokens.RefreshToken, p.ClientID, eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("replayed refresh: %v", err)
	}
	if err := f.oauth.RevokePrincipal(t.Context(), p.ID); err != nil {
		t.Fatal(err)
	}
	if active, err := f.oauth.PrincipalActive(t.Context(), p.ID); err != nil || active {
		t.Fatalf("revoked delivery principal active: %v %v", active, err)
	}
	if _, err := f.oauth.ValidatePrincipal(t.Context(), fresh.AccessToken, eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("revoked access: %v", err)
	}
	if _, err := f.oauth.RefreshResource(t.Context(), fresh.RefreshToken, p.ClientID, eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("revoked refresh: %v", err)
	}
	if _, err := f.oauth.ValidatePrincipal(t.Context(), second.AccessToken, eventResource); err != nil {
		t.Fatalf("independent connection revoked: %v", err)
	}
	f.now = f.now.Add(accessTTL)
	if _, err := f.oauth.ValidatePrincipal(t.Context(), second.AccessToken, eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("expired access accepted: %v", err)
	}
	if active, err := f.oauth.PrincipalActive(t.Context(), p2.ID); err != nil || !active {
		t.Fatalf("access expiry incorrectly stops plugin refresh lifetime: %v %v", active, err)
	}
}

func TestEventOAuthHTTPRequiresAudienceAndPreservesFormResource(t *testing.T) {
	f := newEventFixture(t, true)
	cid, err := f.oauth.RegisterClient(t.Context(), eventRedirect)
	if err != nil {
		t.Fatal(err)
	}
	code, err := f.oauth.MintLoginCode(t.Context(), "dots")
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"login_code": {code}, "client_id": {cid}, "redirect_uri": {eventRedirect}, "code_challenge": {pkce(eventVerifier)}, "resource": {eventResource}}
	r := httptest.NewRequest(http.MethodPost, eventBase+"/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.g.Handler().ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatalf("authorize: %d %s", w.Code, w.Body)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {cid}, "redirect_uri": {eventRedirect}, "code_verifier": {eventVerifier}}
	for _, resource := range []string{"", eventResource} {
		tokenForm.Set("resource", resource)
		r = httptest.NewRequest(http.MethodPost, eventBase+"/token", strings.NewReader(tokenForm.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w = httptest.NewRecorder()
		f.g.Handler().ServeHTTP(w, r)
		want := 400
		if resource != "" {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("token audience %q: %d %s", resource, w.Code, w.Body)
		}
	}
}

func TestLegacyOAuthRowsCannotBypassEventsPolicy(t *testing.T) {
	f := newEventFixture(t, false)
	cid, err := f.oauth.RegisterClient(t.Context(), eventRedirect)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO gw_codes(hash,kind,agent,expires_at) VALUES (?,?,?,?)`, []any{hash("OLD-LOGIN"), kindLogin, "dots", f.now.Add(time.Minute).UnixMilli()}},
		{`INSERT INTO gw_codes(hash,kind,agent,client_id,redirect,challenge,expires_at) VALUES (?,?,?,?,?,?,?)`, []any{hash("old-auth"), kindAuth, "dots", cid, eventRedirect, pkce(eventVerifier), f.now.Add(time.Minute).UnixMilli()}},
		{`INSERT INTO gw_tokens(hash,kind,agent,client_id,expires_at) VALUES (?,?,?,?,?)`, []any{hash("old-access"), kindAccess, "dots", cid, f.now.Add(time.Hour).UnixMilli()}},
		{`INSERT INTO gw_tokens(hash,kind,agent,client_id,expires_at) VALUES (?,?,?,?,?)`, []any{hash("old-refresh"), kindRefresh, "dots", cid, f.now.Add(time.Hour).UnixMilli()}},
	} {
		if _, err := f.store.DB().Exec(row.sql, row.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.oauth.Validate(t.Context(), "old-access"); err != nil {
		t.Fatalf("legacy default behavior changed: %v", err)
	}
	if err := f.oauth.ConfigureEvents(eventResource, []string{"dots"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.oauth.ValidatePrincipal(t.Context(), "old-access", eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("legacy access bypass: %v", err)
	}
	if _, err := f.oauth.RefreshResource(t.Context(), "old-refresh", cid, eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("legacy refresh bypass: %v", err)
	}
	if _, err := f.oauth.ExchangeLoginResource(t.Context(), "OLD-LOGIN", cid, eventRedirect, pkce(eventVerifier), eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("legacy login bypass: %v", err)
	}
	if _, err := f.oauth.ExchangeAuthCodeResource(t.Context(), "old-auth", cid, eventRedirect, eventVerifier, eventResource); !errors.Is(err, errInvalid) {
		t.Fatalf("legacy auth bypass: %v", err)
	}
}

func TestEventLoginExchangeFailureRollsBackAndGrantSurvivesRestart(t *testing.T) {
	f := newEventFixture(t, true)
	cid, err := f.oauth.RegisterClient(t.Context(), eventRedirect)
	if err != nil {
		t.Fatal(err)
	}
	code, err := f.oauth.MintLoginCode(t.Context(), "dots")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB().Exec(`CREATE TRIGGER fail_auth BEFORE INSERT ON gw_codes WHEN NEW.kind = 'auth' BEGIN SELECT RAISE(FAIL, 'injected authorization failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.oauth.ExchangeLoginResource(t.Context(), code, cid, eventRedirect, pkce(eventVerifier), eventResource); err == nil {
		t.Fatal("expected authorization insert failure")
	}
	if _, err := f.store.DB().Exec(`DROP TRIGGER fail_auth`); err != nil {
		t.Fatal(err)
	}
	auth, err := f.oauth.ExchangeLoginResource(t.Context(), code, cid, eventRedirect, pkce(eventVerifier), eventResource)
	if err != nil {
		t.Fatalf("failed login exchange consumed code: %v", err)
	}
	tokens, err := f.oauth.ExchangeAuthCodeResource(t.Context(), auth, cid, eventRedirect, eventVerifier, eventResource)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.oauth.ValidatePrincipal(t.Context(), tokens.AccessToken, eventResource)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewOAuth(f.store.DB(), func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ConfigureEvents(eventResource, []string{"dots"}); err != nil {
		t.Fatal(err)
	}
	pRestart, err := restarted.ValidatePrincipal(t.Context(), tokens.AccessToken, eventResource)
	if err != nil || pRestart != p {
		t.Fatalf("grant lost on startup: %+v %v", pRestart, err)
	}
	if err := restarted.RevokePrincipal(t.Context(), p.ID); err != nil {
		t.Fatal(err)
	}
	if active, err := f.oauth.PrincipalActive(t.Context(), p.ID); err != nil || active {
		t.Fatalf("revocation not persistent across instances: %v %v", active, err)
	}
}

func TestEventSubscriptionRejectsInvalidParametersAndProtocol(t *testing.T) {
	f := newEventFixture(t, true)
	tokens, p := f.login(t, "dots")
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { p["name"] = "unknown" },
		func(p map[string]any) { p["arguments"].(map[string]any)["unexpected"] = "untrusted" },
		func(p map[string]any) { p["delivery"].(map[string]any)["mode"] = "poll" },
		func(p map[string]any) { p["delivery"].(map[string]any)["url"] = "http://receiver.example/events" },
		func(p map[string]any) { p["delivery"].(map[string]any)["secret"] = "invalid" },
		func(p map[string]any) { p["cursor"] = "unsupported" },
		func(p map[string]any) { p["ttlMs"] = -1 },
		func(p map[string]any) { p["ttlMs"] = 1.1 },
	} {
		params := subscriptionParams("dots")
		mutate(params)
		_, out := f.rpc(t, tokens.AccessToken, "events/subscribe", params)
		if rpcCode(out) == 0 {
			t.Fatalf("invalid parameters accepted: %+v", params)
		}
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"events/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	r := httptest.NewRequest(http.MethodPost, eventResource, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	w := httptest.NewRecorder()
	f.g.Handler().ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || rpcCode(out) == 0 {
		t.Fatalf("header/metadata protocol mismatch: %d %s", w.Code, w.Body)
	}
	subs, err := f.store.EventSubscriptions(t.Context(), p.ID, "dots")
	if err != nil || len(subs) != 0 || f.sender.verifications != 0 {
		t.Fatalf("invalid input persisted or verified: %+v %v count=%d", subs, err, f.sender.verifications)
	}
}

func TestEventMailboxRemovalAndPolicyRemovalStopAccess(t *testing.T) {
	for _, remove := range []string{"mailbox", "policy"} {
		t.Run(remove, func(t *testing.T) {
			f := newEventFixture(t, true)
			tokens, p := f.login(t, "dots")
			if remove == "mailbox" {
				if _, err := f.store.DeleteAgent(t.Context(), "dots"); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := f.oauth.ConfigureEvents(eventResource, nil); err != nil {
					t.Fatal(err)
				}
			}
			if active, err := f.oauth.PrincipalActive(t.Context(), p.ID); err != nil || active {
				t.Fatalf("removed access still permits delivery: %v %v", active, err)
			}
			if _, err := f.oauth.ValidatePrincipal(t.Context(), tokens.AccessToken, eventResource); !errors.Is(err, errInvalid) {
				t.Fatalf("removed access still permits dispatch: %v", err)
			}
			if _, err := f.oauth.RefreshResource(t.Context(), tokens.RefreshToken, p.ClientID, eventResource); !errors.Is(err, errInvalid) {
				t.Fatalf("removed access still permits refresh: %v", err)
			}
		})
	}
}
