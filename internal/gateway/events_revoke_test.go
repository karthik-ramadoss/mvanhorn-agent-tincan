package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestEventHTTPTokenRevocationIsIndependentAndPreservesBinding(t *testing.T) {
	f := newEventFixture(t, true)
	a, pa := f.login(t, "dots")
	b, pb := f.login(t, "dots")
	revoke := func(token, clientID string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, eventBase+"/revoke", strings.NewReader(url.Values{"token": {token}, "client_id": {clientID}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		f.g.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	revoke(a.RefreshToken, pb.ClientID)
	if _, err := f.oauth.ValidatePrincipal(t.Context(), a.AccessToken, eventResource); err != nil {
		t.Fatalf("wrong client revoked: %v", err)
	}
	revoke(a.RefreshToken, pa.ClientID)
	revoke(a.RefreshToken, pa.ClientID)
	if active, err := f.oauth.PrincipalActive(t.Context(), pa.ID); err != nil || active {
		t.Fatal(active, err)
	}
	if _, err := f.oauth.ValidatePrincipal(t.Context(), b.AccessToken, eventResource); err != nil {
		t.Fatal(err)
	}
	if _, err := f.oauth.RefreshResource(t.Context(), a.RefreshToken, pa.ClientID, eventResource); err == nil {
		t.Fatal("revoked refresh worked")
	}
	agent, ok, err := f.store.AgentByName(t.Context(), "dots")
	if err != nil || !ok || agent.NodeID != "node-backend" {
		t.Fatal(agent, ok, err)
	}
}
