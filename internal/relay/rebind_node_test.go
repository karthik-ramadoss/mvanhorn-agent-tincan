package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/mvanhorn/agent-tincan/internal/identity"
)

func TestRebindNodeLocalOnlyPreservesAgentsAndSwitchesAccess(t *testing.T) {
	h := newHarnessDir(t, Config{}, identity.Config{NoAutoRebind: true})
	ctx := context.Background()
	events := &enrollEvents{}
	h.srv.SetEvents(events)
	before, _ := h.st.Agents(ctx)
	h.who.Set("100.83.239.89:1", identity.Node{ID: "nNEW", Name: "codex-environment-5"})
	h.who.SetOnline("nNEW", true)
	body := `{"name":"muse","expected_old_node_id":"nMUSE","stable_id":"nNEW","ip":"100.83.239.89","node_name":"codex-environment-5"}`
	for _, addr := range []string{macAddr, strangerAddr} {
		h.do(addr, "POST", "/v1/admin/rebind-node", body, http.StatusNotFound, nil)
	}
	r := httptest.NewRequest("POST", "/v1/admin/rebind-node", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.srv.handleRebindNode(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("nonlocal handler accepted")
	}
	h.h = h.srv.AdminHandler()
	for _, bad := range []string{strings.Replace(body, `"nMUSE"`, `"nSTALE"`, 1), strings.Replace(body, `"nMUSE"`, `""`, 1), strings.Replace(body, `"nNEW"`, `"nOTHER"`, 1), body + ` {}`, strings.Replace(body, `"name":`, `"unknown":true,"name":`, 1)} {
		want := http.StatusBadRequest
		if strings.Contains(bad, "nSTALE") {
			want = http.StatusConflict
		}
		h.do(macAddr, "POST", "/v1/admin/rebind-node", bad, want, nil)
	}
	after, _ := h.st.Agents(ctx)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failure changed agents")
	}
	h.do(macAddr, "POST", "/v1/admin/rebind-node", body, http.StatusOK, nil)
	h.do(macAddr, "POST", "/v1/admin/rebind-node", body, http.StatusConflict, nil)
	for _, a := range before {
		got, _, _ := h.st.AgentByName(ctx, a.Name)
		if a.Name == "muse" {
			a.NodeID = "nNEW"
			a.NodeName = "codex-environment-5"
			a.NodeUser = ""
		}
		if !reflect.DeepEqual(a, got) {
			t.Fatal("metadata changed", a.Name)
		}
	}
	h.h = h.srv.Handler()
	for _, tc := range []struct {
		addr   string
		status int
	}{{"100.83.239.89:1", http.StatusOK}, {museAddr, http.StatusForbidden}, {strangerAddr, http.StatusForbidden}} {
		r := httptest.NewRequest("GET", "/v1/agents", nil)
		r.RemoteAddr = tc.addr
		r.Header.Set("X-Tincan-Agent", "muse")
		w := httptest.NewRecorder()
		h.h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal("access", tc.addr, w.Code)
		}
	}
	ev, _ := h.st.AuditEvents(ctx)
	count := 0
	for _, e := range ev {
		if e.Event == "rebound_node" {
			count++
		}
	}
	if count != 1 || events.calls != 0 {
		t.Fatal("unexpected audit or wake", count, events.calls)
	}
	if _, err := h.st.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if h.srv.dir.IsAdmin(ctx, "100.83.239.89:1") {
		t.Fatal("target became admin")
	}
}
