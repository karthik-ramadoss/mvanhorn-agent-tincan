package relay

import (
	"context"
	"encoding/json"
	"github.com/mvanhorn/agent-tincan/internal/envelope"
	"github.com/mvanhorn/agent-tincan/internal/identity"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type enrollEvents struct{ calls int }

func (e *enrollEvents) Queued(context.Context, envelope.Request) { e.calls++ }

func TestEnrollNodeSocketOnly(t *testing.T) {
	h := newHarnessDir(t, Config{}, identity.Config{NoAutoRebind: true})
	events := &enrollEvents{}
	h.srv.SetEvents(events)
	ctx := context.Background()
	before, _ := h.st.Agents(ctx)
	h.who.Set("100.109.195.90:1", identity.Node{ID: "nDOTS", Name: "codex-environment-1"})
	h.who.SetOnline("nDOTS", true)
	body := `{"name":"openai-dots","kind":"codex","stable_id":"nDOTS","ip":"100.109.195.90","node_name":"codex-environment-1"}`
	for _, addr := range []string{macAddr, strangerAddr} {
		h.do(addr, "POST", "/v1/admin/enroll-node", body, http.StatusNotFound, nil)
	}
	req := httptest.NewRequest("POST", "/v1/admin/enroll-node", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.srv.handleEnrollNode(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatal("missing local context accepted")
	}
	h.h = h.srv.AdminHandler()
	for _, bad := range []string{strings.Replace(body, `"codex"`, `"unknown-kind"`, 1), strings.Replace(body, `"nDOTS"`, `"nOTHER"`, 1), body + ` {}`, strings.Replace(body, `"kind":`, `"unexpected":true,"kind":`, 1)} {
		h.do(macAddr, "POST", "/v1/admin/enroll-node", bad, http.StatusBadRequest, nil)
	}
	after, _ := h.st.Agents(ctx)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failure changed state")
	}
	var out struct {
		Status string
		Agent  identity.Agent
	}
	h.do(macAddr, "POST", "/v1/admin/enroll-node", body, http.StatusOK, &out)
	if out.Status != "created" || out.Agent.NodeID != "nDOTS" {
		t.Fatal(out)
	}
	h.do(macAddr, "POST", "/v1/admin/enroll-node", body, http.StatusOK, &out)
	if out.Status != "unchanged" {
		t.Fatal(out)
	}
	h.do(macAddr, "POST", "/v1/admin/enroll-node", strings.Replace(body, `"codex"`, `"hermes"`, 1), http.StatusConflict, nil)
	h.who.Set("100.109.195.90:55", identity.Node{ID: "nDOTS", Name: "codex-environment-1"})
	h.h = h.srv.Handler()
	h.do("100.109.195.90:1", "GET", "/v1/admin/audit/verify", "", http.StatusForbidden, nil)
	req = httptest.NewRequest("GET", "/v1/agents", nil)
	req.RemoteAddr = "100.109.195.90:55"
	req.Header.Set("X-Tincan-Agent", "openai-dots")
	rec = httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest("GET", "/v1/agents", nil)
	req.RemoteAddr = strangerAddr
	req.Header.Set("X-Tincan-Agent", "openai-dots")
	rec = httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatal("other node claimed identity")
	}
	for _, a := range before {
		b, _, err := h.st.AgentByName(ctx, a.Name)
		if err != nil || !reflect.DeepEqual(a, b) {
			t.Fatal("existing agent changed", a.Name)
		}
	}
	audit, err := h.st.AuditEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range audit {
		if e.Event == "enrolled_node" {
			count++
			var detail map[string]any
			if err := json.Unmarshal([]byte(e.Detail), &detail); err != nil {
				t.Fatal(err)
			}
			if len(detail) != 5 {
				t.Fatal("unexpected audit fields")
			}
		}
	}
	if count != 1 {
		t.Fatal("audit count", count)
	}
	if events.calls != 0 {
		t.Fatal("enrollment dispatched wake/work")
	}
	if ok := h.srv.dir.IsAdmin(ctx, "100.109.195.90:1"); ok {
		t.Fatal("enrollment granted admin")
	}
	if !h.srv.dir.IsAdmin(ctx, macAddr) {
		t.Fatal("existing admin lost authorization")
	}
}
