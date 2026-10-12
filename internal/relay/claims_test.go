package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/envelope"
	"github.com/mvanhorn/agent-tincan/internal/identity"
)

const (
	claimBackendAddrA = "100.0.0.20:1"
	claimBackendAddrB = "100.0.0.21:1"
	claimBackendTag   = "tag:openai-dots-backend"
)

// These are HTTP boundary tests: actor_id in submitted JSON must never select
// an actor, even when two nodes authenticate as the same logical mailbox.
func ownedHTTPHarness(t *testing.T) (*harness, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Now().UTC().Truncate(time.Millisecond)}
	h := newHarnessDir(t, Config{Now: clock.Now, ClaimLease: time.Minute, RequireClaimOwnership: []string{"openai-dots"}},
		identity.Config{Now: clock.Now, NoAutoRebind: true, ServiceRoles: map[string]string{claimBackendTag: "openai-dots"}})
	h.st.SetClock(clock.Now)
	h.joinAt(strangerAddr, "openai-dots")
	h.who.Set(claimBackendAddrA, identity.Node{ID: "nBACKEND-A", Name: "ephemeral-one", Tags: []string{claimBackendTag}})
	h.who.Set(claimBackendAddrB, identity.Node{ID: "nBACKEND-B", Name: "ephemeral-two", Tags: []string{claimBackendTag, "tag:codex-forgejo"}})
	return h, clock
}

func claimJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func claimHTTPRequest(h *harness, addr, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.RemoteAddr = addr
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, r)
	return rec
}

func assertClaimConflict(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	var result struct {
		Error string `json:"error"`
	}
	if rec.Code != http.StatusConflict || json.Unmarshal(rec.Body.Bytes(), &result) != nil || result.Error != "claim_conflict" {
		t.Fatalf("claim conflict: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func httpOwnedClaim(t *testing.T, h *harness, addr, id, task, attempt string) envelope.ClaimOwnership {
	t.Helper()
	var got envelope.Request
	h.do(addr, http.MethodPost, "/v1/requests/"+id+"/claim", claimJSON(t, map[string]string{"task_id": task, "attempt_id": attempt}), http.StatusOK, &got)
	if got.Ownership == nil || got.Ownership.TaskID != task || got.Ownership.AttemptID != attempt || got.Ownership.LeaseGeneration <= 0 || got.Ownership.LeaseUntil.IsZero() {
		t.Fatalf("missing or invalid claim receipt: %+v", got)
	}
	return *got.Ownership
}

func TestClaimHTTPConcurrentTasksAndNodes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs [2]string
	}{
		{"same-node", [2]string{claimBackendAddrA, claimBackendAddrA}},
		{"different-nodes", [2]string{claimBackendAddrA, claimBackendAddrB}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := ownedHTTPHarness(t)
			sent := h.send(grokAddr, "openai-dots", "private operation")
			path := "/v1/requests/" + sent.ID + "/claim"
			bodies := [2]string{
				`{"task_id":"task-a","attempt_id":"attempt-1"}`,
				`{"task_id":"task-b","attempt_id":"attempt-1"}`,
			}
			var results [2]*httptest.ResponseRecorder
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range results {
				wg.Go(func() {
					<-start
					results[i] = claimHTTPRequest(h, tc.addrs[i], path, bodies[i])
				})
			}
			close(start)
			wg.Wait()
			winner := -1
			for i, rec := range results {
				if rec.Code == http.StatusOK {
					if winner >= 0 {
						t.Fatal("two concurrent task owners acquired one request")
					}
					winner = i
				} else {
					assertClaimConflict(t, rec)
				}
			}
			if winner < 0 {
				t.Fatal("no concurrent claimant succeeded")
			}
			var first, retry envelope.Request
			if err := json.Unmarshal(results[winner].Body.Bytes(), &first); err != nil {
				t.Fatal(err)
			}
			h.do(tc.addrs[winner], http.MethodPost, path, bodies[winner], http.StatusOK, &retry)
			if first.Ownership == nil || !reflect.DeepEqual(first.Ownership, retry.Ownership) {
				t.Fatalf("lost-response claim retry changed receipt: first=%+v retry=%+v", first.Ownership, retry.Ownership)
			}
			wantActor := "nBACKEND-A"
			if tc.addrs[winner] == claimBackendAddrB {
				wantActor = "nBACKEND-B"
			}
			if first.Ownership.ActorID != wantActor || first.Ownership.LeaseGeneration != 1 {
				t.Fatalf("receipt actor or generation: %+v", first.Ownership)
			}
		})
	}
}

func TestClaimHTTPMissingForgedAndForeignOwnership(t *testing.T) {
	h, _ := ownedHTTPHarness(t)
	sent := h.send(grokAddr, "openai-dots", "private operation")
	base := "/v1/requests/" + sent.ID
	owner := httpOwnedClaim(t, h, claimBackendAddrA, sent.ID, "task-a", "attempt-1")
	for _, op := range []struct{ path, body string }{
		{"/progress", `{"note":"working"}`},
		{"/reply", `{"body":"done","status":"answered"}`},
		{"/reply", `{"body":"which item?","status":"needs_input"}`},
		{"/release", `{}`},
	} {
		assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+op.path, op.body))
	}
	for _, field := range []string{"task", "attempt", "generation", "zero-generation"} {
		forged := owner
		switch field {
		case "task":
			forged.TaskID = "another-task"
		case "attempt":
			forged.AttemptID = "another-attempt"
		case "generation":
			forged.LeaseGeneration++
		case "zero-generation":
			forged.LeaseGeneration = 0
		}
		for _, op := range []string{"progress", "reply", "release"} {
			body := claimJSON(t, map[string]any{"note": "working", "body": "done", "status": "answered", "ownership": forged})
			assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/"+op, body))
		}
	}
	// B cannot borrow A's receipt by copying the server's actor_id back into JSON.
	for _, op := range []string{"progress", "reply", "release"} {
		body := claimJSON(t, map[string]any{"note": "working", "body": "done", "status": "answered", "ownership": owner})
		assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrB, base+"/"+op, body))
	}
	// A's submitted actor_id is ignored in favor of its authenticated StableID.
	owner.ActorID = "nBACKEND-B"
	h.do(claimBackendAddrA, http.MethodPost, base+"/progress", claimJSON(t, map[string]any{"note": "working", "ownership": owner}), http.StatusOK, nil)
	var res envelope.Result
	h.do(grokAddr, http.MethodGet, base+"/inspect", "", http.StatusOK, &res)
	if res.Progress == nil || res.Progress.Note != "working" || res.Request.Ownership.ActorID != "nBACKEND-A" {
		t.Fatalf("authenticated progress: %+v", res)
	}
}

func TestClaimHTTPExpiryAndAttemptHistory(t *testing.T) {
	h, clock := ownedHTTPHarness(t)
	sent := h.send(grokAddr, "openai-dots", "private operation")
	base := "/v1/requests/" + sent.ID
	stale := httpOwnedClaim(t, h, claimBackendAddrA, sent.ID, "task-a", "attempt-1")
	clock.advance(2 * time.Minute)
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/claim", `{"task_id":"task-a","attempt_id":"attempt-1"}`))
	for _, op := range []string{"progress", "reply", "release"} {
		body := claimJSON(t, map[string]any{"note": "stale", "body": "stale", "status": "answered", "ownership": stale})
		assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/"+op, body))
	}
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/reply", claimJSON(t, map[string]any{"body": "stale question?", "status": "needs_input", "ownership": stale})))
	current := httpOwnedClaim(t, h, claimBackendAddrB, sent.ID, "task-a", "attempt-2")
	if current.LeaseGeneration != stale.LeaseGeneration+1 || current.ActorID != "nBACKEND-B" {
		t.Fatalf("replacement receipt: %+v", current)
	}
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/reply", claimJSON(t, map[string]any{"body": "late done", "ownership": stale})))
	clock.advance(2 * time.Minute)
	// A delayed attempt-1 claim cannot acquire a new generation after attempt-2.
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/claim", `{"task_id":"task-a","attempt_id":"attempt-1"}`))
	latest := httpOwnedClaim(t, h, claimBackendAddrA, sent.ID, "task-a", "attempt-3")
	if latest.LeaseGeneration != current.LeaseGeneration+1 {
		t.Fatalf("third claim receipt: %+v", latest)
	}
	h.do(claimBackendAddrA, http.MethodPost, base+"/reply", claimJSON(t, map[string]any{"body": "complete", "status": "answered", "ownership": latest}), http.StatusOK, nil)
}

func TestClaimHTTPReplyAndClarificationRetries(t *testing.T) {
	h, _ := ownedHTTPHarness(t)
	sent := h.send(grokAddr, "openai-dots", "choose an item")
	base := "/v1/requests/" + sent.ID
	owner := httpOwnedClaim(t, h, claimBackendAddrA, sent.ID, "task-a", "attempt-1")
	question := claimJSON(t, map[string]any{"body": "which item?", "status": "needs_input", "ownership": owner})
	var first, retry envelope.Reply
	h.do(claimBackendAddrA, http.MethodPost, base+"/reply", question, http.StatusOK, &first)
	h.do(claimBackendAddrA, http.MethodPost, base+"/reply", question, http.StatusOK, &retry)
	if first.Generation <= 0 || !reflect.DeepEqual(first, retry) {
		t.Fatalf("clarification retry changed committed reply: first=%+v retry=%+v", first, retry)
	}
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/reply", claimJSON(t, map[string]any{"body": "changed question?", "status": "needs_input", "ownership": owner})))
	h.do(instinctAddr, http.MethodPost, base+"/answer", `{"body":"forged input"}`, http.StatusForbidden, nil)
	h.do(grokAddr, http.MethodPost, base+"/answer", `{"body":"item 2"}`, http.StatusOK, nil)
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/reply", question))
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/claim", `{"task_id":"task-a","attempt_id":"attempt-1"}`))
	owner = httpOwnedClaim(t, h, claimBackendAddrA, sent.ID, "task-a", "attempt-2")
	if owner.LeaseGeneration != 2 {
		t.Fatalf("resumed claim: %+v", owner)
	}
	terminal := claimJSON(t, map[string]any{"body": "completed item 2", "status": "answered", "ownership": owner})
	h.do(claimBackendAddrA, http.MethodPost, base+"/reply", terminal, http.StatusOK, &first)
	h.do(claimBackendAddrA, http.MethodPost, base+"/reply", terminal, http.StatusOK, &retry)
	if first.Generation != 2 || !reflect.DeepEqual(first, retry) {
		t.Fatalf("terminal retry changed reply: first=%+v retry=%+v", first, retry)
	}
	for _, status := range []string{"answered", "failed", "declined"} {
		assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/reply", claimJSON(t, map[string]any{"body": "changed terminal", "status": status, "ownership": owner})))
	}
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrB, base+"/reply", terminal))
}

func TestClaimHTTPReleaseRetriesAndStickyMigration(t *testing.T) {
	// Default remains compatible for a request that has never opted into ownership.
	h := newHarness(t, Config{})
	legacy := h.send(grokAddr, "muse", "legacy operation")
	h.do(museAddr, http.MethodPost, "/v1/requests/"+legacy.ID+"/claim", "", http.StatusOK, nil)
	h.do(museAddr, http.MethodPost, "/v1/requests/"+legacy.ID+"/reply", `{"body":"legacy complete"}`, http.StatusOK, nil)
	sent := h.send(grokAddr, "muse", "owned operation")
	base := "/v1/requests/" + sent.ID
	owner := httpOwnedClaim(t, h, museAddr, sent.ID, "task-a", "attempt-1")
	release := claimJSON(t, map[string]any{"ownership": owner})
	h.do(museAddr, http.MethodPost, base+"/release", release, http.StatusOK, nil)
	h.do(museAddr, http.MethodPost, base+"/release", release, http.StatusOK, nil)
	// Ownership is sticky on the request after release, even without config migration.
	h.do(museAddr, http.MethodPost, base+"/claim", "", http.StatusConflict, nil)
	assertClaimConflict(t, claimHTTPRequest(h, museAddr, base+"/progress", `{"note":"legacy bypass"}`))
	assertClaimConflict(t, claimHTTPRequest(h, museAddr, base+"/reply", `{"body":"legacy bypass"}`))
	current := httpOwnedClaim(t, h, museAddr, sent.ID, "task-a", "attempt-2")
	if current.LeaseGeneration != owner.LeaseGeneration+1 {
		t.Fatalf("claim after release: %+v", current)
	}
	assertClaimConflict(t, claimHTTPRequest(h, museAddr, base+"/release", release))
	h.do(museAddr, http.MethodPost, base+"/reply", claimJSON(t, map[string]any{"body": "complete", "ownership": current}), http.StatusOK, nil)
}

func TestClaimHTTPPeekAndInspectAreNonTaking(t *testing.T) {
	h, _ := ownedHTTPHarness(t)
	sent := h.send(grokAddr, "openai-dots", "private operation")
	base := "/v1/requests/" + sent.ID
	var peek struct {
		Pending []envelope.Pending `json:"pending"`
		Queued  int                `json:"queued"`
	}
	h.do(claimBackendAddrA, http.MethodGet, "/v1/peek", "", http.StatusOK, &peek)
	if peek.Queued != 1 || len(peek.Pending) != 1 || peek.Pending[0].ID != sent.ID {
		t.Fatalf("peek pending: %+v", peek)
	}
	var inspect envelope.Result
	h.do(claimBackendAddrA, http.MethodGet, base+"/inspect", "", http.StatusOK, &inspect)
	if inspect.Status != envelope.StatusQueued || inspect.Request.Body != "private operation" {
		t.Fatalf("inspect changed queued state: %+v", inspect)
	}
	_, status, err := h.st.Request(t.Context(), sent.ID)
	if err != nil || status != envelope.StatusQueued {
		t.Fatalf("non-taking read delivered request: status=%s err=%v", status, err)
	}
	owner := httpOwnedClaim(t, h, claimBackendAddrA, sent.ID, "task-a", "attempt-1")
	h.do(claimBackendAddrA, http.MethodPost, base+"/reply", claimJSON(t, map[string]any{"body": "done", "ownership": owner}), http.StatusOK, nil)
	for range 2 {
		h.do(grokAddr, http.MethodGet, base+"/inspect", "", http.StatusOK, &inspect)
		if inspect.Reply == nil || inspect.Reply.Body != "done" || inspect.Status != envelope.StatusAnswered {
			t.Fatalf("inspect reply: %+v", inspect)
		}
		if n := h.srv.UnseenReplies("grokbot"); n != 1 {
			t.Fatalf("inspect acknowledged reply: unseen=%d", n)
		}
	}
	h.do(instinctAddr, http.MethodGet, base+"/inspect", "", http.StatusNotFound, nil)
}

func TestClaimHTTPServiceRoleAuditAndBinding(t *testing.T) {
	h, _ := ownedHTTPHarness(t)
	original, found, err := h.srv.dir.Agent(t.Context(), "openai-dots")
	if err != nil || !found {
		t.Fatalf("original binding: %+v found=%v err=%v", original, found, err)
	}
	sent := h.send(grokAddr, "openai-dots", "private operation")
	base := "/v1/requests/" + sent.ID
	owner := httpOwnedClaim(t, h, claimBackendAddrB, sent.ID, "task-b", "attempt-1")
	h.do(claimBackendAddrB, http.MethodPost, base+"/progress", claimJSON(t, map[string]any{"note": "working", "ownership": owner}), http.StatusOK, nil)
	h.do(claimBackendAddrB, http.MethodPost, base+"/reply", claimJSON(t, map[string]any{"body": "done", "ownership": owner}), http.StatusOK, nil)
	roleSend := h.send(claimBackendAddrA, "muse", "role sender")
	if roleSend.From != "openai-dots" {
		t.Fatalf("logical sender: %+v", roleSend)
	}
	events, err := h.st.AuditEvents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, event := range events {
		wantActor := ""
		if event.RequestID == sent.ID && (event.Event == "claimed" || event.Event == "progress" || event.Event == "replied") {
			wantActor = "nBACKEND-B"
		} else if event.RequestID == roleSend.ID && event.Event == "queued" {
			wantActor = "nBACKEND-A"
		}
		if wantActor == "" {
			continue
		}
		var detail map[string]any
		if err := json.Unmarshal([]byte(event.Detail), &detail); err != nil {
			t.Fatal(err)
		}
		if event.Actor != wantActor || detail["agent"] != "openai-dots" {
			t.Fatalf("service role audit lost actual actor or logical mailbox: %+v", event)
		}
		seen[event.Event]++
	}
	for _, event := range []string{"claimed", "progress", "replied", "queued"} {
		if seen[event] != 1 {
			t.Fatalf("%s audit count=%d, want 1", event, seen[event])
		}
	}
	after, found, err := h.srv.dir.Agent(t.Context(), "openai-dots")
	if err != nil || !found || after.NodeID != original.NodeID || after.NodeName != original.NodeName || after.NodeUser != original.NodeUser {
		t.Fatalf("role calls changed enrolled binding: before=%+v after=%+v err=%v", original, after, err)
	}
	if _, err := h.st.VerifyAudit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestClaimHTTPServiceRoleCannotComeFromNameOrHeader(t *testing.T) {
	h, _ := ownedHTTPHarness(t)
	sent := h.send(grokAddr, "openai-dots", "private operation")
	for _, node := range []identity.Node{
		{ID: "nUNTRUSTED", Name: "openai-dots"},
		{ID: "nUNTRUSTED", Name: "codex-dots-backend-v2", Tags: []string{"tag:codex-forgejo"}},
	} {
		h.who.Set(claimBackendAddrA, node)
		h.doAs(claimBackendAddrA, "openai-dots", http.MethodPost, "/v1/requests/"+sent.ID+"/claim", `{"task_id":"task-a","attempt_id":"attempt-1"}`, http.StatusForbidden, nil)
	}
	h.who.Set(claimBackendAddrA, identity.Node{ID: "nBACKEND-A", Name: "worker", Tags: []string{claimBackendTag}})
	h.doAs(claimBackendAddrA, "muse", http.MethodPost, "/v1/requests/"+sent.ID+"/claim", `{"task_id":"task-a","attempt_id":"attempt-1"}`, http.StatusForbidden, nil)
	// A dedicated tag alone is inert until explicitly granted in config.
	defaultH := newHarness(t, Config{})
	defaultH.joinAt(strangerAddr, "openai-dots")
	defaultH.who.Set(claimBackendAddrA, identity.Node{ID: "nBACKEND-A", Name: "openai-dots", Tags: []string{claimBackendTag}})
	defaultH.doAs(claimBackendAddrA, "openai-dots", http.MethodGet, "/v1/whoami", "", http.StatusForbidden, nil)
}

func TestClaimHTTPInputValidationAndExplicitMigration(t *testing.T) {
	h, _ := ownedHTTPHarness(t)
	sent := h.send(grokAddr, "openai-dots", "private operation")
	path := "/v1/requests/" + sent.ID + "/claim"
	for _, body := range []string{"", `{}`} {
		assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, path, body))
	}
	for _, body := range []string{
		`{"task_id":"task-a"}`,
		`{"attempt_id":"attempt-1"}`,
		`{"task_id":"bad id","attempt_id":"attempt-1"}`,
		`{"task_id":"task-a","attempt_id":"attempt-1","actor_id":"nBACKEND-B"}`,
		`{"task_id":"task-a","attempt_id":"attempt-1","lease_generation":10}`,
	} {
		h.do(claimBackendAddrA, http.MethodPost, path, body, http.StatusBadRequest, nil)
	}
}
