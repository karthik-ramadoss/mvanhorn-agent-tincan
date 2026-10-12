package store

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/identity"
)

func TestReplaceAgentNodePreservesStateAndAudits(t *testing.T) {
	s, c := open(t, ":memory:")
	ctx := context.Background()
	a := identity.Agent{Name: "openai-dots", NodeID: "nOLD", NodeName: "old", NodeUser: "old-owner", Kind: "codex", JoinedAt: c.t}
	if err := s.PutAgent(ctx, a); err != nil {
		t.Fatal(err)
	}
	s.SetAgentGoodAt(ctx, a.Name, "retained")
	if _, err := s.db.Exec(`UPDATE agents SET last_seen_at=123,version='retained-version',features='retained-features',poll_features='retained-poll' WHERE name=?`, a.Name); err != nil {
		t.Fatal(err)
	}
	req := ask(t, s, a.Name, "muse", "dummy preserved request")
	var beforeStatus, beforeBody string
	if err := s.db.QueryRow(`SELECT status,body FROM requests WHERE id=?`, req.ID).Scan(&beforeStatus, &beforeBody); err != nil {
		t.Fatal(err)
	}
	before, _, _ := s.AgentByName(ctx, a.Name)
	got, err := s.ReplaceAgentNode(ctx, a.Name, "nOLD", identity.Node{ID: "nNEW", Name: "new", User: "new-owner"}, c.t)
	if err != nil {
		t.Fatal(err)
	}
	want := before
	want.JoinedAt = want.JoinedAt.UTC()
	want.NodeID = "nNEW"
	want.NodeName = "new"
	want.NodeUser = "new-owner"
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("agent: %#v != %#v", got, want)
	}
	var seen int
	var version, features, poll string
	if err := s.db.QueryRow(`SELECT last_seen_at,version,features,poll_features FROM agents WHERE name=?`, a.Name).Scan(&seen, &version, &features, &poll); err != nil {
		t.Fatal(err)
	}
	if seen != 123 || version != "retained-version" || features != "retained-features" || poll != "retained-poll" {
		t.Fatal("metadata changed")
	}
	var status, body string
	if err := s.db.QueryRow(`SELECT status,body FROM requests WHERE id=?`, req.ID).Scan(&status, &body); err != nil {
		t.Fatal(err)
	}
	if status != beforeStatus || body != beforeBody {
		t.Fatal("request changed")
	}
	ev, err := s.AuditEvents(ctx)
	if err != nil || len(ev) != 1 || ev[0].Event != "rebound_node" || ev[0].Actor != identity.LocalAdmin {
		t.Fatal("audit", ev, err)
	}
	if _, err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceAgentNode(ctx, a.Name, "nOLD", identity.Node{ID: "nLATER", Name: "later"}, c.t); !errors.Is(err, identity.ErrEnrollmentConflict) {
		t.Fatal("stale move", err)
	}
}

func TestReplaceAgentNodeAuditFailureRollsBack(t *testing.T) {
	s, c := open(t, ":memory:")
	ctx := context.Background()
	a := identity.Agent{Name: "openai-dots", NodeID: "nOLD", NodeName: "old", JoinedAt: c.t}
	if err := s.PutAgent(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_rebind_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceAgentNode(ctx, a.Name, "nOLD", identity.Node{ID: "nNEW", Name: "new"}, c.t); err == nil {
		t.Fatal("audit failure accepted")
	}
	got, _, _ := s.AgentByName(ctx, a.Name)
	if !reflect.DeepEqual(got, a) {
		t.Fatal("failed transaction changed binding")
	}
}

func TestReplaceAgentNodeConcurrentCASAndPending(t *testing.T) {
	s, c := open(t, ":memory:")
	ctx := context.Background()
	a := identity.Agent{Name: "openai-dots", NodeID: "nOLD", NodeName: "old", JoinedAt: c.t}
	if err := s.PutAgent(ctx, a); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for _, id := range []string{"nONE", "nTWO"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, err := s.ReplaceAgentNode(ctx, a.Name, "nOLD", identity.Node{ID: id, Name: "new"}, c.t)
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(err, identity.ErrEnrollmentConflict) {
				t.Error(err)
			}
		}(id)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatal("winners", wins)
	}
	ev, _ := s.AuditEvents(ctx)
	if len(ev) != 1 {
		t.Fatal("audit", len(ev))
	}
	got, _, _ := s.AgentByName(ctx, a.Name)
	if err := s.PutInvite(ctx, identity.Invite{Name: a.Name, Code: "dummy-digest", Expires: c.t.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceAgentNode(ctx, a.Name, got.NodeID, identity.Node{ID: "nTHREE", Name: "third"}, c.t); !errors.Is(err, identity.ErrPendingInvite) {
		t.Fatal(err)
	}
	if _, err := s.ReplaceAgentNode(ctx, "missing", "nOLD", identity.Node{ID: "nTHREE", Name: "third"}, c.t); !errors.Is(err, identity.ErrEnrollmentConflict) {
		t.Fatal("missing agent", err)
	}
}
