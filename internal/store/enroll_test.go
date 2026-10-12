package store

import (
	"context"
	"errors"
	"github.com/mvanhorn/agent-tincan/internal/identity"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestCreateAgentEnrollmentCompetingBindings(t *testing.T) {
	st, c := open(t, ":memory:")
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			id := "nFIRST"
			if i%2 == 1 {
				id = "nSECOND"
			}
			_, _, err := st.CreateAgent(ctx, identity.Agent{Name: "openai-dots", NodeID: id, NodeName: "codex-environment-1", Kind: "codex", JoinedAt: c.t}, c.t)
			if err != nil && !errors.Is(err, identity.ErrEnrollmentConflict) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	a, found, err := st.AgentByName(ctx, "openai-dots")
	if err != nil || !found {
		t.Fatal(err)
	}
	loser := "nFIRST"
	if a.NodeID == loser {
		loser = "nSECOND"
	}
	if _, _, err := st.CreateAgent(ctx, identity.Agent{Name: a.Name, NodeID: loser, NodeName: a.NodeName, Kind: a.Kind, JoinedAt: c.t}, c.t); !errors.Is(err, identity.ErrEnrollmentConflict) {
		t.Fatal("loser replaced winner", err)
	}
	b, _, _ := st.AgentByName(ctx, a.Name)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("winner changed")
	}
}

func TestCreateAgentEnrollment(t *testing.T) {
	st, c := open(t, ":memory:")
	ctx := context.Background()
	existing := identity.Agent{Name: "hermes", NodeID: "nHERMES", NodeName: "hermes", Kind: "hermes", JoinedAt: c.t}
	if err := st.PutAgent(ctx, existing); err != nil {
		t.Fatal(err)
	}
	st.SetAgentGoodAt(ctx, "hermes", "retained")
	before, _, _ := st.AgentByName(ctx, "hermes")
	a := identity.Agent{Name: "openai-dots", NodeID: "nDOTS", NodeName: "codex-environment-1", Kind: "codex", JoinedAt: c.t}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, _, err := st.CreateAgent(ctx, a, c.t); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if _, created, err := st.CreateAgent(ctx, a, c.t); err != nil || created {
		t.Fatal("repeat", err)
	}
	changed := a
	changed.NodeID = "nOTHER"
	if _, _, err := st.CreateAgent(ctx, changed, c.t); !errors.Is(err, identity.ErrEnrollmentConflict) {
		t.Fatal("conflict", err)
	}
	changed = a
	changed.Kind = "hermes"
	if _, _, err := st.CreateAgent(ctx, changed, c.t); !errors.Is(err, identity.ErrEnrollmentConflict) {
		t.Fatal("kind conflict", err)
	}
	if err := st.PutInvite(ctx, identity.Invite{Code: "test", Name: "pending", Expires: c.t.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	changed = a
	changed.Name = "pending"
	if _, _, err := st.CreateAgent(ctx, changed, c.t); !errors.Is(err, identity.ErrPendingInvite) {
		t.Fatal("pending", err)
	}
	c.advance(2 * time.Hour)
	if _, created, err := st.CreateAgent(ctx, changed, c.t); err != nil || !created {
		t.Fatal("expired invite", err)
	}
	after, _, _ := st.AgentByName(ctx, "hermes")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("existing fields changed")
	}
	var invites int
	if err := st.db.QueryRow("SELECT count(*) FROM invites").Scan(&invites); err != nil || invites != 1 {
		t.Fatal("invite state changed", err)
	}
}
