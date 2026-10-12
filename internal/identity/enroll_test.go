package identity_test

import (
	"context"
	"errors"
	"github.com/mvanhorn/agent-tincan/internal/identity"
	"sync"
	"testing"
	"time"
)

type enrollResolver struct {
	node          identity.Node
	err           error
	online, found bool
	statusErr     error
}

func (r enrollResolver) WhoIs(context.Context, string) (identity.Node, error) { return r.node, r.err }
func (r enrollResolver) NodeOnline(context.Context, string) (bool, bool, error) {
	return r.online, r.found, r.statusErr
}

type noStatusResolver struct{}

func (noStatusResolver) WhoIs(context.Context, string) (identity.Node, error) {
	return identity.Node{ID: "nDOTS", Name: "codex-environment-1"}, nil
}

func TestEnrollNodeValidation(t *testing.T) {
	ctx := context.Background()
	base := enrollResolver{node: identity.Node{ID: "nDOTS", Name: "codex-environment-1"}, online: true, found: true}
	for _, tc := range []struct {
		name, remote, agent, kind, id, ip, dns string
		resolver                               identity.Resolver
	}{
		{"not-local", "100.64.0.2:1", "openai-dots", "codex", "nDOTS", "100.109.195.90", "codex-environment-1", base},
		{"name", identity.LocalAdmin, "Bad Name", "codex", "nDOTS", "100.109.195.90", "codex-environment-1", base},
		{"kind", identity.LocalAdmin, "openai-dots", "", "nDOTS", "100.109.195.90", "codex-environment-1", base},
		{"id-mismatch", identity.LocalAdmin, "openai-dots", "codex", "nOTHER", "100.109.195.90", "codex-environment-1", base},
		{"dns-mismatch", identity.LocalAdmin, "openai-dots", "codex", "nDOTS", "100.109.195.90", "codex-environment", base},
		{"hostname", identity.LocalAdmin, "openai-dots", "codex", "nDOTS", "codex-environment-1", "codex-environment-1", base},
		{"non-tailnet", identity.LocalAdmin, "openai-dots", "codex", "nDOTS", "192.168.8.45", "codex-environment-1", base},
		{"whois-error", identity.LocalAdmin, "openai-dots", "codex", "nDOTS", "100.109.195.90", "codex-environment-1", enrollResolver{err: errors.New("down")}},
		{"offline", identity.LocalAdmin, "openai-dots", "codex", "nDOTS", "100.109.195.90", "codex-environment-1", enrollResolver{node: base.node, found: true}},
		{"missing", identity.LocalAdmin, "openai-dots", "codex", "nDOTS", "100.109.195.90", "codex-environment-1", enrollResolver{node: base.node, online: true}},
		{"status-error", identity.LocalAdmin, "openai-dots", "codex", "nDOTS", "100.109.195.90", "codex-environment-1", enrollResolver{node: base.node, statusErr: errors.New("down")}},
		{"no-status", identity.LocalAdmin, "openai-dots", "codex", "nDOTS", "100.109.195.90", "codex-environment-1", noStatusResolver{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := identity.NewMemoryStore()
			d := identity.NewDirectory(st, tc.resolver, identity.Config{NoAutoRebind: true})
			if _, _, err := d.EnrollNode(ctx, tc.remote, tc.agent, tc.kind, tc.id, tc.ip, tc.dns); err == nil {
				t.Fatal("accepted invalid enrollment")
			}
			a, _ := st.Agents(ctx)
			if len(a) != 0 {
				t.Fatal("changed state")
			}
		})
	}
}

func TestEnrollNodeConcurrentAndPending(t *testing.T) {
	ctx := context.Background()
	st := identity.NewMemoryStore()
	now := time.Now()
	r := enrollResolver{node: identity.Node{ID: "nDOTS", Name: "codex-environment-1"}, online: true, found: true}
	d := identity.NewDirectory(st, r, identity.Config{NoAutoRebind: true})
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, _, err := d.EnrollNode(ctx, identity.LocalAdmin, "openai-dots", "codex", "nDOTS", "100.109.195.90", "codex-environment-1"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if _, created, err := d.EnrollNode(ctx, identity.LocalAdmin, "openai-dots", "codex", "nDOTS", "100.109.195.90", "codex-environment-1"); err != nil || created {
		t.Fatal("repeat was not unchanged", err)
	}
	if _, _, err := st.CreateAgent(ctx, identity.Agent{Name: "openai-dots", NodeID: "other", Kind: "codex"}, now); !errors.Is(err, identity.ErrEnrollmentConflict) {
		t.Fatal("overwrote binding", err)
	}
	if err := st.PutInvite(ctx, identity.Invite{Name: "pending", Code: "test-digest", Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.EnrollNode(ctx, identity.LocalAdmin, "pending", "codex", "nDOTS", "100.109.195.90", "codex-environment-1"); !errors.Is(err, identity.ErrPendingInvite) {
		t.Fatal("accepted pending invitation", err)
	}
}
