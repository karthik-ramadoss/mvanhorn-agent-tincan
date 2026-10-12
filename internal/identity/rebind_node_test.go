package identity_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/identity"
)

func TestRebindNodeValidation(t *testing.T) {
	ctx := context.Background()
	base := enrollResolver{node: identity.Node{ID: "nNEW", Name: "codex-environment-5"}, online: true, found: true}
	for _, tc := range []struct {
		name, remote, agent, old, id, ip, dns string
		r                                     identity.Resolver
	}{
		{"not-local", "100.64.0.2:1", "openai-dots", "nOLD", "nNEW", "100.83.239.89", "codex-environment-5", base},
		{"stale", identity.LocalAdmin, "openai-dots", "nOTHER", "nNEW", "100.83.239.89", "codex-environment-5", base},
		{"missing-old", identity.LocalAdmin, "openai-dots", "", "nNEW", "100.83.239.89", "codex-environment-5", base},
		{"same-node", identity.LocalAdmin, "openai-dots", "nNEW", "nNEW", "100.83.239.89", "codex-environment-5", base},
		{"id-mismatch", identity.LocalAdmin, "openai-dots", "nOLD", "nOTHER", "100.83.239.89", "codex-environment-5", base},
		{"dns-mismatch", identity.LocalAdmin, "openai-dots", "nOLD", "nNEW", "100.83.239.89", "other", base},
		{"non-tailnet", identity.LocalAdmin, "openai-dots", "nOLD", "nNEW", "192.168.8.45", "codex-environment-5", base},
		{"whois-failed", identity.LocalAdmin, "openai-dots", "nOLD", "nNEW", "100.83.239.89", "codex-environment-5", enrollResolver{err: errors.New("down")}},
		{"offline", identity.LocalAdmin, "openai-dots", "nOLD", "nNEW", "100.83.239.89", "codex-environment-5", enrollResolver{node: base.node, found: true}},
		{"missing", identity.LocalAdmin, "openai-dots", "nOLD", "nNEW", "100.83.239.89", "codex-environment-5", enrollResolver{node: base.node, online: true}},
		{"status-failed", identity.LocalAdmin, "openai-dots", "nOLD", "nNEW", "100.83.239.89", "codex-environment-5", enrollResolver{node: base.node, statusErr: errors.New("down")}},
		{"no-status", identity.LocalAdmin, "openai-dots", "nOLD", "nDOTS", "100.83.239.89", "codex-environment-1", noStatusResolver{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := identity.NewMemoryStore()
			a := identity.Agent{Name: "openai-dots", NodeID: "nOLD", NodeName: "old", Kind: "codex", JoinedAt: time.Now()}
			st.PutAgent(ctx, a)
			d := identity.NewDirectory(st, tc.r, identity.Config{NoAutoRebind: true})
			if _, err := d.RebindNode(ctx, tc.remote, tc.agent, tc.old, tc.id, tc.ip, tc.dns); err == nil {
				t.Fatal("invalid move accepted")
			}
			got, _, _ := st.AgentByName(ctx, a.Name)
			if !reflect.DeepEqual(a, got) {
				t.Fatal("binding changed")
			}
		})
	}
}
