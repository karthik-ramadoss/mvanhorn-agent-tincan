package identity_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/identity"
	"github.com/mvanhorn/agent-tincan/internal/identity/identitytest"
)

const dotsRoleTag = "tag:openai-dots-backend"

type serviceRoleStore struct {
	*identity.MemoryStore
	writes atomic.Int32
}

func (s *serviceRoleStore) PutAgent(ctx context.Context, a identity.Agent) error {
	s.writes.Add(1)
	return s.MemoryStore.PutAgent(ctx, a)
}

func (s *serviceRoleStore) CreateAgent(ctx context.Context, a identity.Agent, now time.Time) (identity.Agent, bool, error) {
	s.writes.Add(1)
	return s.MemoryStore.CreateAgent(ctx, a, now)
}

func (s *serviceRoleStore) ReplaceAgentNode(ctx context.Context, name, expectedOld string, n identity.Node, now time.Time) (identity.Agent, error) {
	s.writes.Add(1)
	return s.MemoryStore.ReplaceAgentNode(ctx, name, expectedOld, n, now)
}

type countedRoleResolver struct {
	identity.Resolver
	calls atomic.Int32
}

func (r *countedRoleResolver) WhoIs(ctx context.Context, addr string) (identity.Node, error) {
	r.calls.Add(1)
	return r.Resolver.WhoIs(ctx, addr)
}

func roleFixture(t *testing.T, cfg identity.Config, nodes map[string]identity.Node) (*identity.Directory, *serviceRoleStore, *countedRoleResolver, identity.Agent) {
	t.Helper()
	store := &serviceRoleStore{MemoryStore: identity.NewMemoryStore()}
	a := identity.Agent{Name: "openai-dots", NodeID: "nENROLLED", NodeName: "original-backend", NodeUser: "original-owner@example.test", Kind: "codex", JoinedAt: time.Unix(1790000000, 0)}
	if err := store.MemoryStore.PutAgent(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	who := &countedRoleResolver{Resolver: identitytest.New(nodes)}
	return identity.NewDirectory(store, who, cfg), store, who, a
}

func TestServiceRoleNodeReplacementPreservesBindingAndActualActor(t *testing.T) {
	ctx := context.Background()
	dir, store, who, original := roleFixture(t, identity.Config{ServiceRoles: map[string]string{dotsRoleTag: "openai-dots"}}, map[string]identity.Node{
		"100.64.0.1:1": {ID: "nBACKEND1", Name: "ephemeral-one", User: "other@example.test", Tags: []string{dotsRoleTag}},
		"100.64.0.2:1": {ID: "nBACKEND2", Name: "ephemeral-two", Tags: []string{dotsRoleTag, "tag:codex-forgejo"}},
	})
	for addr, actor := range map[string]string{"100.64.0.1:1": "nBACKEND1", "100.64.0.2:1": "nBACKEND2"} {
		for _, claimed := range []string{"", "openai-dots"} {
			res, actual, err := dir.ResolveActor(ctx, addr, claimed)
			if err != nil || res.Name != "openai-dots" || actual != actor || res.Rebind != nil || !res.ServiceRole {
				t.Fatalf("resolve %s claimed %q: result=%+v actor=%q err=%v", addr, claimed, res, actual, err)
			}
		}
	}
	if who.calls.Load() != 4 {
		t.Fatalf("WhoIs called %d times for four calls", who.calls.Load())
	}
	if store.writes.Load() != 0 {
		t.Fatalf("service role made %d identity writes", store.writes.Load())
	}
	stored, found, err := dir.Agent(ctx, original.Name)
	if err != nil || !found || !reflect.DeepEqual(stored, original) {
		t.Fatalf("enrolled identity changed: %+v found=%v err=%v", stored, found, err)
	}
}

func TestServiceRoleConcurrentActorsRemainDistinct(t *testing.T) {
	dir, store, _, _ := roleFixture(t, identity.Config{ServiceRoles: map[string]string{dotsRoleTag: "openai-dots"}}, map[string]identity.Node{
		"100.64.0.1:1": {ID: "nBACKEND1", Name: "worker", Tags: []string{dotsRoleTag}},
		"100.64.0.2:1": {ID: "nBACKEND2", Name: "worker", Tags: []string{dotsRoleTag}},
	})
	var wg sync.WaitGroup
	for i := range 32 {
		addr, want := "100.64.0.1:1", "nBACKEND1"
		if i%2 != 0 {
			addr, want = "100.64.0.2:1", "nBACKEND2"
		}
		wg.Go(func() {
			res, actor, err := dir.ResolveActor(context.Background(), addr, "openai-dots")
			if err != nil || res.Name != "openai-dots" || actor != want {
				t.Errorf("concurrent resolve: %+v %q %v; want actor %s", res, actor, err, want)
			}
		})
	}
	wg.Wait()
	if store.writes.Load() != 0 {
		t.Fatalf("concurrent role resolution wrote identity %d times", store.writes.Load())
	}
}

func TestServiceRoleDisabledByDefault(t *testing.T) {
	dir, store, _, _ := roleFixture(t, identity.Config{}, map[string]identity.Node{
		"100.64.0.1:1": {ID: "nBACKEND", Name: "original-backend", Tags: []string{dotsRoleTag}},
		"100.64.0.2:1": {ID: "nENROLLED", Name: "original-backend", Tags: []string{dotsRoleTag}},
	})
	if _, _, err := dir.ResolveActor(context.Background(), "100.64.0.1:1", "openai-dots"); !errors.Is(err, identity.ErrNotJoined) {
		t.Fatalf("role without explicit config: %v", err)
	}
	res, actor, err := dir.ResolveActor(context.Background(), "100.64.0.2:1", "openai-dots")
	if err != nil || res.Name != "openai-dots" || actor != "nENROLLED" || res.ServiceRole {
		t.Fatalf("normal enrolled node: %+v %q %v", res, actor, err)
	}
	if store.writes.Load() != 0 {
		t.Fatalf("default resolution changed tagged node binding")
	}
}

func TestServiceRoleRequiresVerifiedTagAndMatchingClaim(t *testing.T) {
	for _, tc := range []struct {
		name    string
		node    identity.Node
		claimed string
	}{
		{name: "mailbox machine name", node: identity.Node{ID: "nNEW", Name: "openai-dots"}, claimed: "openai-dots"},
		{name: "role machine name", node: identity.Node{ID: "nNEW", Name: dotsRoleTag}, claimed: "openai-dots"},
		{name: "same machine and owner", node: identity.Node{ID: "nNEW", Name: "original-backend", User: "original-owner@example.test", Tags: []string{"tag:codex-forgejo"}}, claimed: "openai-dots"},
		{name: "claimed header alone", node: identity.Node{ID: "nNEW", Name: "random"}, claimed: "openai-dots"},
		{name: "shared backend tag", node: identity.Node{ID: "nNEW", Tags: []string{"tag:codex-forgejo"}}, claimed: "openai-dots"},
		{name: "wrong claimed agent", node: identity.Node{ID: "nNEW", Tags: []string{dotsRoleTag}}, claimed: "history"},
		{name: "missing stable ID", node: identity.Node{Tags: []string{dotsRoleTag}}, claimed: "openai-dots"},
		{name: "virtual ID", node: identity.Node{ID: identity.VirtualAddr("openai-dots"), Tags: []string{dotsRoleTag}}, claimed: "openai-dots"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, store, _, _ := roleFixture(t, identity.Config{ServiceRoles: map[string]string{dotsRoleTag: "openai-dots"}}, map[string]identity.Node{"100.64.0.1:1": tc.node})
			if _, actor, err := dir.ResolveActor(context.Background(), "100.64.0.1:1", tc.claimed); !errors.Is(err, identity.ErrNotJoined) || actor != "" {
				t.Fatalf("unauthorized caller: actor=%q err=%v", actor, err)
			}
			if store.writes.Load() != 0 {
				t.Fatalf("unauthorized role call wrote identity")
			}
		})
	}
}

func TestServiceRoleRequiresExistingMailboxAndRevokesOnRemoval(t *testing.T) {
	dir, store, _, _ := roleFixture(t, identity.Config{ServiceRoles: map[string]string{dotsRoleTag: "openai-dots"}}, map[string]identity.Node{
		"100.64.0.1:1": {ID: "nBACKEND", Tags: []string{dotsRoleTag}},
	})
	ctx := context.Background()
	if _, _, err := dir.ResolveActor(ctx, "100.64.0.1:1", "openai-dots"); err != nil {
		t.Fatal(err)
	}
	if err := dir.Remove(ctx, identity.LocalAdmin, "openai-dots"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dir.ResolveActor(ctx, "100.64.0.1:1", "openai-dots"); !errors.Is(err, identity.ErrNotJoined) {
		t.Fatalf("removed mailbox still authorized: %v", err)
	}
	if agents, err := dir.Agents(ctx); err != nil || len(agents) != 0 || store.writes.Load() != 0 {
		t.Fatalf("role auto-enrolled mailbox: agents=%+v err=%v writes=%d", agents, err, store.writes.Load())
	}
}

func TestServiceRoleConflictsCannotBeSelectedByHeader(t *testing.T) {
	dir, store, _, _ := roleFixture(t, identity.Config{ServiceRoles: map[string]string{dotsRoleTag: "openai-dots", "tag:other-backend": "other"}}, map[string]identity.Node{
		"100.64.0.1:1": {ID: "nBACKEND", Tags: []string{dotsRoleTag, "tag:other-backend"}},
	})
	for _, claimed := range []string{"", "openai-dots", "other"} {
		if _, _, err := dir.ResolveActor(context.Background(), "100.64.0.1:1", claimed); !errors.Is(err, identity.ErrAgentAmbiguous) {
			t.Fatalf("conflicting roles claimed %q: %v", claimed, err)
		}
	}
	if store.writes.Load() != 0 {
		t.Fatalf("ambiguous resolution wrote identity")
	}
}

func TestServiceRoleDoesNotGrantAdmin(t *testing.T) {
	dir, _, _, _ := roleFixture(t, identity.Config{Admins: []string{"admin-machine"}, ServiceRoles: map[string]string{dotsRoleTag: "openai-dots"}}, map[string]identity.Node{
		"100.64.0.1:1": {ID: "nBACKEND", Name: "admin-machine", Tags: []string{dotsRoleTag}},
	})
	if dir.IsAdmin(context.Background(), "100.64.0.1:1") {
		t.Fatal("role holder is an admin")
	}
	if _, err := dir.Invite(context.Background(), "100.64.0.1:1", "new-agent"); !errors.Is(err, identity.ErrNotAdmin) {
		t.Fatalf("role holder invited agent: %v", err)
	}
}

func TestServiceRoleConfigCopiedAtConstruction(t *testing.T) {
	roles := map[string]string{dotsRoleTag: "openai-dots"}
	dir, _, _, _ := roleFixture(t, identity.Config{ServiceRoles: roles}, map[string]identity.Node{
		"100.64.0.1:1": {ID: "nBACKEND1", Tags: []string{dotsRoleTag}},
		"100.64.0.2:1": {ID: "nBACKEND2", Tags: []string{"tag:codex-forgejo"}},
	})
	roles[dotsRoleTag] = "history"
	roles["tag:codex-forgejo"] = "openai-dots"
	if name, err := dir.Resolve(context.Background(), "100.64.0.1:1", "openai-dots"); err != nil || name != "openai-dots" {
		t.Fatalf("original grant mutated: %q %v", name, err)
	}
	if _, err := dir.Resolve(context.Background(), "100.64.0.2:1", "openai-dots"); !errors.Is(err, identity.ErrNotJoined) {
		t.Fatalf("post-construction grant accepted: %v", err)
	}
}

func TestEmptyServiceRoleConfigCopiedAtConstruction(t *testing.T) {
	roles := map[string]string{}
	dir, _, _, _ := roleFixture(t, identity.Config{ServiceRoles: roles}, map[string]identity.Node{
		"100.64.0.1:1": {ID: "nBACKEND", Tags: []string{dotsRoleTag}},
	})
	roles[dotsRoleTag] = "openai-dots"
	if _, err := dir.Resolve(context.Background(), "100.64.0.1:1", "openai-dots"); !errors.Is(err, identity.ErrNotJoined) {
		t.Fatalf("post-construction initial grant accepted: %v", err)
	}
}

func TestValidateServiceRoles(t *testing.T) {
	for _, roles := range []map[string]string{nil, {}, {dotsRoleTag: "openai-dots"}} {
		if err := identity.ValidateServiceRoles(roles); err != nil {
			t.Fatalf("valid role configuration %+v: %v", roles, err)
		}
	}
	for _, roles := range []map[string]string{
		{"tag:codex-forgejo": "openai-dots"},
		{"openai-dots-backend": "openai-dots"},
		{"tag:": "openai-dots"},
		{"tag:-backend": "openai-dots"},
		{"tag:Backend": "openai-dots"},
		{"tag:backend.role": "openai-dots"},
		{"tag:backend role": "openai-dots"},
		{dotsRoleTag: ""},
		{dotsRoleTag: "OpenAI-Dots"},
		{dotsRoleTag: "openai-dots/other"},
	} {
		if err := identity.ValidateServiceRoles(roles); err == nil {
			t.Fatalf("invalid role configuration accepted: %+v", roles)
		}
	}
}

func TestInvalidServiceRoleConfigFailsClosed(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("invalid role grant did not fail construction")
		}
	}()
	identity.NewDirectory(identity.NewMemoryStore(), identitytest.New(nil), identity.Config{ServiceRoles: map[string]string{"tag:codex-forgejo": "openai-dots"}})
}

func TestResolveActorRetainsRebindResultAndSingleWhoIs(t *testing.T) {
	dir, store, who, original := roleFixture(t, identity.Config{}, map[string]identity.Node{
		"100.64.0.1:1": {ID: "nREBUILT", Name: "original-backend-1", User: "original-owner@example.test"},
	})
	res, actor, err := dir.ResolveActor(context.Background(), "100.64.0.1:1", "openai-dots")
	if err != nil || res.Name != "openai-dots" || actor != "nREBUILT" || res.Rebind == nil || res.Rebind.OldNode != original.NodeID || res.ServiceRole {
		t.Fatalf("normal rebind result lost: %+v actor=%q err=%v", res, actor, err)
	}
	if who.calls.Load() != 1 || store.writes.Load() != 1 {
		t.Fatalf("normal rebind: WhoIs=%d writes=%d", who.calls.Load(), store.writes.Load())
	}
}
