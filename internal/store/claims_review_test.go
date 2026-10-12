package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/envelope"
)

func ownedNotify(t *testing.T, s *Store) (envelope.Request, envelope.ClaimOwnership) {
	t.Helper()
	req, err := s.Enqueue(t.Context(), envelope.Request{From: "sender", To: "receiver", Kind: envelope.KindNotify, Body: "notice", Chain: []string{}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node-a", "task-a", "attempt-1"), time.Minute)
	if err != nil || claimed.Ownership == nil || !claimed.Ownership.LeaseUntil.IsZero() {
		t.Fatalf("notify claim = %+v, %v", claimed, err)
	}
	return req, *claimed.Ownership
}

func assertOwnedMutationsConflict(t *testing.T, s *Store, id string, owner envelope.ClaimOwnership) {
	t.Helper()
	ctx := WithClaimOwner(t.Context(), owner)
	if err := s.SetProgress(ctx, id, "receiver", "stale progress", time.Minute); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("progress = %v", err)
	}
	if _, err := s.Reply(ctx, id, "receiver", envelope.Reply{Status: envelope.StatusAnswered, Body: "stale reply"}); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("reply = %v", err)
	}
	if transitioned, err := s.ReleaseOwned(t.Context(), id, "receiver", owner); transitioned || !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("release = %v, %v", transitioned, err)
	}
}

func TestOwnedNotifySurvivesSweepWithoutAClaimLease(t *testing.T) {
	s, c := open(t, ":memory:")
	req, owner := ownedNotify(t, s)
	c.advance(2 * time.Minute)
	if transitions, err := s.Sweep(t.Context()); err != nil || len(transitions) != 0 {
		t.Fatalf("notify sweep = %+v, %v", transitions, err)
	}
	retry, err := s.ClaimOwned(t.Context(), req.ID, "receiver", owner, time.Minute)
	if err != nil || retry.Ownership.LeaseGeneration != owner.LeaseGeneration || !retry.Ownership.LeaseUntil.IsZero() {
		t.Fatalf("notify retry = %+v, %v", retry, err)
	}
	for _, competing := range []envelope.ClaimOwnership{
		claimTuple("node-b", owner.TaskID, owner.AttemptID),
		claimTuple(owner.ActorID, "task-b", owner.AttemptID),
		claimTuple(owner.ActorID, owner.TaskID, "attempt-2"),
	} {
		if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", competing, time.Minute); !errors.Is(err, ErrClaimConflict) {
			t.Fatalf("competing notify claim = %v", err)
		}
		competing.LeaseGeneration = owner.LeaseGeneration
		assertOwnedMutationsConflict(t, s, req.ID, competing)
	}
	wrongGeneration := owner
	wrongGeneration.LeaseGeneration++
	assertOwnedMutationsConflict(t, s, req.ID, wrongGeneration)
	ctx := WithClaimOwner(t.Context(), owner)
	if err := s.SetProgress(ctx, req.ID, "receiver", "notice handled", time.Minute); err != nil {
		t.Fatal(err)
	}
	current, status, err := s.Request(t.Context(), req.ID)
	if err != nil || status != envelope.StatusClaimed || !current.Ownership.LeaseUntil.IsZero() {
		t.Fatalf("progress gave notify a lease: %+v, %s, %v", current, status, err)
	}
	reply := envelope.Reply{Status: envelope.StatusAnswered, Body: "optional acknowledgement"}
	first, err := s.Reply(ctx, req.ID, "receiver", reply)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Reply(ctx, req.ID, "receiver", reply)
	if err != nil || first.Generation != second.Generation || !first.CreatedAt.Equal(second.CreatedAt) {
		t.Fatalf("notify reply retry = %+v, %v", second, err)
	}
}

func TestOwnedNotifyReleaseRetiresAttemptAndReportsOnlyTransitions(t *testing.T) {
	s, c := open(t, ":memory:")
	req, owner := ownedNotify(t, s)
	c.advance(2 * time.Minute)
	if transitioned, err := s.ReleaseOwned(t.Context(), req.ID, "receiver", owner); err != nil || !transitioned {
		t.Fatalf("notify release = %v, %v", transitioned, err)
	}
	if transitioned, err := s.ReleaseOwned(t.Context(), req.ID, "receiver", owner); err != nil || transitioned {
		t.Fatalf("release retry = %v, %v", transitioned, err)
	}
	if _, err := s.Deliver(t.Context(), "receiver", 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	if transitioned, err := s.ReleaseOwned(t.Context(), req.ID, "receiver", owner); err != nil || transitioned {
		t.Fatalf("delivered release retry = %v, %v", transitioned, err)
	}
	if _, status, err := s.Request(t.Context(), req.ID); err != nil || status != envelope.StatusDelivered {
		t.Fatalf("retry changed delivered state: %s, %v", status, err)
	}
	if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", owner, time.Minute); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("retired notify attempt = %v", err)
	}
	current, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node-b", "task-b", "attempt-2"), time.Minute)
	if err != nil || current.Ownership.LeaseGeneration != owner.LeaseGeneration+1 || !current.Ownership.LeaseUntil.IsZero() {
		t.Fatalf("replacement notify claim = %+v, %v", current, err)
	}
	assertOwnedMutationsConflict(t, s, req.ID, owner)
	events, err := s.AuditForTrace(t.Context(), req.TraceID)
	if err != nil {
		t.Fatal(err)
	}
	releases := 0
	for _, event := range events {
		if event.Event == "released" {
			releases++
			if event.RequestID != req.ID || event.TraceID != req.TraceID || event.Actor != owner.ActorID {
				t.Fatalf("release attribution = %+v", event)
			}
		}
	}
	if releases != 1 {
		t.Fatalf("trace contains %d releases, want exactly one", releases)
	}
}

func TestOwnedNotifyTTLAndZeroLeaseAreFenced(t *testing.T) {
	t.Run("notify TTL", func(t *testing.T) {
		s, c := open(t, ":memory:")
		req, owner := ownedNotify(t, s)
		c.advance(time.Hour)
		if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", owner, time.Minute); !errors.Is(err, ErrClaimConflict) {
			t.Fatalf("notify retry after TTL = %v", err)
		}
		assertOwnedMutationsConflict(t, s, req.ID, owner)
	})
	for _, kind := range []envelope.Kind{envelope.KindAsk, envelope.KindPing} {
		t.Run(string(kind), func(t *testing.T) {
			s, c := open(t, ":memory:")
			req, err := s.Enqueue(t.Context(), envelope.Request{From: "sender", To: "receiver", Kind: kind, Body: "work", Chain: []string{}}, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node-a", "task-a", "attempt-1"), time.Minute)
			if err != nil || !claimed.Ownership.LeaseUntil.Equal(c.t.Add(time.Minute)) {
				t.Fatalf("finite claim = %+v, %v", claimed, err)
			}
			if _, err := s.db.Exec(`UPDATE requests SET lease_until=0 WHERE id=?`, req.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", *claimed.Ownership, time.Minute); !errors.Is(err, ErrClaimConflict) {
				t.Fatalf("zero-lease finite retry = %v", err)
			}
			assertOwnedMutationsConflict(t, s, req.ID, *claimed.Ownership)
		})
	}
}

func TestOwnedNotifyRetryNormalizesExistingFiniteLease(t *testing.T) {
	s, c := open(t, ":memory:")
	req, owner := ownedNotify(t, s)
	if _, err := s.db.Exec(`UPDATE requests SET lease_until=? WHERE id=?`, c.t.Add(time.Minute).UnixMilli(), req.ID); err != nil {
		t.Fatal(err)
	}
	c.advance(2 * time.Minute)
	if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node-b", "task-b", "attempt-2"), time.Minute); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("old finite notify lease allowed takeover = %v", err)
	}
	if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", owner, time.Minute); err != nil {
		t.Fatal(err)
	}
	current, _, err := s.Request(t.Context(), req.ID)
	if err != nil || !current.Ownership.LeaseUntil.IsZero() || current.Ownership.LeaseGeneration != owner.LeaseGeneration {
		t.Fatalf("normalized notify = %+v, %v", current, err)
	}
}

func TestOwnedNotifyReopenNormalizesFiniteLeaseBeforeSweep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	s, c := open(t, path)
	notify, owner := ownedNotify(t, s)
	oldUntil := c.t.Add(time.Minute)
	if _, err := s.db.Exec(`UPDATE requests SET lease_until=? WHERE id=?`, oldUntil.UnixMilli(), notify.ID); err != nil {
		t.Fatal(err)
	}
	var finiteIDs []string
	for _, kind := range []envelope.Kind{envelope.KindAsk, envelope.KindPing} {
		req, err := s.Enqueue(t.Context(), envelope.Request{From: "sender", To: "receiver", Kind: kind, Body: "work", Chain: []string{}}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node-a", "task-a", string(kind)), time.Minute); err != nil {
			t.Fatal(err)
		}
		finiteIDs = append(finiteIDs, req.ID)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	c.advance(2 * time.Minute)
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetClock(c.now)
	current, status, err := reopened.Request(t.Context(), notify.ID)
	if err != nil || status != envelope.StatusClaimed || !current.Ownership.LeaseUntil.IsZero() || current.Ownership.ActorID != owner.ActorID || current.Ownership.TaskID != owner.TaskID || current.Ownership.AttemptID != owner.AttemptID || current.Ownership.LeaseGeneration != owner.LeaseGeneration {
		t.Fatalf("notify migration changed ownership: %+v, %s, %v", current, status, err)
	}
	for _, id := range finiteIDs {
		finite, _, err := reopened.Request(t.Context(), id)
		if err != nil || !finite.Ownership.LeaseUntil.Equal(oldUntil) {
			t.Fatalf("migration changed finite lease: %+v, %v", finite, err)
		}
	}
	transitions, err := reopened.Sweep(t.Context())
	if err != nil || len(transitions) != len(finiteIDs) {
		t.Fatalf("post-upgrade sweep = %+v, %v", transitions, err)
	}
	for _, transition := range transitions {
		if transition.ID == notify.ID {
			t.Fatal("upgrade redelivered consumed notify")
		}
	}
	if current, status, err := reopened.Request(t.Context(), notify.ID); err != nil || status != envelope.StatusClaimed || !current.Ownership.LeaseUntil.IsZero() {
		t.Fatalf("post-upgrade notify = %+v, %s, %v", current, status, err)
	}
}

func TestOwnedClarificationAuditPreservesBytesActorAndTrace(t *testing.T) {
	s, _ := open(t, ":memory:")
	req := ask(t, s, "sender", "receiver", "choose an item")
	claimed, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("actual-node", "task", "attempt"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	question := "Which café?"
	ctx := WithClaimOwner(t.Context(), *claimed.Ownership)
	for range 2 {
		if _, err := s.Reply(ctx, req.ID, "receiver", envelope.Reply{Status: envelope.StatusNeedsInput, Body: question}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.AuditForTrace(t.Context(), req.TraceID)
	if err != nil {
		t.Fatal(err)
	}
	questions := 0
	for _, event := range events {
		if event.Event == "replied" {
			t.Fatalf("clarification recorded as terminal reply: %+v", event)
		}
		if event.Event != "needs_input" {
			continue
		}
		questions++
		var detail map[string]any
		if err := json.Unmarshal([]byte(event.Detail), &detail); err != nil {
			t.Fatal(err)
		}
		if event.Actor != claimed.Ownership.ActorID || event.RequestID != req.ID || detail["agent"] != "receiver" || detail["question_bytes"] != float64(len(question)) || detail["lease_generation"] != float64(claimed.Ownership.LeaseGeneration) || strings.Contains(event.Detail, question) {
			t.Fatalf("clarification audit = %+v", event)
		}
	}
	if questions != 1 {
		t.Fatalf("clarification retry created %d audit entries", questions)
	}
	if _, err := s.VerifyAudit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedReleaseAndClarificationAuditFailureRollsBack(t *testing.T) {
	for _, event := range []string{"released", "needs_input"} {
		t.Run(event, func(t *testing.T) {
			s, _ := open(t, ":memory:")
			req := ask(t, s, "sender", "receiver", "work")
			claimed, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("actual-node", "task", "attempt"), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`CREATE TRIGGER reject_owned_audit BEFORE INSERT ON audit WHEN NEW.event='` + event + `' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`); err != nil {
				t.Fatal(err)
			}
			if event == "released" {
				if transitioned, err := s.ReleaseOwned(t.Context(), req.ID, "receiver", *claimed.Ownership); err == nil || transitioned {
					t.Fatalf("failed release reported transition: %v, %v", transitioned, err)
				}
			} else if _, err := s.Reply(WithClaimOwner(t.Context(), *claimed.Ownership), req.ID, "receiver", envelope.Reply{Status: envelope.StatusNeedsInput, Body: "which item?"}); err == nil {
				t.Fatal("clarification committed without audit")
			}
			current, status, err := s.Request(t.Context(), req.ID)
			if err != nil || status != envelope.StatusClaimed || len(current.Exchanges) != 0 || current.Ownership.LeaseGeneration != claimed.Ownership.LeaseGeneration {
				t.Fatalf("audit failure changed request: %+v, %s, %v", current, status, err)
			}
			if reply, err := s.replyFor(t.Context(), req.ID); err != nil || reply != nil {
				t.Fatalf("audit failure left reply: %+v, %v", reply, err)
			}
		})
	}
}
