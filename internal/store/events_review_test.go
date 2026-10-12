package store

import (
	"github.com/mvanhorn/agent-tincan/internal/envelope"
	"testing"
	"time"
)

func TestEventDeliveryCrashBeforeClaimProducesNewQueueNotification(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	eventSub(t, s, "queue", "grant", "receiver", EventRequestQueued)
	req := ask(t, s, "sender", "receiver", "private")
	first := eventLease(t, s, 10)
	if len(first) != 1 {
		t.Fatal(first)
	}
	if err := s.FinishEventDelivery(t.Context(), first[0].Subscription.ID, first[0].Event.ID, first[0].LeaseToken, true, 0); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Deliver(t.Context(), "receiver", 10, time.Minute); err != nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	c.advance(2 * time.Minute)
	if _, err := s.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	second := eventLease(t, s, 10)
	if len(second) != 1 || second[0].Event.ID == first[0].Event.ID || second[0].Event.Generation != 1 {
		t.Fatal(second)
	}
	if err := s.ReconcileEvents(t.Context()); err != nil {
		t.Fatal(err)
	}
	if eventCount(t, s, "event_outbox") != 2 {
		t.Fatal("duplicate on reconciliation")
	}
	r, st, err := s.Request(t.Context(), req.ID)
	if err != nil || st != envelope.StatusQueued || r.Ownership != nil {
		t.Fatal(r, st, err)
	}
}

func TestClaimReleaseRetryAfterTakingPollBeforeNewGeneration(t *testing.T) {
	s, _ := open(t, ":memory:")
	req := ask(t, s, "sender", "receiver", "private")
	r, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node", "task", "attempt-1"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ReleaseOwned(t.Context(), req.ID, "receiver", *r.Ownership); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Deliver(t.Context(), "receiver", 10, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err = s.ReleaseOwned(t.Context(), req.ID, "receiver", *r.Ownership); err != nil {
		t.Fatal(err)
	}
	_, st, err := s.Request(t.Context(), req.ID)
	if err != nil || st != envelope.StatusDelivered {
		t.Fatal(st, err)
	}
}
