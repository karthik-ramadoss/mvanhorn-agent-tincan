package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// Each state has its own mailbox/subscription so unsubscribe can exercise a
// cancelled delivery without also cancelling the other fixtures.
func retentionDeliveries(t *testing.T, s *Store, prefix string) map[string]EventDelivery {
	t.Helper()
	ctx := context.Background()
	for _, state := range []string{"delivered", "failed", "cancelled", "pending", "leased"} {
		mailbox := prefix + state
		eventSub(t, s, mailbox, "grant-"+mailbox, mailbox, EventRequestQueued)
		ask(t, s, "sender", mailbox, "private test body")
	}
	ask(t, s, "sender", prefix+"no-subscriber", "private test body")
	deliveries, err := s.LeaseEventDeliveries(ctx, 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]EventDelivery)
	for _, d := range deliveries {
		switch d.Event.Mailbox {
		case prefix + "delivered":
			err = s.FinishEventDelivery(ctx, d.Subscription.ID, d.Event.ID, d.LeaseToken, true, 0)
			out["delivered"] = d
		case prefix + "failed":
			err = s.FailEventDelivery(ctx, d.Subscription.ID, d.Event.ID, d.LeaseToken)
			out["failed"] = d
		case prefix + "cancelled":
			err = s.DeleteEventSubscription(ctx, d.Subscription.Principal, d.Subscription.ID)
			out["cancelled"] = d
		case prefix + "pending":
			err = s.FinishEventDelivery(ctx, d.Subscription.ID, d.Event.ID, d.LeaseToken, false, 0)
			out["pending"] = d
		case prefix + "leased":
			out["leased"] = d
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) != 5 {
		t.Fatalf("delivery state fixtures = %+v", out)
	}
	return out
}

func TestEventRetentionPrunesExpiredStatesAndUnsubscribedEvents(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	ctx := context.Background()
	deliveries := retentionDeliveries(t, s, "expired-")
	if eventCount(t, s, "event_deliveries") != 5 || eventCount(t, s, "event_outbox") != 6 {
		t.Fatal("incomplete retention fixtures")
	}

	// Immediately before the horizon, preserve both terminal receipts and the
	// pending/leased event IDs. Cleanup must not shorten idempotency retention.
	c.advance(EventRetention - time.Millisecond)
	if retried := eventLease(t, s, 100); len(retried) != 2 {
		t.Fatalf("live pending/leased retry = %+v", retried)
	}
	if eventCount(t, s, "event_deliveries") != 5 || eventCount(t, s, "event_outbox") != 6 {
		t.Fatal("maintenance removed events before their horizon")
	}
	d := deliveries["delivered"]
	if err := s.FinishEventDelivery(ctx, d.Subscription.ID, d.Event.ID, d.LeaseToken, true, 0); err != nil {
		t.Fatalf("completion receipt lost before horizon: %v", err)
	}

	// Expiry is inclusive. Even a lease extending beyond the event horizon
	// has already lost its right to complete, so no expired receipt is retained.
	c.advance(time.Millisecond)
	if got := eventLease(t, s, 100); len(got) != 0 {
		t.Fatalf("expired work leased = %+v", got)
	}
	if n := eventCount(t, s, "event_deliveries"); n != 0 {
		t.Fatalf("expired delivery rows retained = %d", n)
	}
	if n := eventCount(t, s, "event_outbox"); n != 0 {
		t.Fatalf("expired outbox rows retained, including zero subscribers = %d", n)
	}
	if err := s.FinishEventDelivery(ctx, d.Subscription.ID, d.Event.ID, d.LeaseToken, true, 0); !errors.Is(err, ErrEventDeliveryLease) {
		t.Fatalf("late completion after cleanup = %v", err)
	}
	if eventCount(t, s, "event_outbox") != 0 || eventCount(t, s, "event_deliveries") != 0 {
		t.Fatal("late completion resurrected expired state")
	}
}

func TestEventRetentionPreservesLiveStatesAndLeaseFencing(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	ctx := context.Background()
	ask(t, s, "sender", "old-no-subscriber", "private test body")
	c.advance(EventRetention - time.Minute)
	live := retentionDeliveries(t, s, "live-")
	c.advance(time.Minute)
	current := eventLease(t, s, 100)
	if len(current) != 1 || current[0].Event.ID != live["pending"].Event.ID {
		t.Fatalf("maintenance changed live lease eligibility = %+v", current)
	}
	if eventCount(t, s, "event_deliveries") != 5 || eventCount(t, s, "event_outbox") != 6 {
		t.Fatal("cleanup did not isolate old outbox from live terminal/pending/leased rows")
	}
	leased := live["leased"]
	for range 2 {
		if err := s.FinishEventDelivery(ctx, leased.Subscription.ID, leased.Event.ID, leased.LeaseToken, true, 0); err != nil {
			t.Fatalf("live in-flight/idempotent completion = %v", err)
		}
	}
	completed := live["delivered"]
	if err := s.FinishEventDelivery(ctx, completed.Subscription.ID, completed.Event.ID, completed.LeaseToken, true, 0); err != nil {
		t.Fatalf("live completed receipt = %v", err)
	}
	pending := live["pending"]
	if err := s.FinishEventDelivery(ctx, pending.Subscription.ID, pending.Event.ID, pending.LeaseToken, true, 0); !errors.Is(err, ErrEventDeliveryLease) {
		t.Fatalf("maintenance bypassed current lease fence = %v", err)
	}
	if err := s.FinishEventDelivery(ctx, current[0].Subscription.ID, current[0].Event.ID, current[0].LeaseToken, true, 0); err != nil {
		t.Fatalf("current pending retry receipt = %v", err)
	}
}

func TestEventRetentionReconciliationCannotRecreateExpiredOutstanding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retention.db")
	s, c := eventTestStore(t, path)
	ctx := context.Background()
	queue := ask(t, s, "sender", "target", "private test body")
	// The request can outlive its event horizon; cleanup must not interpret
	// continued queue membership as a newly occurring event.
	if _, err := s.db.Exec(`UPDATE requests SET expires_at=? WHERE id=?`, c.t.Add(72*time.Hour).UnixMilli(), queue.ID); err != nil {
		t.Fatal(err)
	}
	reply := ask(t, s, "sender", "worker", "private test body")
	if _, err := s.db.Exec(`UPDATE requests SET status='answered',reply_generation=1 WHERE id=?`, reply.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO replies(request_id,from_agent,status,body,created_at) VALUES (?,'worker','answered','private test reply',?)`, reply.ID, c.t.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	eventSub(t, s, "queue", "queue-grant", "target", EventRequestQueued)
	eventSub(t, s, "reply", "reply-grant", "sender", EventReplyCreated)
	c.advance(EventRetention)
	eventLease(t, s, 100)
	for range 2 {
		if err := s.InitEvents(); err != nil {
			t.Fatal(err)
		}
		if err := s.ReconcileEvents(ctx); err != nil {
			t.Fatal(err)
		}
	}
	eventSub(t, s, "late-queue", "late-queue-grant", "target", EventRequestQueued)
	eventSub(t, s, "late-reply", "late-reply-grant", "sender", EventReplyCreated)
	if eventCount(t, s, "event_outbox") != 0 || eventCount(t, s, "event_deliveries") != 0 {
		t.Fatal("startup, reconciliation or new subscribe recreated expired events")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	reopened.SetClock(c.now)
	if err := reopened.InitEvents(); err != nil {
		t.Fatal(err)
	}
	if got := eventLease(t, reopened, 100); len(got) != 0 {
		t.Fatalf("restart made old work deliverable = %+v", got)
	}
	if eventCount(t, reopened, "event_outbox") != 0 || eventCount(t, reopened, "event_deliveries") != 0 {
		t.Fatal("restart recreated expired events")
	}
	var status string
	var seen int64
	if err := reopened.db.QueryRow(`SELECT status FROM requests WHERE id=?`, queue.ID).Scan(&status); err != nil || status != "queued" {
		t.Fatalf("retention acknowledged queue: %s, %v", status, err)
	}
	if err := reopened.db.QueryRow(`SELECT reply_seen_at FROM requests WHERE id=?`, reply.ID).Scan(&seen); err != nil || seen != 0 {
		t.Fatalf("retention acknowledged reply: %d, %v", seen, err)
	}
	// A real new queue transition of the old request still creates a fresh
	// generation, using its actual transition time rather than creation time.
	if _, err := reopened.db.Exec(`UPDATE requests SET status='delivered' WHERE id=?`, queue.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.db.Exec(`UPDATE requests SET status='queued',updated_at=? WHERE id=?`, c.t.UnixMilli(), queue.ID); err != nil {
		t.Fatal(err)
	}
	if got := eventLease(t, reopened, 100); len(got) != 2 || got[0].Event.RequestID != queue.ID || got[0].Event.Generation != 1 {
		t.Fatalf("fresh queue generation after expired history = %+v", got)
	}
}

func TestEventRetentionMaintenanceIsTransactional(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	eventSub(t, s, "queue", "grant", "target", EventRequestQueued)
	ask(t, s, "sender", "target", "private test body")
	c.advance(EventRetention)
	// Fail after delivery deletion, before outbox deletion. SQLite must roll
	// back the whole maintenance batch rather than losing only the child rows.
	if _, err := s.db.Exec(`CREATE TRIGGER retention_test_abort BEFORE DELETE ON event_outbox BEGIN SELECT RAISE(ABORT,'retention-test'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LeaseEventDeliveries(context.Background(), 100, time.Minute); err == nil {
		t.Fatal("expected retention failure was not surfaced")
	}
	if eventCount(t, s, "event_deliveries") != 1 || eventCount(t, s, "event_outbox") != 1 {
		t.Fatal("cleanup failure did not roll back both tables")
	}
	if _, err := s.db.Exec(`DROP TRIGGER retention_test_abort`); err != nil {
		t.Fatal(err)
	}
	if got := eventLease(t, s, 100); len(got) != 0 {
		t.Fatalf("expired rollback fixture leased = %+v", got)
	}
	if eventCount(t, s, "event_deliveries") != 0 || eventCount(t, s, "event_outbox") != 0 {
		t.Fatal("successful maintenance failed to reclaim both tables")
	}
}
