package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func eventTestStore(t *testing.T, path string) (*Store, *clock) {
	t.Helper()
	s, c := open(t, path)
	if err := s.InitEvents(); err != nil {
		t.Fatal(err)
	}
	return s, c
}

func eventSub(t *testing.T, s *Store, id, principal, mailbox, name string) EventSubscription {
	t.Helper()
	sub, err := s.PutEventSubscription(context.Background(), EventSubscription{
		ID: id, Principal: principal, Mailbox: mailbox, Name: name,
		URL: "https://callback.example/" + id, Secret: "test-secret-" + id,
		ExpiresAt: s.now().Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

func eventCount(t *testing.T, s *Store, table string) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func eventLease(t *testing.T, s *Store, limit int) []EventDelivery {
	t.Helper()
	d, err := s.LeaseEventDeliveries(context.Background(), limit, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestEventJournalCommitsAndRollsBackWithMessages(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	ctx := context.Background()
	eventSub(t, s, "queue", "grant-target", "target", EventRequestQueued)
	eventSub(t, s, "reply", "grant-sender", "sender", EventReplyCreated)

	// Simulate a crash before a message transaction commits. Both the request
	// and the trigger-created outbox/delivery rows must roll back together.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO requests(id,from_agent,to_agent,trace_id,hop,chain,kind,body,status,created_at,updated_at,expires_at)
 VALUES ('rolled-back','sender','target','trace',1,'[]','ask','private body','queued',?,?,?)`, c.t.UnixMilli(), c.t.UnixMilli(), c.t.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM event_outbox`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("uncommitted event = %d, %v", n, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if eventCount(t, s, "event_outbox") != 0 || eventCount(t, s, "event_deliveries") != 0 {
		t.Fatal("message rollback left event or delivery behind")
	}

	req := ask(t, s, "sender", "target", "private committed body")
	queue := eventLease(t, s, 10)
	if len(queue) != 1 || queue[0].Event.RequestID != req.ID || queue[0].Event.Status != "queued" || queue[0].Event.Mailbox != "target" {
		t.Fatalf("queued event = %+v", queue)
	}
	// A reply transaction that fails after INSERT must not publish a phantom.
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE requests SET status='answered',reply_generation=1 WHERE id=?`, req.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO replies(request_id,from_agent,status,body,created_at) VALUES (?,'target','answered','private reply',?)`, req.ID, c.t.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if eventCount(t, s, "event_outbox") != 1 || len(eventLease(t, s, 10)) != 0 {
		t.Fatal("rolled back reply became deliverable")
	}
	// No body-bearing column is admitted to the event persistence schema.
	for _, table := range []string{"event_outbox", "event_deliveries"} {
		var leaked int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name IN ('body','question','answer')`, table).Scan(&leaked); err != nil || leaked != 0 {
			t.Fatalf("%s contains message columns: %d, %v", table, leaked, err)
		}
	}
}

func TestEventReconciliationNeverAcknowledgesAndDeduplicates(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	ctx := context.Background()
	req := ask(t, s, "sender", "target", "private")
	if _, err := s.db.Exec(`UPDATE requests SET status='answered',reply_generation=3 WHERE id=?`, req.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO replies(request_id,from_agent,status,body,created_at) VALUES (?,'target','answered','private',?)`, req.ID, c.t.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	eventSub(t, s, "reply", "grant", "sender", EventReplyCreated)
	for range 3 {
		if err := s.InitEvents(); err != nil {
			t.Fatal(err)
		}
		if err := s.ReconcileEvents(ctx); err != nil {
			t.Fatal(err)
		}
	}
	deliveries := eventLease(t, s, 10)
	if len(deliveries) != 1 || deliveries[0].Event.Generation != 3 || deliveries[0].Event.Mailbox != "sender" {
		t.Fatalf("current unseen reply = %+v", deliveries)
	}
	var seen, lease int64
	var status string
	if err := s.db.QueryRow(`SELECT reply_seen_at,lease_until,status FROM requests WHERE id=?`, req.ID).Scan(&seen, &lease, &status); err != nil {
		t.Fatal(err)
	}
	if seen != 0 || lease != 0 || status != "answered" {
		t.Fatalf("event read acknowledged request/reply: seen=%d lease=%d status=%s", seen, lease, status)
	}
	if eventCount(t, s, "event_outbox") != 2 || eventCount(t, s, "event_deliveries") != 1 {
		t.Fatal("startup replay duplicated an event or delivery")
	}
}

func TestEventQueueGenerationsIncludeClaimsAndClarificationReplies(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	eventSub(t, s, "queue", "grant", "target", EventRequestQueued)
	req := ask(t, s, "sender", "target", "private")
	if _, err := s.db.Exec(`UPDATE requests SET status='claimed',claim_generation=1,updated_at=? WHERE id=?`, c.t.UnixMilli(), req.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE requests SET status='queued',updated_at=? WHERE id=?`, c.t.UnixMilli(), req.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE requests SET status='needs_input',reply_generation=1 WHERE id=?`, req.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE requests SET status='queued',updated_at=? WHERE id=?`, c.t.UnixMilli(), req.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	d := eventLease(t, s, 10)
	if len(d) != 3 {
		t.Fatalf("queue generations = %+v", d)
	}
	ids := make(map[string]bool)
	gens := make(map[int64]bool)
	for _, delivery := range d {
		ids[delivery.Event.ID], gens[delivery.Event.Generation] = true, true
	}
	if len(ids) != 3 || !gens[0] || !gens[1] || !gens[2] {
		t.Fatalf("dedup discarded claim or clarification generation: %+v", d)
	}
}

func TestEventDeliveryRestartAndAmbiguousCallbackRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	s, c := eventTestStore(t, path)
	eventSub(t, s, "queue", "grant", "target", EventRequestQueued)
	req := ask(t, s, "sender", "target", "private")
	first := eventLease(t, s, 10)[0]
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Callback may have succeeded just before the relay crashed. The restarted
	// process must send the exact same event ID after the persisted lease expires.
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	reopened.SetClock(c.now)
	if err := reopened.InitEvents(); err != nil {
		t.Fatal(err)
	}
	if len(eventLease(t, reopened, 10)) != 0 {
		t.Fatal("restart stole unexpired delivery lease")
	}
	c.advance(time.Minute + time.Millisecond)
	second := eventLease(t, reopened, 10)
	if len(second) != 1 || second[0].Event.ID != first.Event.ID || second[0].Event.RequestID != req.ID || second[0].Attempts != 2 || second[0].LeaseToken == first.LeaseToken {
		t.Fatalf("restart receipt = %+v", second)
	}
	ctx := context.Background()
	if err := reopened.FinishEventDelivery(ctx, first.Subscription.ID, first.Event.ID, first.LeaseToken, true, 0); !errors.Is(err, ErrEventDeliveryLease) {
		t.Fatalf("old worker completion = %v", err)
	}
	d := second[0]
	for range 2 {
		if err := reopened.FinishEventDelivery(ctx, d.Subscription.ID, d.Event.ID, d.LeaseToken, true, 0); err != nil {
			t.Fatalf("idempotent success = %v", err)
		}
	}
	c.advance(time.Hour)
	if len(eventLease(t, reopened, 10)) != 0 {
		t.Fatal("acknowledged delivery retried")
	}
}

func TestEventConcurrentDeliveryLeaseAcrossStoreConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	s, c := eventTestStore(t, path)
	eventSub(t, s, "queue", "grant", "target", EventRequestQueued)
	ask(t, s, "sender", "target", "private")
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	other.SetClock(c.now)
	start := make(chan struct{})
	results := make(chan []EventDelivery, 2)
	errorsCh := make(chan error, 2)
	var wg sync.WaitGroup
	for _, st := range []*Store{s, other} {
		wg.Go(func() {
			<-start
			d, err := st.LeaseEventDeliveries(context.Background(), 1, time.Minute)
			results <- d
			errorsCh <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	var total int
	for d := range results {
		total += len(d)
	}
	if total != 1 {
		t.Fatalf("concurrent workers leased %d copies", total)
	}
}

func TestEventSubscriptionsOwnershipRotationAndIndependentRevocation(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	ctx := context.Background()
	a := eventSub(t, s, "a", "grant-a", "target", EventRequestQueued)
	eventSub(t, s, "b", "grant-b", "target", EventRequestQueued)
	eventSub(t, s, "c", "grant-c", "different", EventRequestQueued)
	for _, mutate := range []func(*EventSubscription){
		func(sub *EventSubscription) { sub.Principal = "attacker" },
		func(sub *EventSubscription) { sub.Mailbox = "different" },
		func(sub *EventSubscription) { sub.Name = EventReplyCreated },
		func(sub *EventSubscription) { sub.URL = "https://other.example/" },
	} {
		copy := a
		mutate(&copy)
		if _, err := s.PutEventSubscription(ctx, copy); !errors.Is(err, ErrEventSubscriptionConflict) {
			t.Fatalf("subscription binding overwrite = %v", err)
		}
	}
	if err := s.DeleteEventSubscription(ctx, "grant-b", "a"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-grant unsubscribe = %v", err)
	}
	a.Secret, a.ExpiresAt = "replacement-test-secret", c.t.Add(72*time.Hour)
	rotated, err := s.PutEventSubscription(ctx, a)
	if err != nil || rotated.PreviousSecret != "test-secret-a" || !rotated.PreviousUntil.Equal(c.t.Add(EventSecretOverlap)) || !rotated.ExpiresAt.Equal(a.ExpiresAt) {
		t.Fatalf("atomic rotation = %+v, %v", rotated, err)
	}
	c.advance(EventSecretOverlap + time.Millisecond)
	active, err := s.EventSubscriptions(ctx, "grant-a", "target")
	if err != nil || len(active) != 1 || active[0].PreviousSecret != "" || !active[0].PreviousUntil.IsZero() {
		t.Fatalf("expired signing overlap = %+v, %v", active, err)
	}
	if active, err := s.EventSubscriptions(ctx, "grant-a", "different"); err != nil || len(active) != 0 {
		t.Fatalf("mailbox filter = %+v, %v", active, err)
	}
	ask(t, s, "sender", "target", "private")
	d := eventLease(t, s, 10)
	if len(d) != 2 {
		t.Fatalf("isolated mailboxes = %+v", d)
	}
	if err := s.RevokeEventPrincipal(ctx, "grant-a"); err != nil {
		t.Fatal(err)
	}
	for _, delivery := range d {
		err := s.FinishEventDelivery(ctx, delivery.Subscription.ID, delivery.Event.ID, delivery.LeaseToken, true, 0)
		if delivery.Subscription.Principal == "grant-a" && !errors.Is(err, ErrEventDeliveryLease) {
			t.Fatalf("revoked in-flight completion = %v", err)
		}
		if delivery.Subscription.Principal == "grant-b" && err != nil {
			t.Fatalf("independent grant completion = %v", err)
		}
	}
	if _, err := s.PutEventSubscription(ctx, a); !errors.Is(err, ErrEventPrincipalRevoked) {
		t.Fatalf("revoked grant resurrected = %v", err)
	}
	// Revocation before the first subscription is also durable.
	if err := s.RevokeEventPrincipal(ctx, "never-subscribed"); err != nil {
		t.Fatal(err)
	}
	a.ID, a.Principal = "new", "never-subscribed"
	if _, err := s.PutEventSubscription(ctx, a); !errors.Is(err, ErrEventPrincipalRevoked) {
		t.Fatalf("preemptively revoked principal resurrected = %v", err)
	}
}

func TestEventUnsubscribeExpiryAndBoundedRetries(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	ctx := context.Background()
	eventSub(t, s, "queue", "grant", "target", EventRequestQueued)
	ask(t, s, "sender", "target", "private")
	for attempt := 1; attempt <= EventMaxAttempts; attempt++ {
		d := eventLease(t, s, 10)
		if len(d) != 1 || d[0].Attempts != attempt {
			t.Fatalf("attempt %d = %+v", attempt, d)
		}
		if err := s.FinishEventDelivery(ctx, d[0].Subscription.ID, d[0].Event.ID, d[0].LeaseToken, false, 0); err != nil {
			t.Fatal(err)
		}
		if len(eventLease(t, s, 10)) != 0 {
			t.Fatal("failed callback immediately retried without backoff")
		}
		c.advance(time.Hour)
	}
	if len(eventLease(t, s, 10)) != 0 {
		t.Fatal("retry bound exceeded")
	}

	eventSub(t, s, "unsubscribe", "grant-u", "target", EventRequestQueued)
	ask(t, s, "sender", "target", "private")
	u := eventLease(t, s, 10)
	if err := s.DeleteEventSubscription(ctx, "grant-u", "unsubscribe"); err != nil {
		t.Fatal(err)
	}
	for _, d := range u {
		if d.Subscription.ID == "unsubscribe" {
			if err := s.FinishEventDelivery(ctx, d.Subscription.ID, d.Event.ID, d.LeaseToken, true, 0); !errors.Is(err, ErrEventDeliveryLease) {
				t.Fatalf("unsubscribed completion = %v", err)
			}
		}
	}
	c.advance(EventRetention)
	if len(eventLease(t, s, 100)) != 0 {
		t.Fatal("expired events retried")
	}
	eventSub(t, s, "expires", "grant-e", "target", EventRequestQueued)
	ask(t, s, "sender", "target", "private")
	if _, err := s.db.Exec(`UPDATE event_subscriptions SET expires_at=? WHERE id='expires'`, c.t.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	for _, d := range eventLease(t, s, 100) {
		if d.Subscription.ID == "expires" {
			t.Fatal("expired subscription leased delivery")
		}
	}
}

func TestEventSubscribeDoesNotReplayAcknowledgedHistory(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	ctx := context.Background()
	old := ask(t, s, "sender", "target", "private")
	if _, err := s.db.Exec(`UPDATE requests SET status='answered',reply_generation=1,reply_seen_at=? WHERE id=?`, c.t.UnixMilli(), old.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO replies(request_id,from_agent,status,body,created_at) VALUES (?,'target','answered','private',?)`, old.ID, c.t.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	current := ask(t, s, "sender", "target", "private")
	eventSub(t, s, "q", "grant-q", "target", EventRequestQueued)
	eventSub(t, s, "r", "grant-r", "sender", EventReplyCreated)
	d := eventLease(t, s, 10)
	if len(d) != 1 || d[0].Event.RequestID != current.ID {
		t.Fatalf("subscription replayed history = %+v", d)
	}
	if err := s.DeleteEventSubscription(ctx, "grant-q", "q"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEventSubscription(ctx, "grant-q", "q"); err != nil {
		t.Fatalf("idempotent unsubscribe = %v", err)
	}
	if err := s.DeleteEventSubscription(ctx, "grant-q", "missing"); err != nil {
		t.Fatalf("unknown subscription = %v", err)
	}
}

func TestEventExpiryAndRevocationBetweenLeaseAndCompletion(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	ctx := context.Background()
	eventSub(t, s, "a", "grant-a", "target", EventRequestQueued)
	eventSub(t, s, "b", "grant-b", "target", EventRequestQueued)
	eventSub(t, s, "c", "grant-c", "target", EventRequestQueued)
	ask(t, s, "sender", "target", "private")
	deliveries := eventLease(t, s, 10)
	if len(deliveries) != 3 {
		t.Fatalf("initial deliveries = %+v", deliveries)
	}
	if _, err := s.db.Exec(`UPDATE event_subscriptions SET expires_at=? WHERE id='a'`, c.t.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeEventPrincipal(ctx, "grant-b"); err != nil {
		t.Fatal(err)
	}
	for _, d := range deliveries {
		if d.Subscription.ID != "c" {
			if err := s.FinishEventDelivery(ctx, d.Subscription.ID, d.Event.ID, d.LeaseToken, true, 0); !errors.Is(err, ErrEventDeliveryLease) {
				t.Fatalf("inactive in-flight completion %s = %v", d.Subscription.ID, err)
			}
		} else {
			for range 2 {
				if err := s.FailEventDelivery(ctx, d.Subscription.ID, d.Event.ID, d.LeaseToken); err != nil {
					t.Fatalf("terminal callback failure = %v", err)
				}
			}
		}
	}
	c.advance(time.Minute)
	if len(eventLease(t, s, 10)) != 0 {
		t.Fatal("expired, revoked or terminal callback failure retried")
	}
	var cancelled int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM event_deliveries WHERE state='cancelled'`).Scan(&cancelled); err != nil || cancelled != 2 {
		t.Fatalf("expiry/revocation cancellation = %d, %v", cancelled, err)
	}
}

func TestEventExpiredSubscriptionRenewalDoesNotRevivePending(t *testing.T) {
	s, c := eventTestStore(t, ":memory:")
	ctx := context.Background()
	sub := eventSub(t, s, "queue", "grant", "target", EventRequestQueued)
	ask(t, s, "sender", "target", "private")
	if _, err := s.db.Exec(`UPDATE event_subscriptions SET expires_at=? WHERE id=?`, c.t.UnixMilli(), sub.ID); err != nil {
		t.Fatal(err)
	}
	sub.ExpiresAt = c.t.Add(time.Hour)
	if _, err := s.PutEventSubscription(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if len(eventLease(t, s, 10)) != 0 {
		t.Fatal("renewal revived delivery from expired subscription")
	}
	ask(t, s, "sender", "target", "new private request")
	if len(eventLease(t, s, 10)) != 1 {
		t.Fatal("renewed subscription failed to receive a new event")
	}
}

func TestEventOptInAndInvalidOperations(t *testing.T) {
	s, _ := open(t, ":memory:")
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='event_outbox')`).Scan(&exists); err != nil || exists {
		t.Fatalf("events implicitly enabled = %t, %v", exists, err)
	}
	s, _ = eventTestStore(t, ":memory:")
	ctx := context.Background()
	if _, err := s.PutEventSubscription(ctx, EventSubscription{}); !errors.Is(err, ErrEventInvalid) {
		t.Fatalf("empty subscription = %v", err)
	}
	if _, err := s.LeaseEventDeliveries(ctx, 101, time.Minute); !errors.Is(err, ErrEventInvalid) {
		t.Fatalf("unbounded delivery batch = %v", err)
	}
	if _, err := s.LeaseEventDeliveries(ctx, 1, 6*time.Minute); !errors.Is(err, ErrEventInvalid) {
		t.Fatalf("unbounded lease = %v", err)
	}
	if err := s.FinishEventDelivery(ctx, "sub", "event", "token", true, 0); !errors.Is(err, ErrEventDeliveryLease) {
		t.Fatalf("fabricated receipt = %v", err)
	}
}
