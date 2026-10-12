package store

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/envelope"
)

func assertNotifyLifecycleCounts(t *testing.T, s *Store, claimed int) {
	t.Helper()
	stats, err := s.QueueStats(t.Context())
	if err != nil || stats["receiver"].Claimed != claimed || stats["receiver"].Queued != 0 {
		t.Fatalf("notify backlog = %+v, %v; want %d claimed", stats, err, claimed)
	}
	if count, err := s.CountQueued(t.Context(), "receiver"); err != nil || count != 0 {
		t.Fatalf("queued = %d, %v", count, err)
	}
	if count, err := s.CountUrgentQueued(t.Context(), "receiver"); err != nil || count != 0 {
		t.Fatalf("urgent queued = %d, %v", count, err)
	}
	if count, pings, err := s.CountQueuedWithPings(t.Context(), "receiver"); err != nil || count != 0 || pings != 0 {
		t.Fatalf("queued with pings = %d, %d, %v", count, pings, err)
	}
	if agents, err := s.AgentsWithQueuedRequests(t.Context()); err != nil || len(agents) != 0 {
		t.Fatalf("queued agents = %v, %v", agents, err)
	}
	if pending, err := s.PendingRequests(t.Context(), "receiver", 10); err != nil || len(pending) != 0 {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
	if req, exists, err := s.OpenClaim(t.Context(), "receiver"); err != nil || exists {
		t.Fatalf("notify became implicit ask parent: %+v, %v, %v", req, exists, err)
	}
	if count, err := s.CountUnseenReplies(t.Context(), "sender"); err != nil || count != 0 {
		t.Fatalf("notify created unseen reply: %d, %v", count, err)
	}
	if agents, err := s.AgentsWithUnseenReplies(t.Context()); err != nil || len(agents) != 0 {
		t.Fatalf("notify created reply wake: %v, %v", agents, err)
	}
	if delivered, err := s.Deliver(t.Context(), "receiver", 10, time.Minute); err != nil || len(delivered) != 0 {
		t.Fatalf("notify redelivered = %+v, %v", delivered, err)
	}
}

func assertNotifyLifecycleExpired(t *testing.T, s *Store, req envelope.Request, owner envelope.ClaimOwnership) {
	t.Helper()
	assertNotifyLifecycleCounts(t, s, 0)
	for _, attempted := range []envelope.ClaimOwnership{owner, claimTuple("node-b", "fresh-task", "fresh-attempt")} {
		if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", attempted, time.Minute); !errors.Is(err, ErrClaimConflict) {
			t.Fatalf("claim at TTL = %v", err)
		}
	}
	assertOwnedMutationsConflict(t, s, req.ID, owner)
	transitions, err := s.Sweep(t.Context())
	if err != nil || len(transitions) != 1 {
		t.Fatalf("exact-TTL sweep = %+v, %v", transitions, err)
	}
	transition := transitions[0]
	if transition.ID != req.ID || transition.TraceID != req.TraceID || transition.From != req.From || transition.To != req.To || transition.Status != envelope.StatusExpired || transition.Held {
		t.Fatalf("notify expiry attribution = %+v", transition)
	}
	current, status, err := s.Request(t.Context(), req.ID)
	if err != nil || status != envelope.StatusExpired || current.Ownership == nil || current.Ownership.ActorID != owner.ActorID || current.Ownership.TaskID != owner.TaskID || current.Ownership.AttemptID != owner.AttemptID || current.Ownership.LeaseGeneration != owner.LeaseGeneration || !current.Ownership.LeaseUntil.IsZero() {
		t.Fatalf("expired notify = %+v, %s, %v", current, status, err)
	}
	for _, read := range []func() (envelope.Result, error){
		func() (envelope.Result, error) { return s.Inspect(t.Context(), req.ID, req.From) },
		func() (envelope.Result, error) { return s.Get(t.Context(), req.ID, req.From) },
	} {
		if result, err := read(); err != nil || result.Status != envelope.StatusExpired || result.Reply != nil || result.Request.ID != req.ID {
			t.Fatalf("sender expiry view = %+v, %v", result, err)
		}
	}
	assertOwnedMutationsConflict(t, s, req.ID, owner)
	if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node-b", "fresh-task", "fresh-attempt"), time.Minute); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("reclaim after TTL sweep = %v", err)
	}
	assertNotifyLifecycleCounts(t, s, 0)
	if repeated, err := s.Sweep(t.Context()); err != nil || len(repeated) != 0 {
		t.Fatalf("notify expired twice: %+v, %v", repeated, err)
	}
}

func TestOwnedNotifyLifecycleCountsUntilTTLWithoutRedelivery(t *testing.T) {
	s, c := open(t, ":memory:")
	req, owner := ownedNotify(t, s)
	assertNotifyLifecycleCounts(t, s, 1)
	c.advance(2 * time.Minute)
	if transitions, err := s.Sweep(t.Context()); err != nil || len(transitions) != 0 {
		t.Fatalf("claim-time sweep redelivered notify: %+v, %v", transitions, err)
	}
	assertNotifyLifecycleCounts(t, s, 1)
	if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node-b", "other-task", "other-attempt"), time.Minute); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("time allowed notify takeover = %v", err)
	}
	c.advance(time.Hour - 2*time.Minute - time.Millisecond)
	assertNotifyLifecycleCounts(t, s, 1)
	if transitions, err := s.Sweep(t.Context()); err != nil || len(transitions) != 0 {
		t.Fatalf("notify expired before TTL: %+v, %v", transitions, err)
	}
	c.advance(time.Millisecond)
	assertNotifyLifecycleExpired(t, s, req, owner)
}

func TestOwnedNotifyLifecycleExpiresExactlyAtTTL(t *testing.T) {
	s, c := open(t, ":memory:")
	if err := s.InitEvents(); err != nil {
		t.Fatal(err)
	}
	req, owner := ownedNotify(t, s)
	journal := func() (int64, string) {
		t.Helper()
		var generation int64
		var eventIDs string
		if err := s.db.QueryRow(`SELECT queue_generation,(SELECT group_concat(id,',') FROM event_outbox WHERE request_id=? AND name=?) FROM requests WHERE id=?`, req.ID, EventRequestQueued, req.ID).Scan(&generation, &eventIDs); err != nil {
			t.Fatal(err)
		}
		return generation, eventIDs
	}
	beforeGeneration, beforeEvents := journal()
	if beforeEvents == "" {
		t.Fatal("initial queued event missing")
	}
	c.advance(time.Hour)
	assertNotifyLifecycleExpired(t, s, req, owner)
	if generation, eventIDs := journal(); generation != beforeGeneration || eventIDs != beforeEvents {
		t.Fatalf("expiry requeued notify in event journal: generation %d->%d, events %q->%q", beforeGeneration, generation, beforeEvents, eventIDs)
	}
}

func TestOwnedNotifyLifecyclePersistedFiniteClaimReachesTTL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	s, c := open(t, path)
	req, owner := ownedNotify(t, s)
	if _, err := s.db.Exec(`UPDATE requests SET lease_until=? WHERE id=?`, c.t.Add(time.Minute).UnixMilli(), req.ID); err != nil {
		t.Fatal(err)
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
	current, status, err := reopened.Request(t.Context(), req.ID)
	if err != nil || status != envelope.StatusClaimed || !reflect.DeepEqual(current.Ownership, &owner) {
		t.Fatalf("migration changed notify ownership: %+v, %s, %v", current, status, err)
	}
	if transitions, err := reopened.Sweep(t.Context()); err != nil || len(transitions) != 0 {
		t.Fatalf("upgrade redelivered old notify: %+v, %v", transitions, err)
	}
	assertNotifyLifecycleCounts(t, reopened, 1)
	c.advance(time.Hour - 2*time.Minute)
	assertNotifyLifecycleExpired(t, reopened, req, owner)
}

func TestOwnedNotifyLifecyclePreservesFiniteAndLegacyDefaults(t *testing.T) {
	for _, kind := range []envelope.Kind{envelope.KindAsk, envelope.KindPing} {
		t.Run(string(kind), func(t *testing.T) {
			s, c := open(t, ":memory:")
			req, err := s.Enqueue(t.Context(), envelope.Request{From: "sender", To: "receiver", Kind: kind, Body: "work", Chain: []string{}}, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node", "task", "attempt"), 2*time.Hour)
			if err != nil || !claimed.Ownership.LeaseUntil.Equal(c.t.Add(2*time.Hour)) {
				t.Fatalf("finite lease changed: %+v, %v", claimed, err)
			}
			c.advance(time.Hour)
			if transitions, err := s.Sweep(t.Context()); err != nil || len(transitions) != 0 {
				t.Fatalf("TTL shortened finite claim lease: %+v, %v", transitions, err)
			}
			assertOwnedMutationsConflict(t, s, req.ID, *claimed.Ownership)
			c.advance(time.Hour)
			if transitions, err := s.Sweep(t.Context()); err != nil || len(transitions) != 1 || transitions[0].Status != envelope.StatusExpired {
				t.Fatalf("finite lease expiry = %+v, %v", transitions, err)
			}
		})
	}
	t.Run("legacy notify", func(t *testing.T) {
		s, c := open(t, ":memory:")
		req, err := s.Enqueue(t.Context(), envelope.Request{From: "sender", To: "receiver", Kind: envelope.KindNotify, Body: "notice", Chain: []string{}}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Claim(t.Context(), req.ID, "receiver", time.Minute); err != nil {
			t.Fatal(err)
		}
		assertNotifyLifecycleCounts(t, s, 0)
		c.advance(time.Hour)
		if transitions, err := s.Sweep(t.Context()); err != nil || len(transitions) != 0 {
			t.Fatalf("legacy notify behavior changed: %+v, %v", transitions, err)
		}
		if current, status, err := s.Request(t.Context(), req.ID); err != nil || status != envelope.StatusClaimed || current.Ownership != nil {
			t.Fatalf("legacy notify = %+v, %s, %v", current, status, err)
		}
		if err := s.SetProgress(t.Context(), req.ID, "receiver", "legacy progress", time.Minute); err != nil {
			t.Fatalf("legacy progress behavior changed: %v", err)
		}
		assertNotifyLifecycleCounts(t, s, 0)
	})
}

func TestOwnedNotifyLifecycleCommittedReplyRetryAfterTTLDoesNotMutate(t *testing.T) {
	for _, kind := range []envelope.Kind{envelope.KindAsk, envelope.KindPing, envelope.KindNotify} {
		t.Run(string(kind), func(t *testing.T) {
			s, c := open(t, ":memory:")
			req, err := s.Enqueue(t.Context(), envelope.Request{From: "sender", To: "receiver", Kind: kind, Body: "work", Chain: []string{}}, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node", "task", "attempt"), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithClaimOwner(t.Context(), *claimed.Ownership)
			reply := envelope.Reply{Status: envelope.StatusAnswered, Body: "done"}
			first, err := s.Reply(ctx, req.ID, "receiver", reply)
			if err != nil {
				t.Fatal(err)
			}
			before, err := s.AuditEvents(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			c.advance(time.Hour)
			if transitions, err := s.Sweep(t.Context()); err != nil || len(transitions) != 0 {
				t.Fatalf("finished request expired: %+v, %v", transitions, err)
			}
			retry, err := s.Reply(ctx, req.ID, "receiver", reply)
			if err != nil || !reflect.DeepEqual(retry, first) {
				t.Fatalf("committed reply retry = %+v, %v", retry, err)
			}
			assertOwnedMutationsConflict(t, s, req.ID, *claimed.Ownership)
			after, err := s.AuditEvents(t.Context())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("reply retry changed audit: %+v, %v", after, err)
			}
			var rows int
			var generation int64
			if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM replies WHERE request_id=?), reply_generation FROM requests WHERE id=?`, req.ID, req.ID).Scan(&rows, &generation); err != nil || rows != 1 || generation != first.Generation {
				t.Fatalf("reply retry mutated storage: %d, %d, %v", rows, generation, err)
			}
		})
	}
}

func TestOwnedNotifyLifecycleRetainsAttachmentsUntilExpiryAndRetention(t *testing.T) {
	s, c := open(t, ":memory:")
	start := c.t
	attachment := upload(t, s, "sender", "notice.png", 1)
	req, err := s.Enqueue(t.Context(), envelope.Request{From: "sender", To: "receiver", Kind: envelope.KindNotify, Body: "notice", Chain: []string{}, Attachments: []envelope.Attachment{{ID: attachment}}}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimOwned(t.Context(), req.ID, "receiver", claimTuple("node", "task", "attempt"), time.Minute); err != nil {
		t.Fatal(err)
	}
	c.advance(7 * 24 * time.Hour)
	if deleted, err := s.SweepAttachments(t.Context(), 24*time.Hour, 7*24*time.Hour); err != nil || len(deleted) != 0 {
		t.Fatalf("active notify lost attachments: %v, %v", deleted, err)
	}
	if transitions, err := s.Sweep(t.Context()); err != nil || len(transitions) != 0 {
		t.Fatalf("long-TTL notify sweep = %+v, %v", transitions, err)
	}
	c.t = start.Add(30 * 24 * time.Hour)
	if transitions, err := s.Sweep(t.Context()); err != nil || len(transitions) != 1 || transitions[0].Status != envelope.StatusExpired {
		t.Fatalf("long-TTL notify expiry = %+v, %v", transitions, err)
	}
	c.advance(7*24*time.Hour - time.Millisecond)
	if deleted, err := s.SweepAttachments(t.Context(), 24*time.Hour, 7*24*time.Hour); err != nil || len(deleted) != 0 {
		t.Fatalf("expired notify lost attachments before retention: %v, %v", deleted, err)
	}
	c.advance(time.Millisecond)
	if deleted, err := s.SweepAttachments(t.Context(), 24*time.Hour, 7*24*time.Hour); err != nil || !slices.Equal(deleted, []string{attachment}) {
		t.Fatalf("expired notify retention = %v, %v", deleted, err)
	}
	if record, err := s.Attachment(t.Context(), attachment); err != nil || record.DeletedAt.IsZero() {
		t.Fatalf("retained attachment metadata = %+v, %v", record, err)
	}
	if deleted, err := s.SweepAttachments(t.Context(), 24*time.Hour, 7*24*time.Hour); err != nil || len(deleted) != 0 {
		t.Fatalf("attachment expired twice: %v, %v", deleted, err)
	}
}
