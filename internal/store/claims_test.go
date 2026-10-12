package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/envelope"
)

func claimTuple(actor, task, attempt string) envelope.ClaimOwnership {
	return envelope.ClaimOwnership{ActorID: actor, TaskID: task, AttemptID: attempt}
}

func TestOwnedClaimConcurrentTasksAndNodes(t *testing.T) {
	for _, actors := range [][2]string{{"node-a", "node-a"}, {"node-a", "node-b"}} {
		t.Run(actors[0]+"-"+actors[1], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "relay.db")
			a, _ := open(t, path)
			b, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			req := ask(t, a, "sender", "receiver", "work")
			ctx := context.Background()
			owners := []envelope.ClaimOwnership{claimTuple(actors[0], "task-a", "attempt-1"), claimTuple(actors[1], "task-b", "attempt-1")}
			var wg sync.WaitGroup
			wins := make(chan int, 2)
			errs := make(chan error, 2)
			for i, s := range []*Store{a, b} {
				wg.Add(1)
				go func(i int, s *Store) {
					defer wg.Done()
					_, err := s.ClaimOwned(ctx, req.ID, "receiver", owners[i], time.Minute)
					if err == nil {
						wins <- i
					} else {
						errs <- err
					}
				}(i, s)
			}
			wg.Wait()
			close(wins)
			close(errs)
			if len(wins) != 1 {
				t.Fatalf("wins=%d", len(wins))
			}
			for err := range errs {
				if !errors.Is(err, ErrClaimConflict) {
					t.Fatal(err)
				}
			}
			winner := <-wins
			claimed, err := a.ClaimOwned(ctx, req.ID, "receiver", owners[winner], time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if claimed.Ownership.LeaseGeneration != 1 {
				t.Fatalf("generation=%d", claimed.Ownership.LeaseGeneration)
			}
			if _, err = a.Claim(ctx, req.ID, "receiver", time.Minute); !errors.Is(err, ErrWrongState) {
				t.Fatalf("legacy bypass=%v", err)
			}
		})
	}
}

func TestOwnedClaimExpiryFencesAllMutations(t *testing.T) {
	s, c := open(t, ":memory:")
	ctx := context.Background()
	req := ask(t, s, "sender", "receiver", "work")
	o := claimTuple("node-a", "task-a", "attempt-1")
	r, err := s.ClaimOwned(ctx, req.ID, "receiver", o, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	o = *r.Ownership
	c.advance(2 * time.Minute)
	if _, err = s.ClaimOwned(ctx, req.ID, "receiver", o, time.Minute); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("expired retry=%v", err)
	}
	stale := WithClaimOwner(ctx, o)
	if err = s.SetProgress(stale, req.ID, "receiver", "stale", time.Minute); !errors.Is(err, ErrClaimConflict) {
		t.Fatal(err)
	}
	if _, err = s.Reply(stale, req.ID, "receiver", envelope.Reply{Status: envelope.StatusNeedsInput, Body: "question"}); !errors.Is(err, ErrClaimConflict) {
		t.Fatal(err)
	}
	if _, err = s.Reply(stale, req.ID, "receiver", envelope.Reply{Status: envelope.StatusAnswered, Body: "old"}); !errors.Is(err, ErrClaimConflict) {
		t.Fatal(err)
	}
	if err = s.ReleaseOwned(ctx, req.ID, "receiver", o); !errors.Is(err, ErrClaimConflict) {
		t.Fatal(err)
	}
	newOwner := claimTuple("node-b", "task-a", "attempt-2")
	r, err = s.ClaimOwned(ctx, req.ID, "receiver", newOwner, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r.Ownership.LeaseGeneration != 2 {
		t.Fatal(r.Ownership)
	}
	if _, err = s.Reply(stale, req.ID, "receiver", envelope.Reply{Status: envelope.StatusAnswered, Body: "old"}); !errors.Is(err, ErrClaimConflict) {
		t.Fatal(err)
	}
	newCtx := WithClaimOwner(ctx, *r.Ownership)
	c.advance(2 * time.Minute)
	if _, err = s.ClaimOwned(ctx, req.ID, "receiver", o, time.Minute); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("retired attempt came back: %v", err)
	}
	// A third fresh attempt can continue, while both prior receipts stay stale.
	r, err = s.ClaimOwned(ctx, req.ID, "receiver", claimTuple("node-b", "task-a", "attempt-3"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newCtx = WithClaimOwner(ctx, *r.Ownership)
	if _, err = s.Reply(newCtx, req.ID, "receiver", envelope.Reply{Status: envelope.StatusAnswered, Body: "new"}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedAmbiguousRetriesAndClarification(t *testing.T) {
	s, _ := open(t, ":memory:")
	ctx := context.Background()
	req := ask(t, s, "sender", "receiver", "work")
	r, err := s.ClaimOwned(ctx, req.ID, "receiver", claimTuple("node-a", "task-a", "attempt-1"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	o := *r.Ownership
	retry, err := s.ClaimOwned(ctx, req.ID, "receiver", o, time.Minute)
	if err != nil || retry.Ownership.LeaseGeneration != o.LeaseGeneration || !retry.Ownership.LeaseUntil.Equal(o.LeaseUntil) {
		t.Fatalf("claim retry=%+v %v", retry, err)
	}
	owned := WithClaimOwner(ctx, o)
	question := envelope.Reply{Status: envelope.StatusNeedsInput, Body: "which item?"}
	q, err := s.Reply(owned, req.ID, "receiver", question)
	if err != nil {
		t.Fatal(err)
	}
	q2, err := s.Reply(owned, req.ID, "receiver", question)
	if err != nil || q.Generation != q2.Generation {
		t.Fatalf("question retry=%+v %v", q2, err)
	}
	if _, err = s.Reply(owned, req.ID, "receiver", envelope.Reply{Status: envelope.StatusNeedsInput, Body: "changed?"}); !errors.Is(err, ErrClaimConflict) {
		t.Fatal(err)
	}
	if _, err = s.Answer(ctx, req.ID, "sender", "item 2"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimOwned(ctx, req.ID, "receiver", o, time.Minute); !errors.Is(err, ErrClaimConflict) {
		t.Fatal(err)
	}
	r, err = s.ClaimOwned(ctx, req.ID, "receiver", claimTuple("node-a", "task-a", "attempt-2"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	owned = WithClaimOwner(ctx, *r.Ownership)
	reply := envelope.Reply{Status: envelope.StatusAnswered, Body: "complete"}
	first, err := s.Reply(owned, req.ID, "receiver", reply)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Reply(owned, req.ID, "receiver", reply)
	if err != nil || first.Generation != second.Generation || !first.CreatedAt.Equal(second.CreatedAt) {
		t.Fatalf("reply retry=%+v %v", second, err)
	}
	if _, err = s.Reply(owned, req.ID, "receiver", envelope.Reply{Status: envelope.StatusAnswered, Body: "changed"}); !errors.Is(err, ErrClaimConflict) {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT count(*) FROM replies WHERE request_id=?`, req.ID).Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
}

func TestOwnedReleaseAndInspectDoNotAcknowledge(t *testing.T) {
	s, _ := open(t, ":memory:")
	ctx := context.Background()
	req := ask(t, s, "sender", "receiver", "work")
	r, err := s.ClaimOwned(ctx, req.ID, "receiver", claimTuple("node-a", "task", "one"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ReleaseOwned(ctx, req.ID, "receiver", *r.Ownership); err != nil {
		t.Fatal(err)
	}
	if err = s.ReleaseOwned(ctx, req.ID, "receiver", *r.Ownership); err != nil {
		t.Fatal(err)
	}
	r, err = s.ClaimOwned(ctx, req.ID, "receiver", claimTuple("node-a", "task", "two"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Reply(WithClaimOwner(ctx, *r.Ownership), req.ID, "receiver", envelope.Reply{Status: envelope.StatusAnswered, Body: "done"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Inspect(ctx, req.ID, "sender")
	if err != nil || res.Reply == nil {
		t.Fatal(res, err)
	}
	var seen int64
	s.db.QueryRow(`SELECT reply_seen_at FROM requests WHERE id=?`, req.ID).Scan(&seen)
	if seen != 0 {
		t.Fatalf("inspect acknowledged=%d", seen)
	}
	if _, err = s.Inspect(ctx, req.ID, "stranger"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestOwnedClaimAuditFailureRollsBack(t *testing.T) {
	s, _ := open(t, ":memory:")
	req := ask(t, s, "sender", "receiver", "work")
	if _, err := s.db.Exec(`CREATE TRIGGER reject_claim_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimOwned(context.Background(), req.ID, "receiver", claimTuple("node", "task", "attempt"), time.Minute); err == nil {
		t.Fatal("claim committed despite audit failure")
	}
	r, st, err := s.Request(context.Background(), req.ID)
	if err != nil || st != envelope.StatusQueued || r.Ownership != nil {
		t.Fatalf("rollback=%+v %s %v", r, st, err)
	}
}
