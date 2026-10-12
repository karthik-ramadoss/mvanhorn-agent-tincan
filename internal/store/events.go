package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	EventRequestQueued = "tincan.request.queued"
	EventReplyCreated  = "tincan.reply.created"
	EventMaxAttempts   = 8
	EventRetention     = 24 * time.Hour
	EventSecretOverlap = 5 * time.Minute
)

var (
	ErrEventSubscriptionConflict = errors.New("event subscription binding conflicts")
	ErrEventPrincipalRevoked     = errors.New("event principal revoked")
	ErrEventDeliveryLease        = errors.New("event delivery lease is stale")
	ErrEventInvalid              = errors.New("invalid event subscription or delivery")
)

// EventSubscription is bound to one authenticated grant principal and mailbox.
// The gateway validates HTTPS callback ownership before persisting it. Secrets
// are private relay state and must never appear in event payloads or logs.
type EventSubscription struct {
	ID, Principal, Mailbox, Name, URL, Secret, PreviousSecret string
	ExpiresAt, PreviousUntil                                  time.Time
	Revision                                                  int64 // internal refresh/resubscribe fence, never event payload
}

// Event carries only identifiers and state, never request/reply bodies. Queue
// generations are monotonically increasing queue transitions or the existing
// reply generation. Delivery crashes before a claim still produce a new queue
// generation; neither counter is the ownership lease generation.
type Event struct {
	ID, Name, Mailbox, RequestID, Status string
	Generation                           int64
	OccurredAt                           time.Time
}

// EventDelivery is a server-issued worker receipt. A worker may finish only its
// unexpired lease. A retry after an ambiguous callback retains the same Event.ID.
type EventDelivery struct {
	Subscription EventSubscription
	Event        Event
	LeaseToken   string
	Attempts     int
	LeaseUntil   time.Time
}

const eventSchema = `
CREATE TABLE IF NOT EXISTS event_principals (
 principal TEXT PRIMARY KEY,
 revoked_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS event_subscriptions (
 id TEXT PRIMARY KEY,
 principal TEXT NOT NULL REFERENCES event_principals(principal),
 mailbox TEXT NOT NULL,
 name TEXT NOT NULL CHECK(name IN ('tincan.request.queued','tincan.reply.created')),
 url TEXT NOT NULL,
 secret TEXT NOT NULL,
 previous_secret TEXT NOT NULL DEFAULT '',
 previous_until INTEGER NOT NULL DEFAULT 0,
 expires_at INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 revoked_at INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS event_subscriptions_mailbox ON event_subscriptions(mailbox,name);
CREATE TABLE IF NOT EXISTS event_outbox (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 mailbox TEXT NOT NULL,
 request_id TEXT NOT NULL,
 status TEXT NOT NULL,
 generation INTEGER NOT NULL,
 occurred_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS event_deliveries (
 subscription_id TEXT NOT NULL REFERENCES event_subscriptions(id),
 event_id TEXT NOT NULL REFERENCES event_outbox(id),
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','delivered','failed','cancelled')),
 attempts INTEGER NOT NULL DEFAULT 0,
 available_at INTEGER NOT NULL,
 lease_token TEXT NOT NULL DEFAULT '',
 lease_until INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(subscription_id,event_id)
);
CREATE INDEX IF NOT EXISTS event_deliveries_ready ON event_deliveries(state,available_at,lease_until);
CREATE TRIGGER IF NOT EXISTS event_outbox_deliveries AFTER INSERT ON event_outbox BEGIN
 INSERT OR IGNORE INTO event_deliveries(subscription_id,event_id,available_at)
 SELECT s.id,NEW.id,NEW.occurred_at FROM event_subscriptions s JOIN event_principals p ON p.principal=s.principal
 WHERE s.mailbox=NEW.mailbox AND s.name=NEW.name AND s.revoked_at=0 AND p.revoked_at=0 AND s.expires_at>NEW.occurred_at;
END;
CREATE TRIGGER IF NOT EXISTS event_request_insert AFTER INSERT ON requests WHEN NEW.status='queued' BEGIN
 INSERT OR IGNORE INTO event_outbox(id,name,mailbox,request_id,status,generation,occurred_at,expires_at)
 VALUES ('tincan.request.queued:'||NEW.id||':'||NEW.queue_generation,
 'tincan.request.queued',NEW.to_agent,NEW.id,'queued',NEW.queue_generation,NEW.updated_at,NEW.updated_at+86400000);
END;
CREATE TRIGGER IF NOT EXISTS event_request_queue AFTER UPDATE OF status ON requests WHEN NEW.status='queued' AND OLD.status!='queued' BEGIN
 UPDATE requests SET queue_generation=queue_generation+1 WHERE id=NEW.id;
 INSERT OR IGNORE INTO event_outbox(id,name,mailbox,request_id,status,generation,occurred_at,expires_at)
 SELECT 'tincan.request.queued:'||id||':'||queue_generation,
 'tincan.request.queued',to_agent,id,'queued',queue_generation,updated_at,updated_at+86400000 FROM requests WHERE id=NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS event_reply_insert AFTER INSERT ON replies BEGIN
 INSERT OR IGNORE INTO event_outbox(id,name,mailbox,request_id,status,generation,occurred_at,expires_at)
 SELECT 'tincan.reply.created:'||NEW.request_id||':'||q.reply_generation,'tincan.reply.created',q.from_agent,
 NEW.request_id,NEW.status,q.reply_generation,NEW.created_at,NEW.created_at+86400000 FROM requests q WHERE q.id=NEW.request_id;
END;
`

// InitEvents is opt-in; call after the claim migration and only when native
// events are configured. Triggers journal within the message writer's existing
// transaction. No hook, inbox read, or in-memory wake is needed for durability.
func (s *Store) InitEvents() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(eventSchema); err != nil {
		return fmt.Errorf("event schema: %w", err)
	}
	if err := s.reconcileEvents(context.Background(), tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ReconcileEvents recovers currently outstanding work using raw non-taking
// reads. It never acknowledges requests or marks replies seen. Existing event
// and delivery primary keys make repeated startup reconciliation idempotent.
func (s *Store) ReconcileEvents(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.reconcileEvents(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) reconcileEvents(ctx context.Context, tx *sql.Tx) error {
	now := s.now().UnixMilli()
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO event_outbox(id,name,mailbox,request_id,status,generation,occurred_at,expires_at)
 SELECT 'tincan.request.queued:'||id||':'||queue_generation,'tincan.request.queued',to_agent,id,'queued',
 queue_generation,updated_at,updated_at+86400000 FROM requests WHERE status='queued' AND expires_at>?`, now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO event_outbox(id,name,mailbox,request_id,status,generation,occurred_at,expires_at)
 SELECT 'tincan.reply.created:'||q.id||':'||q.reply_generation,'tincan.reply.created',q.from_agent,q.id,r.status,
 q.reply_generation,r.created_at,r.created_at+86400000 FROM requests q JOIN replies r ON r.request_id=q.id
 WHERE q.reply_seen_at=0 AND q.status IN ('answered','failed','declined','needs_input')`)
	return err
}

// PutEventSubscription creates or renews one verified subscription. The
// authenticated binding cannot be changed by an ID collision. A secret change
// and expiry renewal commit together, with a short overlap for dual signing.
// Explicit resubscription can reactivate an unsubscribed ID, but old cancelled
// deliveries remain cancelled. A revoked grant can never be reactivated.
func (s *Store) PutEventSubscription(ctx context.Context, sub EventSubscription) (EventSubscription, error) {
	now := s.now()
	if sub.ID == "" || sub.Principal == "" || sub.Mailbox == "" || sub.URL == "" || sub.Secret == "" ||
		(sub.Name != EventRequestQueued && sub.Name != EventReplyCreated) || !sub.ExpiresAt.After(now) {
		return EventSubscription{}, ErrEventInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EventSubscription{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO event_principals(principal) VALUES (?)`, sub.Principal); err != nil {
		return EventSubscription{}, err
	}
	var revoked int64
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at FROM event_principals WHERE principal=?`, sub.Principal).Scan(&revoked); err != nil {
		return EventSubscription{}, err
	}
	if revoked != 0 {
		return EventSubscription{}, ErrEventPrincipalRevoked
	}
	var oldRevoked int64
	old, err := scanEventSubscription(extraCols{tx.QueryRowContext(ctx, `SELECT `+eventSubscriptionCols+`, revoked_at FROM event_subscriptions WHERE id=?`, sub.ID), []any{&oldRevoked}}, now)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return EventSubscription{}, err
	}
	created := errors.Is(err, sql.ErrNoRows)
	if !created && (old.Principal != sub.Principal || old.Mailbox != sub.Mailbox || old.Name != sub.Name || old.URL != sub.URL) {
		return EventSubscription{}, ErrEventSubscriptionConflict
	}
	if !created && (oldRevoked != 0 || !old.ExpiresAt.After(now)) {
		if _, err := tx.ExecContext(ctx, `UPDATE event_deliveries SET state='cancelled',lease_until=0 WHERE subscription_id=? AND state IN ('pending','leased')`, sub.ID); err != nil {
			return EventSubscription{}, err
		}
	}
	sub.PreviousSecret, sub.PreviousUntil = old.PreviousSecret, old.PreviousUntil
	if !created && old.Secret != sub.Secret {
		sub.PreviousSecret, sub.PreviousUntil = old.Secret, now.Add(EventSecretOverlap)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO event_subscriptions(id,principal,mailbox,name,url,secret,previous_secret,previous_until,expires_at,created_at)
 VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET secret=excluded.secret,previous_secret=excluded.previous_secret,
 previous_until=excluded.previous_until,expires_at=excluded.expires_at,revoked_at=0,revision=event_subscriptions.revision+1`,
		sub.ID, sub.Principal, sub.Mailbox, sub.Name, sub.URL, sub.Secret, sub.PreviousSecret, eventTime(sub.PreviousUntil), sub.ExpiresAt.UnixMilli(), now.UnixMilli()); err != nil {
		return EventSubscription{}, err
	}
	if err := s.reconcileEvents(ctx, tx); err != nil {
		return EventSubscription{}, err
	}
	// Subscribe has no replay cursor. Only the current non-acknowledged queue
	// generation or unseen reply is attached, not the historical journal.
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO event_deliveries(subscription_id,event_id,available_at)
 SELECT ?,e.id,? FROM event_outbox e JOIN requests q ON q.id=e.request_id
 WHERE e.mailbox=? AND e.name=? AND e.expires_at>? AND (
 (e.name='tincan.request.queued' AND q.status='queued' AND q.expires_at>? AND e.id='tincan.request.queued:'||q.id||':'||q.queue_generation) OR
 (e.name='tincan.reply.created' AND q.reply_seen_at=0 AND q.status IN ('answered','failed','declined','needs_input') AND e.generation=q.reply_generation))`,
		sub.ID, now.UnixMilli(), sub.Mailbox, sub.Name, now.UnixMilli(), now.UnixMilli()); err != nil {
		return EventSubscription{}, err
	}
	if err := tx.Commit(); err != nil {
		return EventSubscription{}, err
	}
	if created {
		sub.Revision = 1
	} else {
		sub.Revision = old.Revision + 1
	}
	return sub, nil
}

func eventTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

const eventSubscriptionCols = `id, principal, mailbox, name, url, secret, previous_secret, expires_at, previous_until, revision`

func scanEventSubscription(sc scanner, now time.Time) (EventSubscription, error) {
	var sub EventSubscription
	var expires, previous int64
	err := sc.Scan(&sub.ID, &sub.Principal, &sub.Mailbox, &sub.Name, &sub.URL, &sub.Secret, &sub.PreviousSecret, &expires, &previous, &sub.Revision)
	if err != nil {
		return EventSubscription{}, err
	}
	sub.ExpiresAt = time.UnixMilli(expires).UTC()
	if previous > now.UnixMilli() {
		sub.PreviousUntil = time.UnixMilli(previous).UTC()
	} else {
		sub.PreviousSecret = ""
	}
	return sub, nil
}

// EventSubscriptions lists only a grant's active subscriptions in its exact
// mailbox. The gateway derives both values from OAuth, never event arguments.
func (s *Store) EventSubscriptions(ctx context.Context, principal, mailbox string) ([]EventSubscription, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+prefixed("s.", eventSubscriptionCols)+` FROM event_subscriptions s
 JOIN event_principals p ON p.principal=s.principal WHERE s.principal=? AND s.mailbox=? AND s.revoked_at=0 AND p.revoked_at=0 AND s.expires_at>? ORDER BY s.id`, principal, mailbox, s.now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventSubscription
	for rows.Next() {
		sub, err := scanEventSubscription(rows, s.now())
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// DeleteEventSubscription is idempotent for its owner and forbids other grants.
func (s *Store) DeleteEventSubscription(ctx context.Context, principal, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner string
	if err := tx.QueryRowContext(ctx, `SELECT principal FROM event_subscriptions WHERE id=?`, id).Scan(&owner); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	if owner != principal {
		return ErrForbidden
	}
	if _, err := tx.ExecContext(ctx, `UPDATE event_subscriptions SET revoked_at=? WHERE id=?`, s.now().UnixMilli(), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE event_deliveries SET state='cancelled',lease_until=0 WHERE subscription_id=? AND state IN ('pending','leased')`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeEventPrincipal permanently revokes one grant independently of other
// principals sharing its mailbox, including a grant with no subscriptions yet.
func (s *Store) RevokeEventPrincipal(ctx context.Context, principal string) error {
	if principal == "" {
		return ErrEventInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().UnixMilli()
	if _, err := tx.ExecContext(ctx, `INSERT INTO event_principals(principal,revoked_at) VALUES (?,?) ON CONFLICT(principal) DO UPDATE SET revoked_at=excluded.revoked_at`, principal, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE event_subscriptions SET revoked_at=? WHERE principal=?`, now, principal); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE event_deliveries SET state='cancelled',lease_until=0 WHERE subscription_id IN (SELECT id FROM event_subscriptions WHERE principal=?) AND state IN ('pending','leased')`, principal); err != nil {
		return err
	}
	return tx.Commit()
}

// LeaseEventDeliveries atomically takes a bounded batch. Expired leases are
// eligible again after a crash; each network attempt consumes one durable retry.
// The gateway must additionally recheck its OAuth principal before each send.
func (s *Store) LeaseEventDeliveries(ctx context.Context, limit int, lease time.Duration) ([]EventDelivery, error) {
	if limit <= 0 || limit > 100 || lease <= 0 || lease > 5*time.Minute {
		return nil, ErrEventInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := s.now().UnixMilli()
	if _, err := tx.ExecContext(ctx, `UPDATE event_deliveries SET state='cancelled',lease_until=0 WHERE state IN ('pending','leased') AND subscription_id IN (
 SELECT s.id FROM event_subscriptions s JOIN event_principals p ON p.principal=s.principal WHERE s.revoked_at!=0 OR s.expires_at<=? OR p.revoked_at!=0)`, now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE event_deliveries SET state='failed',lease_until=0 WHERE state IN ('pending','leased') AND
 ((attempts>=? AND lease_until<=?) OR event_id IN (SELECT id FROM event_outbox WHERE expires_at<=?))`, EventMaxAttempts, now, now); err != nil {
		return nil, err
	}
	token, until := randomID(), s.now().Add(lease).UnixMilli()
	rows, err := tx.QueryContext(ctx, `UPDATE event_deliveries SET state='leased',attempts=attempts+1,lease_token=?,lease_until=?
 WHERE (subscription_id,event_id) IN (SELECT d.subscription_id,d.event_id FROM event_deliveries d
 JOIN event_subscriptions s ON s.id=d.subscription_id JOIN event_principals p ON p.principal=s.principal JOIN event_outbox e ON e.id=d.event_id
 WHERE d.state IN ('pending','leased') AND d.available_at<=? AND d.lease_until<=? AND d.attempts<?
 AND s.revoked_at=0 AND p.revoked_at=0 AND s.expires_at>? AND e.expires_at>? ORDER BY d.available_at,d.event_id,d.subscription_id LIMIT ?)
 RETURNING subscription_id,event_id,attempts`, token, until, now, now, EventMaxAttempts, now, now, limit)
	if err != nil {
		return nil, err
	}
	var deliveries []EventDelivery
	for rows.Next() {
		var d EventDelivery
		if err := rows.Scan(&d.Subscription.ID, &d.Event.ID, &d.Attempts); err != nil {
			rows.Close()
			return nil, err
		}
		d.LeaseToken, d.LeaseUntil = token, time.UnixMilli(until).UTC()
		deliveries = append(deliveries, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range deliveries {
		d := &deliveries[i]
		if d.Subscription, err = scanEventSubscription(tx.QueryRowContext(ctx, `SELECT `+eventSubscriptionCols+` FROM event_subscriptions WHERE id=?`, d.Subscription.ID), s.now()); err != nil {
			return nil, err
		}
		var at int64
		if err := tx.QueryRowContext(ctx, `SELECT id,name,mailbox,request_id,status,generation,occurred_at FROM event_outbox WHERE id=?`, d.Event.ID).
			Scan(&d.Event.ID, &d.Event.Name, &d.Event.Mailbox, &d.Event.RequestID, &d.Event.Status, &d.Event.Generation, &at); err != nil {
			return nil, err
		}
		d.Event.OccurredAt = time.UnixMilli(at).UTC()
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return deliveries, nil
}

// FinishEventDelivery accepts only the current lease receipt of an active
// subscription. A repeated identical completion is idempotent until another
// worker leases it. Callbacks use Event.ID to deduplicate ambiguous successes.
func (s *Store) FinishEventDelivery(ctx context.Context, subscriptionID, eventID, leaseToken string, success bool, retryAfter time.Duration) error {
	outcome := "retry"
	if success {
		outcome = "delivered"
	}
	return s.finishEventDelivery(ctx, subscriptionID, eventID, leaseToken, outcome, retryAfter)
}

// FailEventDelivery records a non-retryable callback failure (for example 410,
// 413, or a rejected callback destination) with the same lease fencing as an
// ordinary completion. Unsubscribing additionally stops future events.
func (s *Store) FailEventDelivery(ctx context.Context, subscriptionID, eventID, leaseToken string) error {
	return s.finishEventDelivery(ctx, subscriptionID, eventID, leaseToken, "failed", 0)
}

func (s *Store) finishEventDelivery(ctx context.Context, subscriptionID, eventID, leaseToken, outcome string, retryAfter time.Duration) error {
	if subscriptionID == "" || eventID == "" || leaseToken == "" || retryAfter < 0 {
		return ErrEventInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state, token string
	var attempts int
	var until, revoked, expires, principalRevoked, eventExpires int64
	if err := tx.QueryRowContext(ctx, `SELECT d.state,d.lease_token,d.attempts,d.lease_until,s.revoked_at,s.expires_at,p.revoked_at,e.expires_at
 FROM event_deliveries d JOIN event_subscriptions s ON s.id=d.subscription_id JOIN event_principals p ON p.principal=s.principal JOIN event_outbox e ON e.id=d.event_id
 WHERE d.subscription_id=? AND d.event_id=?`, subscriptionID, eventID).
		Scan(&state, &token, &attempts, &until, &revoked, &expires, &principalRevoked, &eventExpires); errors.Is(err, sql.ErrNoRows) {
		return ErrEventDeliveryLease
	} else if err != nil {
		return err
	}
	now := s.now()
	if token != leaseToken || revoked != 0 || principalRevoked != 0 || expires <= now.UnixMilli() || eventExpires <= now.UnixMilli() {
		return ErrEventDeliveryLease
	}
	if (outcome == "delivered" && state == "delivered") || (outcome == "failed" && state == "failed" && until == 0) ||
		(outcome == "retry" && until == 0 && (state == "pending" || state == "failed")) {
		return nil
	}
	if state != "leased" || until <= now.UnixMilli() {
		return ErrEventDeliveryLease
	}
	nextState, available := outcome, now.UnixMilli()
	if outcome == "retry" {
		nextState = "pending"
		// Respect Retry-After within a bounded retry horizon and apply at least
		// exponential backoff so a bad callback cannot create a tight loop.
		backoff := time.Second * time.Duration(1<<min(attempts, 10))
		retryAfter = min(max(retryAfter, backoff), time.Hour)
		available = now.Add(retryAfter).UnixMilli()
		if attempts >= EventMaxAttempts || available >= eventExpires || available >= expires {
			nextState = "failed"
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE event_deliveries SET state=?,available_at=?,lease_until=0 WHERE subscription_id=? AND event_id=? AND lease_token=?`, nextState, available, subscriptionID, eventID, leaseToken); err != nil {
		return err
	}
	return tx.Commit()
}
