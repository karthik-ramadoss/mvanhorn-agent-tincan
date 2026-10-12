package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/envelope"
)

var ErrClaimConflict = errors.New("claim_conflict")
var claimID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

type ownerKey struct{}

// WithClaimOwner supplies authenticated ownership to the existing mutation
// paths. The relay overwrites ActorID from WhoIs before calling this function.
func WithClaimOwner(ctx context.Context, owner envelope.ClaimOwnership) context.Context {
	return context.WithValue(ctx, ownerKey{}, owner)
}

func claimOwner(ctx context.Context) (envelope.ClaimOwnership, bool) {
	o, ok := ctx.Value(ownerKey{}).(envelope.ClaimOwnership)
	return o, ok
}

func ValidClaimOwner(o envelope.ClaimOwnership, generation bool) bool {
	return o.ActorID != "" && claimID.MatchString(o.TaskID) && claimID.MatchString(o.AttemptID) && (!generation || o.LeaseGeneration > 0)
}

func (s *Store) migrateClaims() error {
	for _, col := range []struct{ name, typ string }{
		{"claim_actor", "TEXT NOT NULL DEFAULT ''"}, {"claim_task", "TEXT NOT NULL DEFAULT ''"},
		{"claim_attempt", "TEXT NOT NULL DEFAULT ''"}, {"claim_generation", "INTEGER NOT NULL DEFAULT 0"},
		{"claim_released", "INTEGER NOT NULL DEFAULT 0"},
	} {
		var has bool
		if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pragma_table_info('requests') WHERE name=?)`, col.name).Scan(&has); err != nil {
			return err
		}
		if !has {
			if _, err := s.db.Exec(`ALTER TABLE requests ADD COLUMN ` + col.name + ` ` + col.typ); err != nil {
				return err
			}
		}
	}
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS claim_attempts(
		request_id TEXT NOT NULL REFERENCES requests(id), actor TEXT NOT NULL,task TEXT NOT NULL,attempt TEXT NOT NULL,
		generation INTEGER NOT NULL, PRIMARY KEY(request_id,actor,task,attempt))`)
	return err
}

func sameOwner(a *envelope.ClaimOwnership, b envelope.ClaimOwnership, generation bool) bool {
	return a != nil && a.ActorID == b.ActorID && a.TaskID == b.TaskID && a.AttemptID == b.AttemptID && (!generation || a.LeaseGeneration == b.LeaseGeneration)
}

// ClaimOwned performs a compare-and-swap in SQLite. A lost response is safe to
// retry while the same lease is live; a lost lease requires a fresh attempt.
func (s *Store) ClaimOwned(ctx context.Context, id, agent string, owner envelope.ClaimOwnership, lease time.Duration) (envelope.Request, error) {
	if !ValidClaimOwner(owner, false) || lease <= 0 {
		return envelope.Request{}, ErrClaimConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return envelope.Request{}, err
	}
	defer tx.Rollback()
	now := s.now().UTC().Truncate(time.Millisecond)
	res, err := tx.ExecContext(ctx, `UPDATE requests SET status='claimed', claim_actor=?,claim_task=?,claim_attempt=?,
		claim_generation=claim_generation+1,claim_released=0,lease_until=?,lease_paused=0,updated_at=?,progress_note='',progress_at=0
		WHERE id=? AND to_agent=? AND expires_at>? AND
		(status IN ('queued','delivered') OR (status='claimed' AND lease_until>0 AND lease_until<=?)) AND
		NOT (claim_actor=? AND claim_task=? AND claim_attempt=?) AND
		NOT EXISTS(SELECT 1 FROM claim_attempts WHERE request_id=? AND actor=? AND task=? AND attempt=?)`, owner.ActorID, owner.TaskID, owner.AttemptID,
		now.Add(lease).UnixMilli(), now.UnixMilli(), id, agent, now.UnixMilli(), now.UnixMilli(), owner.ActorID, owner.TaskID, owner.AttemptID, id, owner.ActorID, owner.TaskID, owner.AttemptID)
	if err != nil {
		return envelope.Request{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return envelope.Request{}, err
	}
	req, status, err := scanRequest(tx.QueryRowContext(ctx, `SELECT `+requestCols+` FROM requests WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return envelope.Request{}, ErrNotFound
	}
	if err != nil {
		return envelope.Request{}, err
	}
	if req.To != agent {
		return envelope.Request{}, ErrForbidden
	}
	if n == 0 {
		if status != envelope.StatusClaimed || !sameOwner(req.Ownership, owner, false) || !req.Ownership.LeaseUntil.After(now) {
			return envelope.Request{}, ErrClaimConflict
		}
		var alive bool
		if err := tx.QueryRowContext(ctx, `SELECT expires_at>? FROM requests WHERE id=?`, now.UnixMilli(), id).Scan(&alive); err != nil {
			return envelope.Request{}, err
		}
		if !alive {
			return envelope.Request{}, ErrClaimConflict
		}
	} else {
		if _, err := tx.ExecContext(ctx, `INSERT INTO claim_attempts(request_id,actor,task,attempt,generation) VALUES(?,?,?,?,?)`, id, owner.ActorID, owner.TaskID, owner.AttemptID, req.Ownership.LeaseGeneration); err != nil {
			return envelope.Request{}, err
		}
		if err := s.auditTx(ctx, tx, AuditEvent{Event: "claimed", RequestID: id, TraceID: req.TraceID, Actor: owner.ActorID,
			Detail: DetailJSON(map[string]any{"agent": agent, "task_id": owner.TaskID, "attempt_id": owner.AttemptID, "lease_generation": req.Ownership.LeaseGeneration})}); err != nil {
			return envelope.Request{}, err
		}
	}
	req.Status = status
	return req, tx.Commit()
}

func (s *Store) progressOwned(ctx context.Context, id, agent string, o envelope.ClaimOwnership, note string, lease time.Duration) error {
	if !ValidClaimOwner(o, true) {
		return ErrClaimConflict
	}
	if len(note) > envelope.MaxProgressNote {
		return envelope.ErrBodyTooLarge
	}
	now := s.now().UnixMilli()
	res, err := s.db.ExecContext(ctx, `UPDATE requests SET progress_note=?,progress_at=?,updated_at=?,lease_until=?
		WHERE id=? AND to_agent=? AND status='claimed' AND expires_at>? AND lease_until>?
		AND claim_actor=? AND claim_task=? AND claim_attempt=? AND claim_generation=?`, note, now, now, s.now().Add(lease).UnixMilli(),
		id, agent, now, now, o.ActorID, o.TaskID, o.AttemptID, o.LeaseGeneration)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrClaimConflict
	}
	return nil
}

func (s *Store) replyOwned(ctx context.Context, id, agent string, o envelope.ClaimOwnership, rep envelope.Reply) (envelope.Reply, error) {
	if !ValidClaimOwner(o, true) {
		return envelope.Reply{}, ErrClaimConflict
	}
	if !rep.Status.Terminal() && rep.Status != envelope.StatusNeedsInput {
		return envelope.Reply{}, ErrWrongState
	}
	if rep.Status == envelope.StatusNeedsInput {
		if err := envelope.ValidateInput(rep.Body); err != nil {
			return envelope.Reply{}, err
		}
		if len(rep.Attachments) != 0 {
			return envelope.Reply{}, ErrWrongState
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return envelope.Reply{}, err
	}
	defer tx.Rollback()
	// Take SQLite's writer reservation before reading the current reply so two
	// identical retries on separate connections serialize without a snapshot
	// upgrade failure. This does not change request state or queue generation.
	if _, err = tx.ExecContext(ctx, `UPDATE requests SET claim_generation=claim_generation WHERE id=?`, id); err != nil {
		return envelope.Reply{}, err
	}
	req, status, err := scanRequest(tx.QueryRowContext(ctx, `SELECT `+requestCols+` FROM requests WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return envelope.Reply{}, ErrNotFound
	}
	if err != nil {
		return envelope.Reply{}, err
	}
	if req.To != agent {
		return envelope.Reply{}, ErrForbidden
	}
	if !sameOwner(req.Ownership, o, true) {
		return envelope.Reply{}, ErrClaimConflict
	}
	// Retrying the exact committed operation does not create a new reply/event.
	if status.Terminal() || status == envelope.StatusNeedsInput {
		var old envelope.Reply
		var atts string
		var created int64
		err := tx.QueryRowContext(ctx, `SELECT from_agent,status,body,attachments,created_at,(SELECT reply_generation FROM requests WHERE id=?) FROM replies WHERE request_id=?`, id, id).
			Scan(&old.From, &old.Status, &old.Body, &atts, &created, &old.Generation)
		if err != nil {
			return envelope.Reply{}, ErrClaimConflict
		}
		old.Attachments, err = decodeAttachments(atts)
		if err != nil {
			return envelope.Reply{}, err
		}
		if old.Status != rep.Status || old.Body != rep.Body || !sameAttachmentIDs(old.Attachments, rep.Attachments) {
			return envelope.Reply{}, ErrClaimConflict
		}
		old.RequestID = id
		old.CreatedAt = time.UnixMilli(created).UTC()
		return old, tx.Commit()
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	if status != envelope.StatusClaimed || !req.Ownership.LeaseUntil.After(now) {
		return envelope.Reply{}, ErrClaimConflict
	}
	var exchanges string
	if rep.Status == envelope.StatusNeedsInput {
		if req.Kind != envelope.KindAsk || len(req.Exchanges) >= envelope.MaxExchanges {
			return envelope.Reply{}, ErrWrongState
		}
		req.Exchanges = append(req.Exchanges, envelope.Exchange{Question: rep.Body, At: now})
		b, err := json.Marshal(req.Exchanges)
		if err != nil {
			return envelope.Reply{}, err
		}
		exchanges = string(b)
	}
	res, err := tx.ExecContext(ctx, `UPDATE requests SET status=?,lease_until=0,updated_at=?,reply_seen_at=CASE WHEN kind='ping' THEN ? ELSE 0 END,
		reply_generation=reply_generation+1,lease_paused=?,exchanges=CASE WHEN ?='' THEN exchanges ELSE ? END
		WHERE id=? AND to_agent=? AND status='claimed' AND expires_at>? AND lease_until>?
		AND claim_actor=? AND claim_task=? AND claim_attempt=? AND claim_generation=?`, rep.Status, now.UnixMilli(), now.UnixMilli(),
		rep.Status == envelope.StatusNeedsInput, exchanges, exchanges, id, agent, now.UnixMilli(), now.UnixMilli(), o.ActorID, o.TaskID, o.AttemptID, o.LeaseGeneration)
	if err != nil {
		return envelope.Reply{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return envelope.Reply{}, err
	}
	if n != 1 {
		return envelope.Reply{}, ErrClaimConflict
	}
	if err := tx.QueryRowContext(ctx, `SELECT reply_generation FROM requests WHERE id=?`, id).Scan(&rep.Generation); err != nil {
		return envelope.Reply{}, err
	}
	rep.RequestID, rep.From, rep.CreatedAt = id, agent, now
	var atts string
	rep.Attachments, atts, err = bindAndEncodeAttachments(ctx, tx, rep.Attachments, agent, id)
	if err != nil {
		return envelope.Reply{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO replies(request_id,from_agent,status,body,created_at,attachments) VALUES(?,?,?,?,?,?)`, id, agent, rep.Status, rep.Body, now.UnixMilli(), atts); err != nil {
		return envelope.Reply{}, err
	}
	if err = s.auditTx(ctx, tx, AuditEvent{Event: "replied", RequestID: id, TraceID: req.TraceID, Actor: o.ActorID, Detail: DetailJSON(map[string]any{"agent": agent, "status": rep.Status, "lease_generation": o.LeaseGeneration})}); err != nil {
		return envelope.Reply{}, err
	}
	return rep, tx.Commit()
}

func sameAttachmentIDs(a, b []envelope.Attachment) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

// ReleaseOwned is idempotent for the last successful release only. Expired or
// superseded workers cannot release a replacement generation.
func (s *Store) ReleaseOwned(ctx context.Context, id, agent string, o envelope.ClaimOwnership) error {
	if !ValidClaimOwner(o, true) {
		return ErrClaimConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().UnixMilli()
	res, err := tx.ExecContext(ctx, `UPDATE requests SET status='queued',lease_until=0,claim_released=1,updated_at=?,progress_note='',progress_at=0
		WHERE id=? AND to_agent=? AND status='claimed' AND expires_at>? AND lease_until>?
		AND claim_actor=? AND claim_task=? AND claim_attempt=? AND claim_generation=?`, now, id, agent, now, now, o.ActorID, o.TaskID, o.AttemptID, o.LeaseGeneration)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var retry bool
		err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM requests WHERE id=? AND to_agent=? AND status='queued' AND claim_released=1 AND expires_at>?
		AND claim_actor=? AND claim_task=? AND claim_attempt=? AND claim_generation=?)`, id, agent, now, o.ActorID, o.TaskID, o.AttemptID, o.LeaseGeneration).Scan(&retry)
		if err != nil {
			return err
		}
		if !retry {
			return ErrClaimConflict
		}
	} else if err = s.auditTx(ctx, tx, AuditEvent{Event: "released", RequestID: id, Actor: o.ActorID, Detail: DetailJSON(map[string]any{"agent": agent, "lease_generation": o.LeaseGeneration})}); err != nil {
		return err
	}
	return tx.Commit()
}

// Inspect returns current state without delivery or reply acknowledgement.
func (s *Store) Inspect(ctx context.Context, id, agent string) (envelope.Result, error) {
	req, status, err := s.lookup(ctx, id)
	if err != nil {
		return envelope.Result{}, err
	}
	if req.From != agent && req.To != agent {
		return envelope.Result{}, ErrNotFound
	}
	rep, err := s.replyFor(ctx, id)
	if err != nil {
		return envelope.Result{}, err
	}
	req.RedactFor(agent)
	return envelope.Result{Request: req, Status: status, Reply: rep, Progress: req.Progress, Exchanges: req.Exchanges}, nil
}
