package store

import (
	"context"
)

// StopEventDeliverySubscription applies HTTP 410 only while its delivery lease
// remains current. A cancelled old delivery cannot stop a recreated same-ID
// subscription after an unsubscribe/resubscribe while the callback was running.
func (s *Store) StopEventDeliverySubscription(ctx context.Context, subscriptionID, eventID, leaseToken string, revision int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().UnixMilli()
	res, err := tx.ExecContext(ctx, `UPDATE event_subscriptions SET revoked_at=? WHERE id=? AND revision=? AND revoked_at=0 AND expires_at>? AND
		EXISTS(SELECT 1 FROM event_deliveries d JOIN event_outbox e ON e.id=d.event_id JOIN event_principals p ON p.principal=event_subscriptions.principal
		WHERE d.subscription_id=event_subscriptions.id AND d.event_id=? AND d.state='leased' AND d.lease_token=? AND d.lease_until>?
		AND e.expires_at>? AND p.revoked_at=0)`, now, subscriptionID, revision, now, eventID, leaseToken, now, now)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrEventDeliveryLease
	}
	if _, err = tx.ExecContext(ctx, `UPDATE event_deliveries SET state='cancelled',lease_until=0 WHERE subscription_id=? AND state IN ('pending','leased')`, subscriptionID); err != nil {
		return err
	}
	return tx.Commit()
}
