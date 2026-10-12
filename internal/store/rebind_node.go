package store

import (
	"context"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/identity"
)

// ReplaceAgentNode commits the compare-and-swap and audit in one transaction.
// UPDATE preserves all non-identity columns and all work/token state.
func (s *Store) ReplaceAgentNode(ctx context.Context, name, expectedOld string, target identity.Node, now time.Time) (identity.Agent, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return identity.Agent{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE agents SET node_id=?,node_name=?,node_user=?
		WHERE name=? AND node_id=? AND NOT EXISTS(SELECT 1 FROM invites WHERE name=? AND expires>=?)`,
		target.ID, target.Name, nullable(target.User), name, expectedOld, name, now.UnixMilli())
	if err != nil {
		return identity.Agent{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return identity.Agent{}, err
	}
	if n != 1 {
		var pending bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM invites WHERE name=? AND expires>=?)`, name, now.UnixMilli()).Scan(&pending); err != nil {
			return identity.Agent{}, err
		}
		if pending {
			return identity.Agent{}, identity.ErrPendingInvite
		}
		return identity.Agent{}, identity.ErrEnrollmentConflict
	}
	var a identity.Agent
	var joined int64
	if err := tx.QueryRowContext(ctx, `SELECT name,node_id,node_name,joined_at,COALESCE(kind,''),COALESCE(node_user,''),COALESCE(good_at,'') FROM agents WHERE name=?`, name).Scan(&a.Name, &a.NodeID, &a.NodeName, &joined, &a.Kind, &a.NodeUser, &a.GoodAt); err != nil {
		return identity.Agent{}, err
	}
	a.JoinedAt = time.UnixMilli(joined).UTC()
	if err := s.auditTx(ctx, tx, AuditEvent{Event: "rebound_node", Actor: identity.LocalAdmin, Detail: DetailJSON(map[string]any{
		"agent": name, "old_node": expectedOld, "new_node": target.ID, "new_node_name": target.Name,
	})}); err != nil {
		return identity.Agent{}, err
	}
	return a, tx.Commit()
}
