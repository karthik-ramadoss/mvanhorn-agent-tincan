package cli

import (
	"context"

	"github.com/mvanhorn/agent-tincan/internal/envelope"
	"github.com/mvanhorn/agent-tincan/internal/relay"
)

// These existing hooks are latency hints. Event rows commit with messages in
// SQLite, so a crash before a hook does not lose a queued notification.
type eventDeliveryHints struct {
	base relay.Events
	wake func()
}

func (h eventDeliveryHints) Queued(ctx context.Context, r envelope.Request) {
	h.base.Queued(ctx, r)
	h.wake()
}
func (h eventDeliveryHints) Requeued(ctx context.Context, r envelope.Request) {
	if b, ok := h.base.(relay.Requeuer); ok {
		b.Requeued(ctx, r)
	} else {
		h.base.Queued(ctx, r)
	}
	h.wake()
}
func (h eventDeliveryHints) Replied(ctx context.Context, r envelope.Request) {
	if b, ok := h.base.(relay.Replier); ok {
		b.Replied(ctx, r)
	}
	h.wake()
}
