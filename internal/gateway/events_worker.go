package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/store"
)

// EventDeliveryWorker runs inside the existing relay process. Wake hints reduce
// latency; SQLite remains the source of pending work across every restart.
type EventDeliveryWorker struct {
	store  *store.Store
	oauth  *OAuth
	sender WebhookSender
	wake   chan struct{}
}

func NewEventDeliveryWorker(st *store.Store, oauth *OAuth, sender WebhookSender) *EventDeliveryWorker {
	if sender == nil {
		sender = NewWebhookSender()
	}
	return &EventDeliveryWorker{store: st, oauth: oauth, sender: sender, wake: make(chan struct{}, 1)}
}

func (w *EventDeliveryWorker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *EventDeliveryWorker) Run(ctx context.Context) error {
	if err := w.store.ReconcileEvents(ctx); err != nil {
		return err
	}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	w.Wake()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-w.wake:
		case <-tick.C:
		}
		if err := w.DeliverPending(ctx); err != nil && ctx.Err() == nil {
			log.Printf("MCP event delivery: state operation failed: %v", err)
		}
	}
}

// DeliverPending rechecks both subscription and grant before every outbound
// attempt. It never reads through taking inbox/Get APIs or holds refresh tokens.
func (w *EventDeliveryWorker) DeliverPending(ctx context.Context) error {
	deliveries, err := w.store.LeaseEventDeliveries(ctx, 8, 3*time.Minute)
	if err != nil {
		return err
	}
	for _, d := range deliveries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		active, err := w.oauth.PrincipalActive(ctx, d.Subscription.Principal)
		if err != nil {
			return err
		}
		_, exists, err := w.store.AgentByName(ctx, d.Subscription.Mailbox)
		if err != nil {
			return err
		}
		if !active || !exists {
			if err = w.store.RevokeEventPrincipal(ctx, d.Subscription.Principal); err != nil {
				return err
			}
			continue
		}
		// Renewals may rotate the signing key and unsubscribe may cancel a lease.
		subs, err := w.store.EventSubscriptions(ctx, d.Subscription.Principal, d.Subscription.Mailbox)
		if err != nil {
			return err
		}
		var sub *store.EventSubscription
		for i := range subs {
			if subs[i].ID == d.Subscription.ID {
				sub = &subs[i]
				break
			}
		}
		if sub == nil {
			continue
		}
		body, err := json.Marshal(map[string]any{"eventId": d.Event.ID, "name": d.Event.Name, "timestamp": d.Event.OccurredAt.UTC().Format(time.RFC3339Nano),
			"data": map[string]any{"request_id": d.Event.RequestID, "status": d.Event.Status, "generation": d.Event.Generation}, "cursor": nil})
		if err != nil {
			return err
		}
		status, sendErr := w.sender.Send(ctx, sub.ID, sub.URL, sub.Secret, sub.PreviousSecret, d.Event.ID, body)
		if status == 410 {
			if err = w.store.StopEventDeliverySubscription(ctx, sub.ID, d.Event.ID, d.LeaseToken, sub.Revision); err != nil && !errors.Is(err, store.ErrEventDeliveryLease) {
				return err
			}
			continue
		}
		terminal := status == 413 || (status >= 400 && status < 500 && status != 408 && status != 429)
		var callback *CallbackEndpointError
		if errors.As(sendErr, &callback) && (callback.Reason == "invalid_url" || callback.Reason == "invalid_secret" || callback.Reason == "blocked_address" || callback.Reason == "payload_too_large") {
			terminal = true
		}
		if terminal {
			err = w.store.FailEventDelivery(ctx, sub.ID, d.Event.ID, d.LeaseToken)
		} else {
			err = w.store.FinishEventDelivery(ctx, sub.ID, d.Event.ID, d.LeaseToken, sendErr == nil && status >= 200 && status < 300, 0)
		}
		if err != nil && !errors.Is(err, store.ErrEventDeliveryLease) {
			return err
		}
	}
	if len(deliveries) == 8 {
		w.Wake()
	}
	return nil
}
