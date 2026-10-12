package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/envelope"
	"github.com/mvanhorn/agent-tincan/internal/store"
)

type workerSender struct {
	status int
	fail   error
	ids    []string
	bodies [][]byte
	onSend func()
}

func (s *workerSender) Verify(context.Context, string, string, string) error { return nil }
func (s *workerSender) Send(_ context.Context, _ string, _ string, _ string, _ string, id string, body []byte) (int, time.Duration, error) {
	s.ids = append(s.ids, id)
	s.bodies = append(s.bodies, append([]byte(nil), body...))
	if s.onSend != nil {
		s.onSend()
	}
	return s.status, 0, s.fail
}

func workerPending(t *testing.T) (*eventFixture, Principal, store.EventSubscription, envelope.Request) {
	t.Helper()
	f := newEventFixture(t, true)
	_, p := f.login(t, "dots")
	sub, err := f.store.PutEventSubscription(t.Context(), store.EventSubscription{ID: "worker-sub", Principal: p.ID, Mailbox: "dots", Name: store.EventRequestQueued, URL: "https://receiver.example/events", Secret: "whsec_fixture", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	req, err := f.store.Enqueue(t.Context(), envelope.Request{From: "sender", To: "dots", TraceID: "trace", Chain: []string{"sender", "dots"}, Kind: envelope.KindAsk, Body: "private body must never appear in events"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return f, p, sub, req
}

func TestEventWorkerDeliversMetadataWithoutAcknowledging(t *testing.T) {
	f, _, _, req := workerPending(t)
	s := &workerSender{status: 204}
	w := NewEventDeliveryWorker(f.store, f.oauth, s)
	if err := w.DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(s.ids) != 1 {
		t.Fatal(s.ids)
	}
	var body map[string]any
	if err := json.Unmarshal(s.bodies[0], &body); err != nil {
		t.Fatal(err)
	}
	data := body["data"].(map[string]any)
	if len(data) != 3 || data["request_id"] != req.ID || data["status"] != "queued" {
		t.Fatal(data)
	}
	if body["eventId"] != s.ids[0] || body["cursor"] != nil {
		t.Fatal(body)
	}
	_, status, err := f.store.Request(t.Context(), req.ID)
	if err != nil || status != envelope.StatusQueued {
		t.Fatal(status, err)
	}
	var seen int64
	f.store.DB().QueryRow(`SELECT reply_seen_at FROM requests WHERE id=?`, req.ID).Scan(&seen)
	if seen != 0 {
		t.Fatal(seen)
	}
	if err := w.DeliverPending(t.Context()); err != nil || len(s.ids) != 1 {
		t.Fatalf("duplicate=%v %v", s.ids, err)
	}
}

func TestEventWorkerAmbiguousDeliveryRetainsStableID(t *testing.T) {
	f, _, _, _ := workerPending(t)
	s := &workerSender{fail: errors.New("ambiguous receipt")}
	w := NewEventDeliveryWorker(f.store, f.oauth, s)
	if err := w.DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Advance just the durable retry availability without waiting in a test.
	if _, err := f.store.DB().Exec(`UPDATE event_deliveries SET available_at=0`); err != nil {
		t.Fatal(err)
	}
	s.fail = nil
	s.status = 202
	if err := w.DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(s.ids) != 2 || s.ids[0] != s.ids[1] || string(s.bodies[0]) != string(s.bodies[1]) {
		t.Fatal(s.ids)
	}
}

func TestEventWorkerTerminalCallbackStatus(t *testing.T) {
	for _, status := range []int{410, 413} {
		t.Run(string(rune(status)), func(t *testing.T) {
			f, _, _, _ := workerPending(t)
			s := &workerSender{status: status}
			w := NewEventDeliveryWorker(f.store, f.oauth, s)
			if err := w.DeliverPending(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := w.DeliverPending(t.Context()); err != nil || len(s.ids) != 1 {
				t.Fatal(s.ids, err)
			}
			var state string
			f.store.DB().QueryRow(`SELECT state FROM event_deliveries LIMIT 1`).Scan(&state)
			if status == 410 && state != "cancelled" || status == 413 && state != "failed" {
				t.Fatalf("status %d state %s", status, state)
			}
		})
	}
}

func TestEventWorkerIndependentRevocation(t *testing.T) {
	f, p, _, _ := workerPending(t)
	_, other := f.login(t, "dots")
	_, err := f.store.PutEventSubscription(t.Context(), store.EventSubscription{ID: "other-sub", Principal: other.ID, Mailbox: "dots", Name: store.EventRequestQueued, URL: "https://receiver.example/other", Secret: "whsec_fixture", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.oauth.RevokePrincipal(t.Context(), p.ID); err != nil {
		t.Fatal(err)
	}
	s := &workerSender{status: 204}
	w := NewEventDeliveryWorker(f.store, f.oauth, s)
	if err = w.DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(s.ids) != 1 {
		t.Fatal(s.ids)
	}
	var cancelled int
	f.store.DB().QueryRow(`SELECT count(*) FROM event_deliveries WHERE state='cancelled'`).Scan(&cancelled)
	if cancelled != 1 {
		t.Fatal(cancelled)
	}
}

func TestEventWorkerRevocationDuringCallbackCannotResurrect(t *testing.T) {
	f, p, sub, _ := workerPending(t)
	s := &workerSender{status: 204, onSend: func() {
		if err := f.store.RevokeEventPrincipal(t.Context(), p.ID); err != nil {
			t.Error(err)
		}
	}}
	w := NewEventDeliveryWorker(f.store, f.oauth, s)
	if err := w.DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	var state string
	f.store.DB().QueryRow(`SELECT state FROM event_deliveries WHERE subscription_id=?`, sub.ID).Scan(&state)
	if state != "cancelled" {
		t.Fatal(state)
	}
	if err := w.DeliverPending(t.Context()); err != nil || len(s.ids) != 1 {
		t.Fatal(s.ids, err)
	}
}
