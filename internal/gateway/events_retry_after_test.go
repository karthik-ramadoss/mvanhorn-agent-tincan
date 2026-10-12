package gateway

import (
	"context"
	"net/http"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/envelope"
	"github.com/mvanhorn/agent-tincan/internal/identity"
	"github.com/mvanhorn/agent-tincan/internal/store"
)

func TestWebhookRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, value string
		want        time.Duration
	}{
		{"seconds", "60", time.Minute},
		{"whitespace", " \t60 \t", time.Minute},
		{"leading_zeroes", "00060", time.Minute},
		{"zero", "0", 0},
		{"maximum", "3600", time.Hour},
		{"clamped", "3601", time.Hour},
		{"duration_overflow_prevented", "9223372036854775807", time.Hour},
		{"maximum_uint", "18446744073709551615", time.Hour},
		{"integer_overflow", "18446744073709551616", 0},
		{"empty", "", 0},
		{"negative", "-1", 0},
		{"plus_sign", "+60", 0},
		{"fraction", "1.5", 0},
		{"exponent", "1e2", 0},
		{"malformed", "retry later", 0},
		{"multiple_values", "60, 120", 0},
		{"non_http_whitespace", "\u00a060\u00a0", 0},
		{"http_date", now.Add(time.Minute).Format(http.TimeFormat), time.Minute},
		{"http_date_whitespace", " \t" + now.Add(time.Minute).Format(http.TimeFormat) + " \t", time.Minute},
		{"obsolete_rfc850_date", now.Add(time.Minute).Format(time.RFC850), time.Minute},
		{"obsolete_asctime_date", now.Add(time.Minute).Format(time.ANSIC), time.Minute},
		{"past_date", now.Add(-time.Minute).Format(http.TimeFormat), 0},
		{"present_date", now.Format(http.TimeFormat), 0},
		{"clamped_date", now.Add(2 * time.Hour).Format(http.TimeFormat), time.Hour},
		{"far_future_date", time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).Format(http.TimeFormat), time.Hour},
		{"bad_date", "Mon, 32 Oct 2026 12:00:00 GMT", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := webhookRetryAfter(tc.value, now); got != tc.want {
				t.Fatalf("Retry-After %q: got %s, want %s", tc.value, got, tc.want)
			}
		})
	}
}

func TestWebhookSendReturnsRetryAfterForTransientStatuses(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		status int
		values []string
		want   time.Duration
	}{
		{429, []string{"60"}, time.Minute},
		{408, []string{now.Add(90 * time.Second).Format(http.TimeFormat)}, 90 * time.Second},
		{500, []string{"60"}, time.Minute},
		{503, []string{" \t60 \t"}, time.Minute},
		{599, []string{"7200"}, time.Hour},
		{429, []string{"60", "120"}, 0},
		{503, []string{"invalid"}, 0},
		{204, []string{"60"}, 0},
		{302, []string{"60"}, 0},
		{404, []string{"60"}, 0},
		{410, []string{"60"}, 0},
		{413, []string{"60"}, 0},
	} {
		t.Run(strconv.Itoa(tc.status)+"/"+tc.values[0], func(t *testing.T) {
			sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
				for _, value := range tc.values {
					w.Header().Add("Retry-After", value)
				}
				w.WriteHeader(tc.status)
			})
			sender.now = func() time.Time { return now }
			status, retryAfter, err := sender.Send(context.Background(), "sub_1", callback, webhookTestSecret(1, 32), "", "evt_1", []byte(`{"eventId":"evt_1"}`))
			if err != nil || status != tc.status || retryAfter != tc.want {
				t.Fatalf("status %d delay %s error %v; want status %d delay %s", status, retryAfter, err, tc.status, tc.want)
			}
		})
	}
}

func TestWebhookRetryAfterDateUsesResponseClock(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", now.Add(time.Minute).Format(http.TimeFormat))
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	clockCalls := 0
	sender.now = func() time.Time {
		clockCalls++
		if clockCalls == 1 { // Signing clock, before the request.
			return now
		}
		return now.Add(30 * time.Second)
	}
	_, retryAfter, err := sender.Send(context.Background(), "sub_1", callback, webhookTestSecret(1, 32), "", "evt_1", []byte(`{"eventId":"evt_1"}`))
	if err != nil || retryAfter != 30*time.Second {
		t.Fatalf("delay %s error %v, want remaining 30s from response receipt", retryAfter, err)
	}
}

func retryAfterWorkerPending(t *testing.T, callback string) (*eventFixture, store.EventSubscription) {
	t.Helper()
	f := &eventFixture{now: time.Now().UTC().Truncate(time.Second)}
	var err error
	f.store, err = store.Open(filepath.Join(t.TempDir(), "retry-after.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	f.store.SetClock(func() time.Time { return f.now })
	if err := f.store.InitEvents(); err != nil {
		t.Fatal(err)
	}
	if err := f.store.PutAgent(t.Context(), identity.Agent{Name: "dots", NodeID: "node-backend", JoinedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	f.oauth, err = NewOAuth(f.store.DB(), func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	if err := f.oauth.ConfigureEvents(eventResource, []string{"dots"}); err != nil {
		t.Fatal(err)
	}
	_, principal := f.login(t, "dots")
	sub, err := f.store.PutEventSubscription(t.Context(), store.EventSubscription{
		ID: "retry-sub", Principal: principal.ID, Mailbox: "dots", Name: store.EventRequestQueued,
		URL: callback, Secret: webhookTestSecret(1, 32), ExpiresAt: f.now.Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Enqueue(t.Context(), envelope.Request{From: "sender", To: "dots", TraceID: "trace", Chain: []string{"sender", "dots"}, Kind: envelope.KindAsk, Body: "private fixture"}, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	return f, sub
}

func TestEventWorkerRetryAfterPersistsAcrossRestart(t *testing.T) {
	var calls atomic.Int32
	ids := make(chan string, 2)
	sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
		ids <- r.Header.Get("webhook-id")
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	f, sub := retryAfterWorkerPending(t, callback)
	sender.now = func() time.Time { return f.now }
	if err := NewEventDeliveryWorker(f.store, f.oauth, sender).DeliverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	var state string
	var available int64
	if err := f.store.DB().QueryRow(`SELECT state,available_at FROM event_deliveries WHERE subscription_id=?`, sub.ID).Scan(&state, &available); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || available != f.now.Add(time.Minute).UnixMilli() {
		t.Fatalf("state %q available_at %d, want pending at %d (Retry-After 60)", state, available, f.now.Add(time.Minute).UnixMilli())
	}
	path := f.store.Path()
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.store, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f.store.SetClock(func() time.Time { return f.now })
	f.oauth, err = NewOAuth(f.store.DB(), func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	if err := f.oauth.ConfigureEvents(eventResource, []string{"dots"}); err != nil {
		t.Fatal(err)
	}
	worker := NewEventDeliveryWorker(f.store, f.oauth, sender)
	f.now = f.now.Add(59 * time.Second)
	if err := worker.DeliverPending(t.Context()); err != nil || calls.Load() != 1 {
		t.Fatalf("retried before persisted Retry-After: calls %d error %v", calls.Load(), err)
	}
	f.now = f.now.Add(time.Second)
	if err := worker.DeliverPending(t.Context()); err != nil || calls.Load() != 2 {
		t.Fatalf("did not retry at persisted Retry-After: calls %d error %v", calls.Load(), err)
	}
	if first, second := <-ids, <-ids; first != second {
		t.Fatalf("retry changed event ID: %q != %q", first, second)
	}
	if err := f.store.DB().QueryRow(`SELECT state FROM event_deliveries WHERE subscription_id=?`, sub.ID).Scan(&state); err != nil || state != "delivered" {
		t.Fatalf("completion state %q error %v", state, err)
	}
}

func TestEventWorkerRetryAfterPreservesDeliveryBounds(t *testing.T) {
	for _, tc := range []struct {
		name, header, state string
		status              int
		priorAttempts       int
		advance, delay      time.Duration
		subscriptionExpiry  time.Duration
	}{
		{name: "rate_limited_seconds", status: 429, header: "60", state: "pending", delay: time.Minute},
		{name: "request_timeout_http_date", status: 408, header: "date", state: "pending", delay: time.Minute},
		{name: "server_error", status: 500, header: "60", state: "pending", delay: time.Minute},
		{name: "unavailable_http_date", status: 503, header: "date", state: "pending", delay: time.Minute},
		{name: "minimum_exponential_delay", status: 429, header: "1", state: "pending", delay: 2 * time.Second},
		{name: "later_exponential_delay", status: 429, header: "1", priorAttempts: 3, state: "pending", delay: 16 * time.Second},
		{name: "malformed_fallback", status: 429, header: "invalid", state: "pending", delay: 2 * time.Second},
		{name: "fractional_fallback", status: 503, header: "1.5", state: "pending", delay: 2 * time.Second},
		{name: "past_date_fallback", status: 408, header: "past", state: "pending", delay: 2 * time.Second},
		{name: "integer_overflow_fallback", status: 429, header: "18446744073709551616", state: "pending", delay: 2 * time.Second},
		{name: "hour_clamp", status: 429, header: "7200", state: "pending", delay: time.Hour},
		{name: "far_future_date_clamp", status: 503, header: "far_future", state: "pending", delay: time.Hour},
		{name: "event_horizon", status: 503, header: "7200", advance: store.EventRetention - 30*time.Minute, state: "failed", delay: time.Hour},
		{name: "subscription_expiry", status: 429, header: "7200", subscriptionExpiry: time.Minute, state: "failed", delay: time.Hour},
		{name: "maximum_attempts", status: 429, header: "60", priorAttempts: store.EventMaxAttempts - 1, state: "failed", delay: 256 * time.Second},
		{name: "gone_unsubscribes", status: 410, header: "60", state: "cancelled"},
		{name: "too_large_is_permanent", status: 413, header: "60", state: "failed"},
		{name: "client_error_is_permanent", status: 400, header: "60", state: "failed"},
		{name: "success_is_acknowledged", status: 204, header: "60", state: "delivered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			header := tc.header
			sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Retry-After", header)
				w.WriteHeader(tc.status)
			})
			f, sub := retryAfterWorkerPending(t, callback)
			occurredAt := f.now
			f.now = f.now.Add(tc.advance)
			sender.now = func() time.Time { return f.now }
			switch header {
			case "date":
				header = f.now.Add(time.Minute).Format(http.TimeFormat)
			case "past":
				header = f.now.Add(-time.Minute).Format(http.TimeFormat)
			case "far_future":
				header = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).Format(http.TimeFormat)
			}
			if tc.priorAttempts != 0 {
				if _, err := f.store.DB().Exec(`UPDATE event_deliveries SET attempts=? WHERE subscription_id=?`, tc.priorAttempts, sub.ID); err != nil {
					t.Fatal(err)
				}
			}
			if tc.subscriptionExpiry != 0 {
				if _, err := f.store.DB().Exec(`UPDATE event_subscriptions SET expires_at=? WHERE id=?`, f.now.Add(tc.subscriptionExpiry).UnixMilli(), sub.ID); err != nil {
					t.Fatal(err)
				}
			}
			worker := NewEventDeliveryWorker(f.store, f.oauth, sender)
			if err := worker.DeliverPending(t.Context()); err != nil {
				t.Fatal(err)
			}
			var state string
			var attempts int
			var available, expires int64
			if err := f.store.DB().QueryRow(`SELECT d.state,d.attempts,d.available_at,e.expires_at FROM event_deliveries d JOIN event_outbox e ON e.id=d.event_id WHERE d.subscription_id=?`, sub.ID).Scan(&state, &attempts, &available, &expires); err != nil {
				t.Fatal(err)
			}
			if state != tc.state || attempts != tc.priorAttempts+1 || available != f.now.Add(tc.delay).UnixMilli() || expires != occurredAt.Add(store.EventRetention).UnixMilli() {
				t.Fatalf("state=%s attempts=%d delay=%s horizon=%s; want state=%s attempts=%d delay=%s horizon=%s", state, attempts, time.UnixMilli(available).Sub(f.now), time.UnixMilli(expires).Sub(occurredAt), tc.state, tc.priorAttempts+1, tc.delay, store.EventRetention)
			}
			if err := worker.DeliverPending(t.Context()); err != nil || calls.Load() != 1 {
				t.Fatalf("delivery retried immediately: calls %d error %v", calls.Load(), err)
			}
		})
	}
}
