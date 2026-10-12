package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/envelope"
)

type ownedReleaseQueueRecorder struct {
	mu     sync.Mutex
	queued []envelope.Request
}

func (q *ownedReleaseQueueRecorder) Queued(_ context.Context, req envelope.Request) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queued = append(q.queued, req)
}

func (q *ownedReleaseQueueRecorder) snapshot() []envelope.Request {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]envelope.Request(nil), q.queued...)
}

type ownedReleaseRequeueRecorder struct {
	ownedReleaseQueueRecorder
	requeued []envelope.Request
}

func (q *ownedReleaseRequeueRecorder) Requeued(_ context.Context, req envelope.Request) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.requeued = append(q.requeued, req)
}

func (q *ownedReleaseRequeueRecorder) requeueSnapshot() []envelope.Request {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]envelope.Request(nil), q.requeued...)
}

func assertOwnedReleaseWakeRequest(t *testing.T, got []envelope.Request, want envelope.Request) {
	t.Helper()
	if len(got) != 1 || got[0].ID != want.ID || got[0].To != want.To || got[0].From != want.From || got[0].TraceID != want.TraceID {
		t.Fatalf("release wake requests = %+v; want one for id=%s from=%s to=%s trace=%s", got, want.ID, want.From, want.To, want.TraceID)
	}
}

func assertOwnedReleaseHubWake(t *testing.T, request, inbox <-chan struct{}, want bool) {
	t.Helper()
	for _, waiter := range []struct {
		name string
		ch   <-chan struct{}
	}{{"request", request}, {"recipient inbox", inbox}} {
		closed := false
		select {
		case <-waiter.ch:
			closed = true
		default:
		}
		if closed != want {
			t.Fatalf("%s wake=%v, want %v", waiter.name, closed, want)
		}
	}
}

func TestOwnedReleaseHTTPRequeuesOnceWithoutAcknowledging(t *testing.T) {
	h, clock := ownedHTTPHarness(t)
	// Leave replies unread by both participants. Requeue metadata lookup must
	// not use a sender Get or a taking inbox read to construct the callback.
	targetReply := h.send(claimBackendAddrA, "muse", "target's unrelated request")
	h.answer(museAddr, targetReply, "target's unread reply")
	senderReply := h.send(grokAddr, "muse", "sender's unrelated request")
	h.answer(museAddr, senderReply, "sender's unread reply")
	sent := h.send(grokAddr, "openai-dots", "release this operation")
	base := "/v1/requests/" + sent.ID
	owner := httpOwnedClaim(t, h, claimBackendAddrA, sent.ID, "task-release", "attempt-1")
	release := claimJSON(t, map[string]any{"ownership": owner})
	recorder := &ownedReleaseRequeueRecorder{}
	h.srv.SetEvents(recorder)
	requestWake := h.srv.hub.wait(requestKey(sent.ID))
	inboxWake := h.srv.hub.wait(inboxKey("openai-dots"))
	var result struct {
		OK bool `json:"ok"`
	}
	h.do(claimBackendAddrA, http.MethodPost, base+"/release", release, http.StatusOK, &result)
	if !result.OK {
		t.Fatal("successful release did not preserve {ok:true} wire response")
	}
	assertOwnedReleaseWakeRequest(t, recorder.requeueSnapshot(), sent)
	if calls := recorder.snapshot(); len(calls) != 0 {
		t.Fatalf("release called Queued despite Requeuer support: %+v", calls)
	}
	assertOwnedReleaseHubWake(t, requestWake, inboxWake, true)
	var inspect envelope.Result
	h.do(claimBackendAddrA, http.MethodGet, base+"/inspect", "", http.StatusOK, &inspect)
	if inspect.Status != envelope.StatusQueued || inspect.Request.Body != sent.Body || inspect.Reply != nil {
		t.Fatalf("release callback took or changed work: %+v", inspect)
	}
	for _, agent := range []string{"grokbot", "openai-dots"} {
		if n := h.srv.UnseenReplies(agent); n != 1 {
			t.Fatalf("release acknowledged %s's unrelated reply: unseen=%d", agent, n)
		}
	}
	// Retrying a lost successful response is an HTTP success, not a second wake.
	requestWake = h.srv.hub.wait(requestKey(sent.ID))
	inboxWake = h.srv.hub.wait(inboxKey("openai-dots"))
	h.do(claimBackendAddrA, http.MethodPost, base+"/release", release, http.StatusOK, &result)
	if !result.OK {
		t.Fatal("release retry did not preserve {ok:true}")
	}
	assertOwnedReleaseWakeRequest(t, recorder.requeueSnapshot(), sent)
	assertOwnedReleaseHubWake(t, requestWake, inboxWake, false)
	// A different actor cannot reuse the receipt even before a fresh claim.
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrB, base+"/release", release))
	assertOwnedReleaseWakeRequest(t, recorder.requeueSnapshot(), sent)
	assertOwnedReleaseHubWake(t, requestWake, inboxWake, false)
	current := httpOwnedClaim(t, h, claimBackendAddrB, sent.ID, "task-release", "attempt-2")
	requestWake = h.srv.hub.wait(requestKey(sent.ID))
	inboxWake = h.srv.hub.wait(inboxKey("openai-dots"))
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrA, base+"/release", release))
	assertOwnedReleaseWakeRequest(t, recorder.requeueSnapshot(), sent)
	assertOwnedReleaseHubWake(t, requestWake, inboxWake, false)
	clock.advance(2 * time.Minute)
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrB, base+"/release", claimJSON(t, map[string]any{"ownership": current})))
	assertOwnedReleaseWakeRequest(t, recorder.requeueSnapshot(), sent)
	assertOwnedReleaseHubWake(t, requestWake, inboxWake, false)
}

func TestOwnedReleaseHTTPQueuedHookFallback(t *testing.T) {
	h, _ := ownedHTTPHarness(t)
	sent := h.send(grokAddr, "openai-dots", "release this operation")
	base := "/v1/requests/" + sent.ID
	owner := httpOwnedClaim(t, h, claimBackendAddrA, sent.ID, "task-release", "attempt-1")
	release := claimJSON(t, map[string]any{"ownership": owner})
	// Older listeners implementing Events alone still need a wake on release.
	recorder := &ownedReleaseQueueRecorder{}
	h.srv.SetEvents(recorder)
	h.do(claimBackendAddrA, http.MethodPost, base+"/release", release, http.StatusOK, nil)
	assertOwnedReleaseWakeRequest(t, recorder.snapshot(), sent)
	h.do(claimBackendAddrA, http.MethodPost, base+"/release", release, http.StatusOK, nil)
	assertOwnedReleaseWakeRequest(t, recorder.snapshot(), sent)
	assertClaimConflict(t, claimHTTPRequest(h, claimBackendAddrB, base+"/release", release))
	assertOwnedReleaseWakeRequest(t, recorder.snapshot(), sent)
}

func TestOwnedReleaseHTTPRetryAfterDeliveryDoesNotWakeOrRequeue(t *testing.T) {
	h, _ := ownedHTTPHarness(t)
	sent := h.send(grokAddr, "openai-dots", "release this operation")
	base := "/v1/requests/" + sent.ID
	owner := httpOwnedClaim(t, h, claimBackendAddrA, sent.ID, "task-release", "attempt-1")
	release := claimJSON(t, map[string]any{"ownership": owner})
	recorder := &ownedReleaseRequeueRecorder{}
	h.srv.SetEvents(recorder)
	h.do(claimBackendAddrA, http.MethodPost, base+"/release", release, http.StatusOK, nil)
	var delivered pollResult
	h.do(claimBackendAddrB, http.MethodGet, "/v1/poll?hold=0&replies=none", "", http.StatusOK, &delivered)
	if len(delivered.Requests) != 1 || delivered.Requests[0].ID != sent.ID {
		t.Fatalf("recipient did not receive released request: %+v", delivered)
	}
	requestWake := h.srv.hub.wait(requestKey(sent.ID))
	inboxWake := h.srv.hub.wait(inboxKey("openai-dots"))
	h.do(claimBackendAddrA, http.MethodPost, base+"/release", release, http.StatusOK, nil)
	assertOwnedReleaseWakeRequest(t, recorder.requeueSnapshot(), sent)
	assertOwnedReleaseHubWake(t, requestWake, inboxWake, false)
	_, status, err := h.st.Request(t.Context(), sent.ID)
	if err != nil || status != envelope.StatusDelivered {
		t.Fatalf("release retry reset delivered work: status=%s err=%v", status, err)
	}
}

func TestOwnedReleaseHTTPConcurrentRetriesWakeOnce(t *testing.T) {
	h, _ := ownedHTTPHarness(t)
	sent := h.send(grokAddr, "openai-dots", "release this operation")
	owner := httpOwnedClaim(t, h, claimBackendAddrA, sent.ID, "task-release", "attempt-1")
	path := "/v1/requests/" + sent.ID + "/release"
	release := claimJSON(t, map[string]any{"ownership": owner})
	recorder := &ownedReleaseRequeueRecorder{}
	h.srv.SetEvents(recorder)
	var responses [2]*httptest.ResponseRecorder
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range responses {
		wg.Go(func() {
			<-start
			responses[i] = claimHTTPRequest(h, claimBackendAddrA, path, release)
		})
	}
	close(start)
	wg.Wait()
	for _, response := range responses {
		var result struct {
			OK bool `json:"ok"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.OK {
			t.Fatalf("concurrent release: status=%d body=%s", response.Code, response.Body.String())
		}
	}
	assertOwnedReleaseWakeRequest(t, recorder.requeueSnapshot(), sent)
	if calls := recorder.snapshot(); len(calls) != 0 {
		t.Fatalf("concurrent release called fallback despite Requeuer: %+v", calls)
	}
}
