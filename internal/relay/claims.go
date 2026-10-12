package relay

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"

	"github.com/mvanhorn/agent-tincan/internal/envelope"
	"github.com/mvanhorn/agent-tincan/internal/store"
)

type authenticatedActorKey struct{}
type authenticatedOwnershipKey struct{}
type authenticatedActor struct {
	ID, Name    string
	ServiceRole bool
}

func (s *Server) operationOwner(w http.ResponseWriter, r *http.Request, name string, raw []byte) bool {
	var in struct {
		Ownership *envelope.ClaimOwnership `json:"ownership"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return false
	}
	if in.Ownership == nil {
		required := slices.Contains(s.cfg.RequireClaimOwnership, name)
		if req, _, err := s.store.Request(r.Context(), r.PathValue("id")); err == nil && req.Ownership != nil {
			required = true
		}
		if required {
			writeErr(w, http.StatusConflict, store.ErrClaimConflict)
			return false
		}
		return true
	}
	a, _ := r.Context().Value(authenticatedActorKey{}).(authenticatedActor)
	in.Ownership.ActorID = a.ID
	if !store.ValidClaimOwner(*in.Ownership, true) {
		writeErr(w, http.StatusConflict, store.ErrClaimConflict)
		return false
	}
	ctx := store.WithClaimOwner(r.Context(), *in.Ownership)
	ctx = context.WithValue(ctx, authenticatedOwnershipKey{}, true)
	*r = *r.WithContext(ctx)
	return true
}

func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	name := s.agent(w, r)
	if name == "" {
		return
	}
	res, err := s.store.Inspect(r.Context(), r.PathValue("id"), name)
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// The explicit alias always takes the non-delivering poll branch and never
// acknowledges replies, even if a caller supplies conflicting query options.
func (s *Server) handlePeek(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("peek", "1")
	q.Set("replies", "none")
	q.Set("hold", "0")
	r.URL.RawQuery = q.Encode()
	s.handlePoll(w, r)
}

func (s *Server) handleClaimRelease(w http.ResponseWriter, r *http.Request) {
	name := s.agent(w, r)
	if name == "" {
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	if !s.operationOwner(w, r, name, raw) {
		return
	}
	var in struct {
		Ownership *envelope.ClaimOwnership `json:"ownership"`
	}
	if err = json.Unmarshal(raw, &in); err != nil || in.Ownership == nil {
		writeErr(w, http.StatusConflict, store.ErrClaimConflict)
		return
	}
	a, _ := r.Context().Value(authenticatedActorKey{}).(authenticatedActor)
	in.Ownership.ActorID = a.ID
	err = s.store.ReleaseOwned(r.Context(), r.PathValue("id"), name, *in.Ownership)
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	s.hub.notify(requestKey(r.PathValue("id")))
	s.hub.notify(inboxKey(name))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
