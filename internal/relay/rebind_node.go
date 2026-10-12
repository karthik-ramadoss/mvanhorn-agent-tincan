package relay

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/mvanhorn/agent-tincan/internal/identity"
)

func (s *Server) handleRebindNode(w http.ResponseWriter, r *http.Request) {
	if !isLocalAdmin(r.Context()) {
		writeErr(w, http.StatusForbidden, identity.ErrNotAdmin)
		return
	}
	var in struct {
		Name        string `json:"name"`
		ExpectedOld string `json:"expected_old_node_id"`
		StableID    string `json:"stable_id"`
		IP          string `json:"ip"`
		NodeName    string `json:"node_name"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeErr(w, http.StatusBadRequest, errors.New("rebind requires one JSON object"))
		return
	}
	a, err := s.dir.RebindNode(r.Context(), s.remote(r), in.Name, in.ExpectedOld, in.StableID, in.IP, in.NodeName)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, identity.ErrEnrollmentConflict) || errors.Is(err, identity.ErrPendingInvite) {
			code = http.StatusConflict
		}
		writeErr(w, code, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "rebound", "name": a.Name, "node_id": a.NodeID, "node_name": a.NodeName})
}
