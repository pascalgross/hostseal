package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/pascalgross/hostseal/internal/intent"
	"github.com/pascalgross/hostseal/internal/store"
)

// hostView is one host as the API renders it.
//
// It is a separate type from store.Host rather than the same struct with JSON tags, because the two
// change for different reasons: the stored shape follows the schema, and this follows what the UI
// needs. Coupling them means a column rename becomes a breaking API change.
type hostView struct {
	// ID is the control plane's identifier for the host.
	ID string `json:"id"`

	// Hostname is what the host calls itself. Display only; identity is the certificate.
	Hostname string `json:"hostname"`

	// Group is the fleet group, from the enrolment token.
	Group string `json:"group"`

	// AgentVersion is the build the host last reported.
	AgentVersion string `json:"agentVersion"`

	// EnrolledAt is when the host first enrolled.
	EnrolledAt time.Time `json:"enrolledAt"`

	// LastSeen is the last heartbeat, or null if the host has never been heard from.
	LastSeen *time.Time `json:"lastSeen"`

	// Online reports whether the host has been heard from recently enough to be considered up.
	Online bool `json:"online"`

	// UptimeSeconds is what the host last reported.
	UptimeSeconds int64 `json:"uptimeSeconds"`

	// ClockOffsetSeconds is the host's own measurement of its offset from the control plane.
	ClockOffsetSeconds int64 `json:"clockOffsetSeconds"`

	// ClockSkewed reports that the offset is large enough for the host to refuse privileged intents.
	//
	// It is computed here rather than left to the client, so that every client agrees on the threshold
	// and none of them has to know the number.
	ClockSkewed bool `json:"clockSkewed"`

	// Paused reports whether /etc/hostseal/paused exists on the host.
	//
	// It is a local kill switch the control plane cannot override, and there is deliberately no
	// agent.resume intent, so the UI shows it as a state rather than something to toggle.
	Paused bool `json:"paused"`

	// Revoked reports that this host's certificates are no longer accepted.
	Revoked bool `json:"revoked"`

	// FactsDigest, PolicyDigest and SignersDigest are what the host last reported.
	FactsDigest   string `json:"factsDigest"`
	PolicyDigest  string `json:"policyDigest"`
	SignersDigest string `json:"signersDigest"`

	// Facts is the last full inventory document, or null if none has been received.
	Facts json.RawMessage `json:"facts"`

	// Policy is the host's last reported effective policy, or null.
	Policy json.RawMessage `json:"policy"`

	// Signers is the host's trusted key identities, or null.
	//
	// Identities only, never the trusted-signers file: the control plane has no business holding a copy
	// of a host's trust anchor, and displaying "ops-yubikey-1 (PKCS#11)" needs no more than this.
	Signers json.RawMessage `json:"signers"`
}

// toView converts a stored host into its API representation.
func (s *Server) toView(h store.Host, now time.Time) hostView {
	view := hostView{
		ID:                 h.ID,
		Hostname:           h.Hostname,
		Group:              h.Group,
		AgentVersion:       h.AgentVersion,
		EnrolledAt:         h.EnrolledAt,
		Online:             h.Online(now, s.cfg.HeartbeatSeconds),
		UptimeSeconds:      h.UptimeSeconds,
		ClockOffsetSeconds: h.ClockOffsetSeconds,
		ClockSkewed:        h.ClockOffsetSeconds > 300 || h.ClockOffsetSeconds < -300,
		Paused:             h.Paused,
		Revoked:            h.Revoked,
		FactsDigest:        h.FactsDigest,
		PolicyDigest:       h.PolicyDigest,
		SignersDigest:      h.SignersDigest,
		Facts:              jsonOrNull(h.Facts),
		Policy:             jsonOrNull(h.Policy),
		Signers:            jsonOrNull(h.Signers),
	}
	if !h.LastSeen.IsZero() {
		seen := h.LastSeen
		view.LastSeen = &seen
	}
	return view
}

// handleListHosts returns the fleet.
func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request, who operator) {
	hosts, err := who.Store.ListHosts(r.Context())
	if err != nil {
		slog.Error("could not list hosts", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the fleet")
		return
	}

	now := time.Now()
	views := make([]hostView, 0, len(hosts))
	for _, h := range hosts {
		views = append(views, s.toView(h, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hosts":            views,
		"heartbeatSeconds": s.cfg.HeartbeatSeconds,
		"serverTime":       now.UTC(),
	})
}

// handleGetHost returns one host in full.
func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request, who operator) {
	host, err := who.Store.GetHost(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such host")
		return
	}
	if err != nil {
		slog.Error("could not read a host", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the host")
		return
	}
	writeJSON(w, http.StatusOK, s.toView(host, time.Now()))
}

// handleRevokeHost withdraws a host's certificates.
//
// It takes effect on the host's next request, because revocation is a database fingerprint check rather
// than a CRL. What it does not do is stop the host: an agent whose certificate is revoked keeps running,
// keeps applying updates from its local policy, and simply cannot talk to this control plane. That is
// the intended behaviour — a revoked host should not become an unpatched host.
func (s *Server) handleRevokeHost(w http.ResponseWriter, r *http.Request, who operator) {
	hostID := r.PathValue("id")
	err := who.Store.RevokeHost(r.Context(), hostID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such host")
		return
	}
	if err != nil {
		slog.Error("could not revoke a host", "error", err, "host", hostID)
		writeError(w, http.StatusInternalServerError, "internal", "could not revoke the host")
		return
	}
	slog.Warn("host revoked", "host", hostID, "tenant", who.Store.Tenant(), "operator", who.Principal())
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// handleDeleteHost removes a host and its history.
//
// Revocation is the ordinary answer and this is not a gentler version of it: deleting a host discards
// its facts, its jobs and its results, which is exactly what an audit would have wanted. It exists for
// the row that should not be there — an enrolment that failed halfway, a test host, a machine that has
// been decommissioned. Like revocation it releases the machine-id hash, so the machine can enrol again.
//
// It does not reach the host. Nothing in HostSeal does: a deleted host keeps running and keeps applying
// its local policy, and simply has nowhere to report. Uninstalling the agent is a separate, local act.
func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request, who operator) {
	hostID := r.PathValue("id")
	err := who.Store.DeleteHost(r.Context(), hostID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such host")
		return
	}
	if err != nil {
		slog.Error("could not delete a host", "error", err, "host", hostID)
		writeError(w, http.StatusInternalServerError, "internal", "could not delete the host")
		return
	}
	slog.Warn("host deleted", "host", hostID, "tenant", who.Store.Tenant(), "operator", who.Principal())
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// tokenView is one enrolment token as the API renders it.
//
// The token itself is absent, because only its hash was ever stored. That is worth being visible in the
// API shape rather than only in a comment: a field that could hold the secret and does not is a
// question somebody asks once.
type tokenView struct {
	// Label is what the operator called it.
	Label string `json:"label"`

	// Group is the fleet group hosts enrolled with it join.
	Group string `json:"group"`

	// CreatedAt is when it was issued.
	CreatedAt time.Time `json:"createdAt"`

	// ExpiresAt is when it stops working.
	ExpiresAt time.Time `json:"expiresAt"`

	// Consumed reports whether it has been used.
	Consumed bool `json:"consumed"`

	// ConsumedByHost is the host that used it, empty if unused.
	ConsumedByHost string `json:"consumedByHost,omitempty"`

	// Usable reports whether it can still be redeemed.
	Usable bool `json:"usable"`
}

// handleListTokens returns enrolment tokens, newest first, without their secrets.
func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, who operator) {
	tokens, err := who.Store.ListEnrollmentTokens(r.Context())
	if err != nil {
		slog.Error("could not list enrolment tokens", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tokens")
		return
	}

	now := time.Now()
	views := make([]tokenView, 0, len(tokens))
	for _, t := range tokens {
		views = append(views, tokenView{
			Label:          t.Label,
			Group:          t.Group,
			CreatedAt:      t.CreatedAt,
			ExpiresAt:      t.ExpiresAt,
			Consumed:       !t.ConsumedAt.IsZero(),
			ConsumedByHost: t.ConsumedByHost,
			Usable:         t.Usable(now),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": views})
}

// handleCreateToken issues a single-use enrolment token.
//
// The token is returned exactly once, here, and is not recoverable afterwards because only its hash is
// stored. The response says so, so that a client can tell the operator rather than leaving them to find
// out by looking for it later.
func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, who operator) {
	var req struct {
		// Label is a human-readable name for the token.
		Label string `json:"label"`

		// Group is the fleet group hosts enrolled with it join.
		Group string `json:"group"`

		// TTLSeconds overrides the server's default lifetime.
		TTLSeconds int `json:"ttlSeconds"`
	}
	if err := decodeJSON(w, r, 64<<10, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		return
	}

	ttl := s.cfg.TokenTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	token, hash, err := NewEnrollmentToken()
	if err != nil {
		slog.Error("could not generate an enrolment token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not generate a token")
		return
	}

	now := time.Now()
	record := store.EnrollmentToken{
		Hash:      hash,
		Label:     req.Label,
		Group:     req.Group,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	if err := who.Store.CreateEnrollmentToken(r.Context(), record); err != nil {
		slog.Error("could not store an enrolment token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the token")
		return
	}

	slog.Info("enrolment token created",
		"label", req.Label, "group", req.Group,
		"tenant", who.Store.Tenant(), "operator", who.Principal(),
		"expires", record.ExpiresAt.Format(time.RFC3339))

	writeJSON(w, http.StatusCreated, map[string]any{
		"token":     token,
		"label":     req.Label,
		"group":     req.Group,
		"expiresAt": record.ExpiresAt,
		"note": "This token is shown once and cannot be recovered: only its hash is stored, " +
			"so a database dump does not let its holder enrol hosts.",
	})
}

// handleCatalogue returns the complete intent catalogue this build knows.
//
// It exists so that an operator evaluating HostSeal can see the entire set of things the control plane
// is able to ask for, from the running server, without reading the source or trusting a web page. The
// claim this project makes is about that set being small and closed, so it should be checkable in one
// request.
func (s *Server) handleCatalogue(w http.ResponseWriter, _ *http.Request, _ operator) {
	type entry struct {
		// Name is the wire identifier.
		Name string `json:"name"`

		// Class is the authorisation tier.
		Class string `json:"class"`

		// Summary is one line of description.
		Summary string `json:"summary"`

		// Implemented reports whether an executor exists behind it on the agent.
		Implemented bool `json:"implemented"`

		// RequiresOfflineSignature reports whether a key from the host's trusted-signers is required.
		RequiresOfflineSignature bool `json:"requiresOfflineSignature"`
	}

	entries := make([]entry, 0, len(intent.Names()))
	for _, spec := range intent.All() {
		entries = append(entries, entry{
			Name:                     string(spec.Name),
			Class:                    string(spec.Class),
			Summary:                  spec.Summary,
			Implemented:              spec.Implemented,
			RequiresOfflineSignature: spec.Class.RequiresOfflineSignature(),
		})
	}

	refused := make([]string, 0, len(intent.Refused))
	for _, n := range intent.Refused {
		refused = append(refused, string(n))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"intents": entries,
		"refused": refused,
		"note": "This set is closed. It is a compile-time map with no registry and no configuration " +
			"that adds to it; new intents arrive only as reviewed source changes. The refused list " +
			"will never be implemented — see docs/SECURITY.md.",
	})
}
