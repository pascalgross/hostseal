package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/pascalgross/hostseal/internal/intent"
	"github.com/pascalgross/hostseal/internal/provision"
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

	// Bootstrap names the provisioning template this token may request at enrolment, empty for none.
	Bootstrap string `json:"bootstrap,omitempty"`
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
			Bootstrap:      t.Bootstrap,
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

		// Bootstrap names the provisioning template this token may request at enrolment.
		//
		// Optional, and empty means this token authorises no bootstrap at all: the template a host
		// applies is decided when the token is minted, by an authenticated operator, not chosen later
		// by whoever holds the token.
		Bootstrap string `json:"bootstrap"`
	}
	if err := decodeJSON(w, r, 64<<10, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		return
	}

	ttl := s.cfg.TokenTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	if !s.checkBootstrapIsIssuable(w, r, who, req.Bootstrap) {
		return
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
		Bootstrap: req.Bootstrap,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	if err := who.Store.CreateEnrollmentToken(r.Context(), record); err != nil {
		slog.Error("could not store an enrolment token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the token")
		return
	}

	slog.Info("enrolment token created",
		"label", req.Label, "group", req.Group, "bootstrap", req.Bootstrap,
		"tenant", who.Store.Tenant(), "operator", who.Principal(),
		"expires", record.ExpiresAt.Format(time.RFC3339))

	writeJSON(w, http.StatusCreated, map[string]any{
		"token":     token,
		"label":     req.Label,
		"group":     req.Group,
		"bootstrap": req.Bootstrap,
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

// checkBootstrapIsIssuable reports whether a token may name this template, answering the caller if not.
//
// The template must exist now and its latest version must be signed. Checking at mint time is operator
// protection rather than security — enrolment checks again, against the host's own trusted-signers,
// which is where the decision actually lives — but a token that names a template no enrolment can be
// issued would fail a machine in a datacentre instead of a person at a keyboard, which is the expensive
// place to find out.
//
// Shared by the two places that mint a token, and shared deliberately: the render endpoint mints one
// too, and a check that lived in only one of them would be a check the other silently skipped.
func (s *Server) checkBootstrapIsIssuable(w http.ResponseWriter, r *http.Request,
	who operator, name string) bool {

	if name == "" {
		return true
	}
	if !s.templateIsLive(w, r, who, name) {
		// An archived template is not issuable, so a token naming one is a token that will be refused
		// at the enrolment it was minted for — and refused on the machine, at the worst moment to find
		// out. Checked here as well as there, because a refusal an operator meets while minting is one
		// they can act on.
		return false
	}

	record, err := who.Store.GetTemplateVersion(r.Context(), name, 0)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found",
			"no template named "+name+" exists in this fleet")
		return false
	case err != nil:
		slog.Error("could not read a template for a token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the template")
		return false
	case !record.Signed():
		writeError(w, http.StatusConflict, "unsigned_template",
			"the latest version of "+name+" is not signed, so no enrolment could be issued it. "+
				"Sign it with `hostseal sign-template` and store the signed version first.")
		return false
	}

	body, err := s.cfg.TemplateKey.Open(record.BodySealed)
	if err != nil {
		slog.Error("could not decrypt a template to check it for the reserved placeholder",
			"template", record.Name, "version", record.Version, "error", err)
		writeError(w, http.StatusInternalServerError, "sealed",
			"the stored template cannot be decrypted; the control plane's template key does not match "+
				"this database. See docs/INSTALL.md on backing the key up beside the CA.")
		return false
	}
	return bootstrapDoesNotMintItsOwnToken(w, name, string(body))
}

// bootstrapDoesNotMintItsOwnToken refuses a bootstrap body that substitutes the reserved placeholder.
//
// A bootstrap is handed to a host verbatim — the offline signature covers those exact bytes, so there
// is nothing on that path that could render it — and {{enrollmentToken}} is minted by the *render*
// endpoint, which a bootstrap never goes through. So a body carrying it reaches cloud-init with the
// braces still there and writes the literal string into the machine's configuration, where it enrols
// nothing. There is no reading of that body under which it works.
//
// Only that one name, and the narrowness is the point. Every other brace pair in a verbatim body is
// ambiguous and usually correct: cloud-init resolves its own `## template: jinja` documents on the
// machine, and a write_files payload shipping a Go, Helm or consul-template config is *meant* to reach
// disk with its braces intact. Refusing those would block the templates verbatim delivery exists to
// carry — and because the body is signed by a key this control plane does not hold, an operator could
// not edit their way past the refusal without re-signing offline. What a broader check would catch
// instead is already visible: every save and every read reports the template's placeholders.
func bootstrapDoesNotMintItsOwnToken(w http.ResponseWriter, name, body string) bool {
	if !slices.Contains(provision.Placeholders(body), provision.TokenPlaceholder) {
		return true
	}
	writeError(w, http.StatusConflict, "unrendered_template",
		"the latest version of "+name+" substitutes {{"+provision.TokenPlaceholder+"}}, and a "+
			"bootstrap template is handed to a host verbatim: the offline signature covers those exact "+
			"bytes, so nothing renders it on the way and the braces would reach cloud-init intact. That "+
			"placeholder is minted by the render endpoint, which a bootstrap never goes through. Store "+
			"a version without it, or use this template through the render endpoint instead.")
	return false
}
