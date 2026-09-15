package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/pascalgross/hostseal/internal/auth"
	"github.com/pascalgross/hostseal/internal/buildinfo"
	"github.com/pascalgross/hostseal/internal/notify"
	"github.com/pascalgross/hostseal/internal/store"
)

// MaxTenantRequestBytes bounds a tenant-administration request body.
//
// A tenant is four short strings. This is generous by three orders of magnitude and exists so the body
// is bounded before it is in memory, like every other body this server reads.
const MaxTenantRequestBytes = 16 << 10

// slugPattern is the shape a tenant's handle may take.
//
// Lower-case letters, digits and hyphens, starting with a letter or digit. It appears in URLs, in log
// lines and in support tickets, and it is chosen by whoever runs the installation rather than by a
// customer — so the constraint costs nothing and saves an argument about whether a tenant may be called
// "../admin".
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// tenantRequest is the body of POST and PATCH on /api/v1/tenants.
//
// The pointer fields are what makes PATCH a patch: a field that was not sent is nil and is left alone,
// where a field sent as "" is an explicit instruction to clear it. Without the distinction, an
// administrator changing an approval mode would silently erase a webhook they never mentioned.
type tenantRequest struct {
	// Slug is the short stable handle. Required on create, immutable afterwards.
	Slug string `json:"slug,omitempty"`

	// DisplayName is what the tenant is called in the interface.
	DisplayName *string `json:"displayName,omitempty"`

	// ApprovalMode is how this tenant releases a destructive job.
	ApprovalMode *string `json:"approvalMode,omitempty"`

	// WebhookURL is where this tenant's events are posted.
	WebhookURL *string `json:"webhookUrl,omitempty"`

	// HostLimit is how many hosts may be enrolled, or null for no limit.
	HostLimit nullableInt `json:"hostLimit,omitempty"`

	// Suspended is whether the control plane refuses this fleet's agent requests.
	Suspended *bool `json:"suspended,omitempty"`
}

// nullableInt is a number that may be sent, sent as null, or left out entirely.
//
// Three states, where a `*int` has two, and the third one is the reason this type exists: `hostLimit`
// uses null to mean *no limit*, so a plain pointer could not tell "remove this fleet's limit" from "I
// did not mention the limit". A PATCH that changed only an approval mode would have silently removed
// the limit, which is a billing failure that looks like nothing at all.
//
// UnmarshalJSON runs only for a key that is present, which is what makes Set trustworthy.
type nullableInt struct {
	// Set reports that the field appeared in the request body, whatever its value.
	Set bool

	// Value is the number, or nil for an explicit null.
	Value *int
}

// UnmarshalJSON records that the field was present, and what it held.
func (n *nullableInt) UnmarshalJSON(data []byte) error {
	n.Set = true
	if string(data) == "null" {
		n.Value = nil
		return nil
	}
	var value int
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	n.Value = &value
	return nil
}

// tenantView is what the API renders for a tenant.
type tenantView struct {
	// ID is the identifier every scoped row carries.
	ID string `json:"id"`

	// Slug is the short stable handle.
	Slug string `json:"slug"`

	// DisplayName is what the tenant is called in the interface.
	DisplayName string `json:"displayName"`

	// CreatedAt is when the tenant was created.
	CreatedAt time.Time `json:"createdAt"`

	// ApprovalMode is how this tenant releases a destructive job.
	ApprovalMode string `json:"approvalMode"`

	// WebhookURL is where this tenant's events go, empty for nowhere.
	WebhookURL string `json:"webhookUrl"`

	// HostLimit is how many hosts may be enrolled, null for no limit.
	HostLimit *int `json:"hostLimit"`

	// Suspended is whether the control plane refuses this fleet's agent requests.
	Suspended bool `json:"suspended"`
}

// toTenantView renders a stored tenant.
func toTenantView(t store.Tenant) tenantView {
	return tenantView{
		ID:           string(t.ID),
		Slug:         t.Slug,
		DisplayName:  t.DisplayName,
		CreatedAt:    t.CreatedAt,
		ApprovalMode: string(t.ApprovalMode),
		WebhookURL:   t.WebhookURL,
		HostLimit:    t.HostLimit,
		Suspended:    t.Suspended,
	}
}

// handleListTenants returns every tenant on this installation.
func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	tenants, err := s.cfg.Store.ListTenants(r.Context())
	if err != nil {
		slog.Error("could not list tenants", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tenant list")
		return
	}
	views := make([]tenantView, 0, len(tenants))
	for _, t := range tenants {
		views = append(views, toTenantView(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": views})
}

// handleGetTenant returns one tenant.
func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	tenant, err := s.cfg.Store.GetTenant(r.Context(), store.TenantID(r.PathValue("id")))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_tenant", "no such tenant")
		return
	case err != nil:
		slog.Error("could not read a tenant", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tenant")
		return
	}
	writeJSON(w, http.StatusOK, toTenantView(tenant))
}

// handleCreateTenant provisions a new fleet.
//
// This is the operation a hosting provider automates, and it deliberately does not also mint an
// operator credential. Issuing a fleet's credential is the identity provider's job — auth.Provider is
// the seam for that — and a tenant API that handed out tokens would make the platform administrator
// able to authenticate as any customer, which is the exact separation the platform role exists to keep.
func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request, who auth.Identity) {
	var req tenantRequest
	if err := decodeJSON(w, r, MaxTenantRequestBytes, &req); err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		return
	}
	if !slugPattern.MatchString(req.Slug) {
		writeError(w, http.StatusBadRequest, "malformed",
			"a tenant needs a slug of lower-case letters, digits and hyphens, starting with a letter "+
				"or a digit: it appears in URLs and in log lines")
		return
	}

	mode := store.ApprovalNone
	if req.ApprovalMode != nil {
		mode = store.ApprovalMode(*req.ApprovalMode)
		if !mode.Valid() {
			writeError(w, http.StatusBadRequest, "malformed",
				`approvalMode is one of "none", "self" or "second_person"; see docs/SECURITY.md §3`)
			return
		}
	}

	id, err := NewID()
	if err != nil {
		slog.Error("could not generate a tenant id", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not allocate a tenant id")
		return
	}

	webhook := valueOr(req.WebhookURL, "")
	if !checkWebhookURL(w, webhook) {
		return
	}

	if !checkHostLimit(w, req.HostLimit) {
		return
	}

	tenant := store.Tenant{
		ID:           store.TenantID(id),
		Slug:         req.Slug,
		DisplayName:  valueOr(req.DisplayName, req.Slug),
		CreatedAt:    time.Now().UTC(),
		ApprovalMode: mode,
		WebhookURL:   webhook,
		// Absent means no limit, which is what an installation that is not selling this wants and what
		// `hostseal-server serve` creates for its own fleet.
		HostLimit: req.HostLimit.Value,
		Suspended: req.Suspended != nil && *req.Suspended,
	}
	switch err := s.cfg.Store.CreateTenant(r.Context(), tenant); {
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "duplicate", "a tenant with this slug already exists")
		return
	case err != nil:
		slog.Error("could not create a tenant", "error", err, "slug", req.Slug)
		writeError(w, http.StatusInternalServerError, "internal", "could not create the tenant")
		return
	}

	slog.Info("tenant created",
		"tenant", tenant.ID, "slug", tenant.Slug, "approval_mode", tenant.ApprovalMode,
		"host_limit", limitForLog(tenant.HostLimit), "platform_operator", who.Principal())
	writeJSON(w, http.StatusCreated, toTenantView(tenant))
}

// handleUpdateTenant changes a tenant's name, approval mode or webhook.
//
// A changed approval mode applies to jobs created afterwards and to nothing already queued. That is the
// same rule migration 0002 wrote down for approval_required and it matters more here, because this
// setting is one an operator can edit: without it, queueing a job under the two-person rule and then
// relaxing the tenant would release work that nobody agreed to under the rule it was created with.
func (s *Server) handleUpdateTenant(w http.ResponseWriter, r *http.Request, who auth.Identity) {
	var req tenantRequest
	if err := decodeJSON(w, r, MaxTenantRequestBytes, &req); err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		return
	}

	id := store.TenantID(r.PathValue("id"))
	tenant, err := s.cfg.Store.GetTenant(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_tenant", "no such tenant")
		return
	case err != nil:
		slog.Error("could not read a tenant", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tenant")
		return
	}

	if req.Slug != "" && req.Slug != tenant.Slug {
		// Immutable, and refused rather than ignored. The slug is what logs, tickets and any external
		// system refer to this tenant by, and a silent rename would leave every one of those pointing
		// at something that no longer answers to that name.
		writeError(w, http.StatusConflict, "immutable",
			"a tenant's slug cannot be changed: it is what logs and support tickets refer to")
		return
	}
	// A patch of exactly what this request asked to change, rather than the whole row read a moment
	// ago. Writing back every field would mean two concurrent edits each restoring the other's stale
	// values — and the hosting layer sets the host limit and the suspension in two separate requests,
	// so a fleet could come out of suspension because somebody renamed it at the wrong moment.
	patch := store.TenantPatch{DisplayName: req.DisplayName, WebhookURL: req.WebhookURL}
	if req.WebhookURL != nil && !checkWebhookURL(w, *req.WebhookURL) {
		return
	}
	if req.ApprovalMode != nil {
		mode := store.ApprovalMode(*req.ApprovalMode)
		if !mode.Valid() {
			writeError(w, http.StatusBadRequest, "malformed",
				`approvalMode is one of "none", "self" or "second_person"; see docs/SECURITY.md §3`)
			return
		}
		patch.ApprovalMode = &mode
	}
	if req.HostLimit.Set {
		if !checkHostLimit(w, req.HostLimit) {
			return
		}
		// Lowering the limit below the fleet's current size is allowed and does nothing to the hosts
		// that are already there. It is not an oversight that this handler does not go and revoke the
		// excess: a setting that could take a running host away from its operator would be a lever on
		// an enrolled host, and there are none of those in this control plane. What it changes is the
		// answer the enrolment endpoint gives the next machine.
		patch.SetHostLimit = true
		patch.HostLimit = req.HostLimit.Value
	}
	patch.Suspended = req.Suspended

	tenant, err = s.cfg.Store.UpdateTenant(r.Context(), id, patch)
	if err != nil {
		slog.Error("could not update a tenant", "error", err, "tenant", id)
		writeError(w, http.StatusInternalServerError, "internal", "could not update the tenant")
		return
	}

	slog.Info("tenant updated",
		"tenant", tenant.ID, "slug", tenant.Slug, "approval_mode", tenant.ApprovalMode,
		"host_limit", limitForLog(tenant.HostLimit), "suspended", tenant.Suspended,
		"platform_operator", who.Principal())
	writeJSON(w, http.StatusOK, toTenantView(tenant))
}

// handleDeleteTenant removes a tenant and everything belonging to it.
//
// Everything means everything: hosts, certificates, enrolment tokens, jobs and results. The agents
// themselves are not told and cannot be — there is no path from this control plane to a host — so they
// keep running on their own local policy and their next request is refused as an unknown certificate.
// That is the correct end state for a customer who has left, and it is worth saying out loud that
// deleting a tenant does not uninstall anything.
func (s *Server) handleDeleteTenant(w http.ResponseWriter, r *http.Request, who auth.Identity) {
	id := store.TenantID(r.PathValue("id"))
	switch err := s.cfg.Store.DeleteTenant(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_tenant", "no such tenant")
		return
	case err != nil:
		slog.Error("could not delete a tenant", "error", err, "tenant", id)
		writeError(w, http.StatusInternalServerError, "internal", "could not delete the tenant")
		return
	}

	slog.Warn("tenant deleted", "tenant", id, "platform_operator", who.Principal())
	w.WriteHeader(http.StatusNoContent)
}

// handleWhoami tells a caller who the control plane thinks they are and which fleet they are in.
//
// The interface needs it for the same reason a shell prompt shows the hostname: an operator with access
// to two fleets, in two browser tabs, needs the page itself to say which one they are looking at before
// they queue a reboot in it.
//
// It is the one route that answers both credentials, and that is a fix rather than a convenience. It
// used to be behind requireOperator, so a platform credential got the 403 every fleet route gives it —
// which left the application able to say only that the credential it had been handed was unusable here,
// with no way to say what it was for. Somebody who pasted the wrong one of an installation's two tokens
// saw an empty console and the words "identity unknown".
//
// A platform credential still gets no tenant, because it has none. The `platform` flag is what the
// interface reads to decide which of two interfaces to render, and `tenant` is null beside it rather
// than an empty object, so a client that forgot to look at the flag fails on the field it needs rather
// than rendering a fleet called "".
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request, who auth.Identity) {
	answer := map[string]any{
		"subject":   who.Subject,
		"display":   who.Display,
		"provider":  who.Provider,
		"principal": who.Principal(),
		"platform":  who.Platform,
		"tenant":    nil,
		// The build, here rather than on /healthz. Somebody has to be able to answer "which version is
		// this installation running" — it is the first question of every upgrade and every advisory —
		// and the difference between the two routes is that this one knows who is asking. /healthz
		// answers a load balancer, which does not need the answer, and answers anybody else who can
		// reach the port, which is who the answer helps most.
		"version": buildinfo.Version,
		"commit":  buildinfo.Revision(),
	}
	if who.Platform || who.Tenant == "" {
		writeJSON(w, http.StatusOK, answer)
		return
	}

	tenant, err := s.cfg.Store.GetTenant(r.Context(), store.TenantID(who.Tenant))
	if err != nil {
		slog.Error("could not read the operator's tenant", "error", err, "tenant", who.Tenant)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tenant")
		return
	}
	answer["tenant"] = toTenantView(tenant)
	writeJSON(w, http.StatusOK, answer)
}

// handleTenantUsage reports how large a fleet is, and nothing else about it.
//
// This is the one route that lets the platform role learn something about the inside of a fleet, and
// what it learns is two integers and a timestamp. That is deliberate and it is the whole design: an
// installation run for other people has to be able to count what it is charging for, and the honest
// alternative — before this existed — was for the hosting provider to hold an operator account inside
// every customer's fleet, which is a credential that can queue jobs, read facts and revoke hosts, held
// by somebody who wanted to count to three.
//
// So the disclosure is made as small as it can be while still answering the question. No hostname, no
// group, no agent version, no fact, no job. A customer can read this endpoint's response and see that
// it could not have told anybody what their machines are called.
//
// The count itself runs through Store.In, so the row-level security policy answers it exactly as it
// answers every other read of a tenant-owned table. There is no exemption here and there must not be
// one.
func (s *Server) handleTenantUsage(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	id := store.TenantID(r.PathValue("id"))
	tenant, err := s.cfg.Store.GetTenant(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_tenant", "no such tenant")
		return
	case err != nil:
		slog.Error("could not read a tenant", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tenant")
		return
	}

	counts, err := s.cfg.Store.In(id).CountHosts(r.Context())
	if err != nil {
		slog.Error("could not count a tenant's hosts", "error", err, "tenant", id)
		writeError(w, http.StatusInternalServerError, "internal", "could not count the hosts")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": string(id),
		"slug":   tenant.Slug,
		// Every host row the fleet holds, and the subset whose certificates are still accepted. Both,
		// because a revoked host stops counting against a limit and stops being billable at the same
		// moment, and a caller reconciling an invoice needs to see that the two agree.
		"hosts":        counts.Total,
		"activeHosts":  counts.Active,
		"revokedHosts": counts.Total - counts.Active,
		"hostLimit":    tenant.HostLimit,
		"suspended":    tenant.Suspended,
		// The moment the count was taken, so that a caller storing it as the evidence behind an invoice
		// stores when it was true rather than when it was read.
		"asOf": time.Now().UTC(),
	})
}

// checkHostLimit answers the request itself when a host limit is one the schema would refuse.
//
// Refused here rather than left to the CHECK constraint, because a constraint violation arrives as a
// 500 and a negative host limit is a caller's mistake they can fix from the message. Zero is allowed
// and means what it says: a fleet that may hold no hosts, which is what a tenant looks like between
// being created and being paid for.
func checkHostLimit(w http.ResponseWriter, limit nullableInt) bool {
	if limit.Value != nil && *limit.Value < 0 {
		writeError(w, http.StatusBadRequest, "malformed",
			"hostLimit must be zero or more, or null for no limit")
		return false
	}
	return true
}

// limitForLog renders a host limit for a log line, where a nil pointer would print as an address.
func limitForLog(limit *int) any {
	if limit == nil {
		return "none"
	}
	return *limit
}

// checkWebhookURL answers the request itself when a webhook URL is one HostSeal will not post to.
//
// It returns whether the caller may continue, in the shape the handlers around it already use, so that
// both write paths refuse the same values with the same message. The empty string is how a tenant says
// it wants no webhook and is not a URL to check.
//
// The reason it is refused *here*, and not only where the delivery happens, is that an operator who
// pasted an http:// endpoint has made a mistake they can fix in the second it takes to read this, and
// discovering it later means discovering it from an event that did not arrive. The sink checks again
// anyway, for the rows written before this rule existed.
func checkWebhookURL(w http.ResponseWriter, raw string) bool {
	if raw == "" {
		return true
	}
	if err := notify.ValidateWebhookURL(raw); err != nil {
		writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return false
	}
	return true
}

// valueOr returns a pointer's value, or a fallback when it is nil.
//
// It exists because the tenant request distinguishes "not sent" from "sent empty", and writing that
// check inline four times would make the two cases look like one.
func valueOr(p *string, fallback string) string {
	if p == nil {
		return fallback
	}
	return *p
}
