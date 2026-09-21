package server

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/pascalgross/hostseal/internal/provision"
	"github.com/pascalgross/hostseal/internal/signing"
	"github.com/pascalgross/hostseal/internal/store"
)

// templateNamePattern is the only shape a template name may take.
//
// A name is typed by an operator on a command line — `hostseal enroll --bootstrap standard-server` —
// and recorded in a host's permanent bootstrap record, so it is kept to the characters that survive
// both without quoting. An allowlist rather than a denylist, for the same reason job ids are.
var templateNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// templateNameShape describes the accepted shape, for error messages that say what to do instead.
const templateNameShape = "lower-case letters, digits and hyphens, starting with a letter or digit, " +
	"at most 64 characters"

// MaxTemplateRequestBytes bounds a template-save request body.
//
// The body itself is bounded to provision.MaxBodyBytes; this leaves room for the JSON encoding and the
// signature fields around it, and exists so the request is bounded before it is in memory.
const MaxTemplateRequestBytes = 256 << 10

// createVersionAttempts is how many times a save retries a version-number collision.
//
// Two operators saving the same template concurrently can compute the same next version, and the
// primary key then refuses the second insert as ErrConflict. The retry re-computes against the
// committed row, so the second saver gets the next number rather than an error — nothing is ever
// overwritten either way, which is the property that matters.
const createVersionAttempts = 3

// templateRequest is the body of POST /api/v1/templates.
type templateRequest struct {
	// Name is the template's identifier, shared by all its versions.
	Name string `json:"name"`

	// Body is the cloud-init user-data, plaintext here and sealed before it reaches the store.
	Body string `json:"body"`

	// Signature is a detached signature over the canonical {name, body} payload, base64, from
	// `hostseal sign-template`. Optional: an unsigned version can be rendered and never issued at
	// enrolment.
	Signature string `json:"signature,omitempty"`

	// SignerKeyID names the key that signed it.
	SignerKeyID string `json:"signerKeyId,omitempty"`

	// SignerAlgorithm is "ed25519" or "ecdsa-p256".
	SignerAlgorithm string `json:"signerAlgorithm,omitempty"`
}

// templateSummaryView is one template as the listing renders it.
type templateSummaryView struct {
	// Name is the template's identifier.
	Name string `json:"name"`

	// LatestVersion is the highest stored version.
	LatestVersion int `json:"latestVersion"`

	// CreatedAt is when the latest version was stored.
	CreatedAt time.Time `json:"createdAt"`

	// CreatedBy is who stored the latest version.
	CreatedBy string `json:"createdBy"`

	// Signed reports whether the latest version can be issued to an enrolling host at all.
	Signed bool `json:"signed"`

	// Archived reports whether the name has been withdrawn from use.
	Archived bool `json:"archived"`

	// ArchivedAt is when it was withdrawn, absent while it is live.
	ArchivedAt *time.Time `json:"archivedAt,omitempty"`

	// ArchivedBy is the operator who withdrew it, absent while it is live.
	ArchivedBy string `json:"archivedBy,omitempty"`
}

// templateView is one template version in full, body included.
type templateView struct {
	// Name is the template's identifier.
	Name string `json:"name"`

	// Version is this revision's number.
	Version int `json:"version"`

	// Body is the plaintext user-data, decrypted for this response only.
	Body string `json:"body"`

	// Signed reports whether this version carries an offline signature.
	Signed bool `json:"signed"`

	// SignerKeyID names the key that signed it, empty when unsigned.
	SignerKeyID string `json:"signerKeyId,omitempty"`

	// CreatedAt is when this version was stored.
	CreatedAt time.Time `json:"createdAt"`

	// CreatedBy is who stored it.
	CreatedBy string `json:"createdBy"`

	// Placeholders are the parameter names the body substitutes, so a client can build the render
	// form without parsing cloud-init itself.
	Placeholders []string `json:"placeholders"`

	// Warnings are the secret shapes found in the body, consequence spelled out. Warnings, never
	// refusals — see internal/provision.
	Warnings []string `json:"warnings"`

	// Archived reports whether the name has been withdrawn from use.
	//
	// On the version as well as on the listing, because this is the response behind the pane an
	// operator reads a body in: a withdrawn template is still readable there — that is the whole
	// point of archiving rather than deleting — and the reader has to be told which of the two they
	// are looking at before they render it and find out.
	Archived bool `json:"archived"`

	// ArchivedAt is when it was withdrawn, absent while it is live.
	ArchivedAt *time.Time `json:"archivedAt,omitempty"`

	// ArchivedBy is the operator who withdrew it, absent while it is live.
	ArchivedBy string `json:"archivedBy,omitempty"`
}

// archivedTemplateMessage explains a refusal caused by a withdrawn template name.
//
// One sentence in one place, because four requests refuse for this reason — a save, a render, minting a
// token that names it, and archiving it twice — and an operator who meets two of them should not have to
// work out that they are the same state. The enrolment path words its own, because the reader there is
// a machine's operator watching an enrolment fail rather than somebody looking at this page.
func archivedTemplateMessage(name string) string {
	return "the template " + name + " has been archived, so it is no longer issued, rendered or " +
		"extended. Every stored version stays readable, and restoring the template puts it back into " +
		"use unchanged."
}

// handleListTemplates returns one summary per template, newest first.
//
// Archived names are left out unless `?include=archived` asks for them. Hidden by default because
// that is what retiring a template was for; listable on request because a name nobody can list is a
// name nobody can restore, and a listing that could not show the retired ones would make archiving
// the deletion it deliberately is not.
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request, who operator) {
	includeArchived := false
	switch r.URL.Query().Get("include") {
	case "":
	case "archived":
		includeArchived = true
	default:
		writeError(w, http.StatusBadRequest, "malformed",
			"the only supported value for include is `archived`")
		return
	}

	summaries, err := who.Store.ListTemplates(r.Context(), includeArchived)
	if err != nil {
		slog.Error("could not list templates", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the templates")
		return
	}
	views := make([]templateSummaryView, 0, len(summaries))
	for _, t := range summaries {
		view := templateSummaryView{
			Name:          t.Name,
			LatestVersion: t.LatestVersion,
			CreatedAt:     t.CreatedAt,
			CreatedBy:     t.CreatedBy,
			Signed:        t.Signed,
			Archived:      t.Archived,
			ArchivedBy:    t.ArchivedBy,
		}
		if t.Archived {
			at := t.ArchivedAt
			view.ArchivedAt = &at
		}
		views = append(views, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": views})
}

// handleCreateTemplate stores the next version of a template.
//
// Every save is a new version; there is no update path, because the Tier 2 bootstrap record on a host
// names a version and must resolve to the bytes that actually ran. Secret shapes in the body warn and
// never block — see internal/provision for why a refusal here would train operators to route around
// the one control that should be read.
func (s *Server) handleCreateTemplate(w http.ResponseWriter, r *http.Request, who operator) {
	var req templateRequest
	if err := decodeJSON(w, r, MaxTemplateRequestBytes, &req); err != nil {
		writeDecodeError(w, err, "this endpoint stores one template version, and the body holds more "+
			"than one JSON value. Nothing was stored; send them as separate requests.")
		return
	}

	if !templateNamePattern.MatchString(req.Name) {
		writeError(w, http.StatusBadRequest, "malformed",
			"a template name is "+templateNameShape+"; it is typed on an enrolment command line and "+
				"recorded permanently on hosts")
		return
	}
	if req.Body == "" {
		writeError(w, http.StatusBadRequest, "malformed", "a template body is required")
		return
	}
	if len(req.Body) > provision.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large",
			"the template body exceeds "+strconv.Itoa(provision.MaxBodyBytes)+" bytes; cloud "+
				"providers cap user-data well below that, so a body this size would not boot anyway")
		return
	}
	if err := validateTemplateSignature(req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if !s.templateIsLive(w, r, who, req.Name) {
		// Refused rather than silently reviving the name. An operator typing a name that was retired
		// last quarter is either continuing work somebody deliberately stopped or has picked a name
		// that is no longer free; both are worth one sentence before a v9 appears under it.
		return
	}

	sealed, err := s.cfg.TemplateKey.Seal([]byte(req.Body))
	if err != nil {
		slog.Error("could not seal a template body", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not encrypt the template")
		return
	}

	record := store.TemplateVersion{
		Name:            req.Name,
		BodySealed:      sealed,
		Signature:       req.Signature,
		SignerKeyID:     req.SignerKeyID,
		SignerAlgorithm: req.SignerAlgorithm,
		CreatedAt:       time.Now().UTC(),
		CreatedBy:       who.Principal(),
	}
	var version int
	for attempt := 0; ; attempt++ {
		version, err = who.Store.CreateTemplateVersion(r.Context(), record)
		if !errors.Is(err, store.ErrConflict) || attempt+1 >= createVersionAttempts {
			break
		}
	}
	if err != nil {
		slog.Error("could not store a template version", "error", err, "template", req.Name)
		writeError(w, http.StatusInternalServerError, "internal", "could not store the template")
		return
	}

	// The name and the author, never the body: template bodies carry the things the warnings below
	// are about, and a log line lives in more places than the sealed column does.
	slog.Info("template version stored",
		"template", req.Name, "version", version, "tenant", who.Store.Tenant(),
		"operator", who.Principal(), "signed", record.Signed(), "signer", req.SignerKeyID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"name":         req.Name,
		"version":      version,
		"signed":       record.Signed(),
		"placeholders": provision.Placeholders(req.Body),
		"warnings":     warningsOrEmpty(provision.Warnings(req.Body)),
	})
}

// validateTemplateSignature checks the optional signature triple on a save.
//
// All three fields or none: a signature without its key id would verify on a host and then be recorded
// as authorised by nobody, and a key id without a signature is a claim with nothing behind it. The
// signature itself is not verified here — it verifies against a key in some host's trusted-signers,
// which this control plane deliberately does not hold a copy of.
func validateTemplateSignature(req templateRequest) error {
	signedFields := 0
	for _, field := range []string{req.Signature, req.SignerKeyID, req.SignerAlgorithm} {
		if field != "" {
			signedFields++
		}
	}
	switch signedFields {
	case 0:
		return nil
	case 3:
		if !signing.Algorithm(req.SignerAlgorithm).Valid() {
			return errors.New("signerAlgorithm must be ed25519 or ecdsa-p256")
		}
		if _, err := base64.StdEncoding.DecodeString(req.Signature); err != nil {
			return errors.New("the signature is not valid base64")
		}
		return nil
	default:
		return errors.New("a signed template carries signature, signerKeyId and signerAlgorithm " +
			"together; use `hostseal sign-template`, which produces all three")
	}
}

// handleGetTemplate returns one version of a template in full, latest unless ?version= names one.
//
// The response is marked non-cacheable: a body is where operators put the things the warnings exist
// for, and a browser cache is one more place for them to live.
func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request, who operator) {
	version := 0
	if raw := r.URL.Query().Get("version"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "malformed", "version must be a positive whole number")
			return
		}
		version = n
	}

	record, err := who.Store.GetTemplateVersion(r.Context(), r.PathValue("name"), version)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such template")
		return
	}
	if err != nil {
		slog.Error("could not read a template", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the template")
		return
	}

	body, err := s.cfg.TemplateKey.Open(record.BodySealed)
	if err != nil {
		// The one way this happens outside a bug is a database restored without the key beside the CA.
		// Saying so is the difference between an operator fixing their restore and filing "templates
		// are corrupt".
		slog.Error("could not decrypt a stored template; the sealing key does not match the database",
			"template", record.Name, "version", record.Version, "error", err)
		writeError(w, http.StatusInternalServerError, "sealed",
			"the stored template cannot be decrypted; the control plane's template key does not match "+
				"this database. See docs/INSTALL.md on backing the key up beside the CA.")
		return
	}

	// Read, never refused: a version of an archived template is exactly what somebody resolving a
	// host's bootstrap record needs, and withholding it would be the deletion this whole design is
	// avoiding. The state is reported instead, so the pane can say so.
	archival, err := who.Store.GetTemplateArchival(r.Context(), record.Name)
	if err != nil {
		slog.Error("could not read a template's archival", "error", err, "template", record.Name)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the template")
		return
	}

	view := templateView{
		Name:         record.Name,
		Version:      record.Version,
		Body:         string(body),
		Signed:       record.Signed(),
		SignerKeyID:  record.SignerKeyID,
		CreatedAt:    record.CreatedAt,
		CreatedBy:    record.CreatedBy,
		Placeholders: provision.Placeholders(string(body)),
		Warnings:     warningsOrEmpty(provision.Warnings(string(body))),
		Archived:     archival.Archived(),
		ArchivedBy:   archival.ArchivedBy,
	}
	if archival.Archived() {
		at := archival.ArchivedAt
		view.ArchivedAt = &at
	}

	noStore(w)
	writeJSON(w, http.StatusOK, view)
}

// handleArchiveTemplate withdraws a template name from use.
//
// This is what the UI's missing delete button became, and the difference is not cosmetic. A template
// version is permanent because a host's Tier 2 bootstrap record names one — docs/SECURITY.md §7 — so
// there is no endpoint here that destroys one and there is not going to be. What an operator retiring a
// template actually wants is for nobody to use it again, and that is what this does: the name leaves
// the listing, refuses new versions, cannot be named by a new enrolment token, cannot be rendered, and
// is refused at enrolment. Every version stays readable, and restoring changes it all back.
//
// It is an operator action like any other, and it authorises nothing on any machine: the effect of
// archiving is entirely subtractive — a control plane that archived every template in a fleet would
// have stopped bootstraps and reached no enrolled host at all.
func (s *Server) handleArchiveTemplate(w http.ResponseWriter, r *http.Request, who operator) {
	name := r.PathValue("name")
	archival := store.TemplateArchival{
		Name:       name,
		ArchivedAt: time.Now().UTC(),
		ArchivedBy: who.Principal(),
	}
	err := who.Store.ArchiveTemplate(r.Context(), archival)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such template")
		return
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "archived_template", archivedTemplateMessage(name))
		return
	case err != nil:
		slog.Error("could not archive a template", "error", err, "template", name)
		writeError(w, http.StatusInternalServerError, "internal", "could not archive the template")
		return
	}

	slog.Info("template archived",
		"template", name, "tenant", who.Store.Tenant(), "operator", who.Principal())

	writeJSON(w, http.StatusOK, map[string]any{
		"name":       name,
		"archived":   true,
		"archivedAt": archival.ArchivedAt,
		"archivedBy": archival.ArchivedBy,
	})
}

// handleRestoreTemplate puts an archived template name back into use.
//
// Restoring is not an approval of anything and grants nothing the name did not have before: a restored
// template is issuable at enrolment only under the conditions that already governed it — a signature
// this control plane cannot produce, and a token minted naming it. Undoing an archival can therefore
// never be the step that lets something reach a host.
func (s *Server) handleRestoreTemplate(w http.ResponseWriter, r *http.Request, who operator) {
	name := r.PathValue("name")
	err := who.Store.RestoreTemplate(r.Context(), name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such template")
		return
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "not_archived",
			"the template "+name+" is not archived, so there is nothing to restore")
		return
	case err != nil:
		slog.Error("could not restore a template", "error", err, "template", name)
		writeError(w, http.StatusInternalServerError, "internal", "could not restore the template")
		return
	}

	slog.Info("template restored",
		"template", name, "tenant", who.Store.Tenant(), "operator", who.Principal())

	writeJSON(w, http.StatusOK, map[string]any{"name": name, "archived": false})
}

// templateIsLive reports whether a template name may still be used, answering the caller if not.
//
// One helper rather than the same four lines at each site, and it returns the refusal already written
// for the same reason checkBootstrapIsIssuable does: a caller that forgot to return after a refusal
// would write a second response body over the first.
func (s *Server) templateIsLive(w http.ResponseWriter, r *http.Request, who operator, name string) bool {
	archival, err := who.Store.GetTemplateArchival(r.Context(), name)
	if err != nil {
		slog.Error("could not read a template's archival", "error", err, "template", name)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the template")
		return false
	}
	if archival.Archived() {
		writeError(w, http.StatusConflict, "archived_template", archivedTemplateMessage(name))
		return false
	}
	return true
}

// templateRevisionView is one stored revision as the listing renders it.
type templateRevisionView struct {
	// Version is the revision's number.
	Version int `json:"version"`

	// Signed reports whether it can be issued to an enrolling host at all.
	Signed bool `json:"signed"`

	// SignerKeyID names the key that signed it, empty when unsigned.
	SignerKeyID string `json:"signerKeyId,omitempty"`

	// CreatedAt is when it was stored.
	CreatedAt time.Time `json:"createdAt"`

	// CreatedBy is who stored it.
	CreatedBy string `json:"createdBy"`
}

// handleListTemplateVersions returns every stored revision of one template, newest first.
//
// It exists because immutable versioning was, until this endpoint, something an operator had to take
// on faith. A host's bootstrap record names a version; the listing showed only the latest; and reaching
// version 3 of a template whose latest is 7 meant guessing the number and asking for it one request at
// a time, with nothing to say whether the gaps were real. "Every save is a new version" is only a
// property worth having if it is one somebody can look at.
//
// No bodies. They are sealed and potentially large, and a caller that wants one names a version and
// asks for it — which is also the request that is marked non-cacheable, because that is the one
// carrying something worth keeping out of a cache.
func (s *Server) handleListTemplateVersions(w http.ResponseWriter, r *http.Request, who operator) {
	revisions, err := who.Store.ListTemplateVersions(r.Context(), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such template")
		return
	}
	if err != nil {
		slog.Error("could not list a template's versions", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the template")
		return
	}

	views := make([]templateRevisionView, 0, len(revisions))
	for _, rev := range revisions {
		views = append(views, templateRevisionView{
			Version:     rev.Version,
			Signed:      rev.Signed,
			SignerKeyID: rev.SignerKeyID,
			CreatedAt:   rev.CreatedAt,
			CreatedBy:   rev.CreatedBy,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":     r.PathValue("name"),
		"versions": views,
	})
}

// renderRequest is the body of POST /api/v1/templates/{name}/render.
type renderRequest struct {
	// Version names the version to render, zero for the latest.
	Version int `json:"version,omitempty"`

	// Params are the values substituted into the template's placeholders.
	Params map[string]string `json:"params,omitempty"`

	// Token configures the enrolment token minted when the template uses {{enrollmentToken}}.
	Token *renderTokenRequest `json:"token,omitempty"`
}

// renderTokenRequest configures the token a render mints.
//
// The same fields POST /api/v1/tokens takes, because it is the same act: the render endpoint mints
// through the same store method, and the token appears in the listing like any other.
type renderTokenRequest struct {
	// Label is a human-readable name, defaulted to the template's.
	Label string `json:"label,omitempty"`

	// Group is the fleet group hosts enrolled with it join.
	Group string `json:"group,omitempty"`

	// TTLSeconds overrides the server's default token lifetime.
	TTLSeconds int `json:"ttlSeconds,omitempty"`

	// Bootstrap names the template this token may request at enrolment, empty for none.
	Bootstrap string `json:"bootstrap,omitempty"`
}

// handleRenderTemplate renders one version to user-data and returns it exactly once.
//
// The output is a credential: it usually carries a live enrolment token, minted here. So the response
// is non-cacheable, the body never reaches a log line or an audit entry, and nothing stores it — an
// operator who loses it renders again, which mints a fresh token and costs nothing.
func (s *Server) handleRenderTemplate(w http.ResponseWriter, r *http.Request, who operator) {
	var req renderRequest
	if err := decodeJSON(w, r, MaxTemplateRequestBytes, &req); err != nil {
		writeDecodeError(w, err, "this endpoint renders one template, and the body holds more than one "+
			"JSON value. Nothing was rendered and no token was minted; send them as separate requests.")
		return
	}
	if req.Version < 0 {
		writeError(w, http.StatusBadRequest, "malformed", "version must be a positive whole number")
		return
	}

	record, err := who.Store.GetTemplateVersion(r.Context(), r.PathValue("name"), req.Version)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such template")
		return
	}
	if err != nil {
		slog.Error("could not read a template", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the template")
		return
	}
	if !s.templateIsLive(w, r, who, record.Name) {
		// Before anything is minted, like every other refusal on this path: a render of a retired
		// template would otherwise leave a live enrolment token behind for user-data nobody receives.
		return
	}
	body, err := s.cfg.TemplateKey.Open(record.BodySealed)
	if err != nil {
		slog.Error("could not decrypt a stored template; the sealing key does not match the database",
			"template", record.Name, "version", record.Version, "error", err)
		writeError(w, http.StatusInternalServerError, "sealed",
			"the stored template cannot be decrypted; the control plane's template key does not match "+
				"this database. See docs/INSTALL.md on backing the key up beside the CA.")
		return
	}

	params := req.Params
	if params == nil {
		params = map[string]string{}
	}
	if _, caller := params[provision.TokenPlaceholder]; caller {
		// Minted, never supplied: the whole point of the placeholder is that the token is single-use
		// and expiring, and a caller-pasted one is a token whose history nobody knows.
		writeError(w, http.StatusBadRequest, "malformed",
			provision.TokenPlaceholder+" is minted at render time and cannot be supplied; configure it "+
				"with the token field instead")
		return
	}

	// Everything that can refuse this request runs before anything is minted. A token is a live
	// credential the moment it exists, and one minted for a render that then failed on a typo is a
	// credential nobody was shown, nobody can revoke by name, and nobody knows is there — so the
	// substitution is rehearsed against a placeholder first, and the real token replaces it only once
	// the whole render is known to succeed.
	mints := usesToken(string(body))
	if req.Token != nil && !mints {
		// Refused rather than ignored. Every field of the token block — the group a host joins, the
		// bootstrap template it may apply — describes a credential this render is not going to produce,
		// and accepting the request would hand back user-data that does nothing the caller asked for.
		// It is the same strictness Render already applies to a parameter that substitutes nothing.
		writeError(w, http.StatusBadRequest, "malformed",
			"this template does not substitute {{"+provision.TokenPlaceholder+"}}, so no enrolment "+
				"token is minted and the token field would have no effect")
		return
	}
	if mints {
		params[provision.TokenPlaceholder] = EnrollmentTokenStandIn()
	}
	if _, err := provision.Render(string(body), params); err != nil {
		writeError(w, http.StatusBadRequest, "unrenderable", err.Error())
		return
	}
	if req.Token != nil && !s.checkBootstrapIsIssuable(w, r, who, req.Token.Bootstrap) {
		return
	}

	var tokenExpiresAt *time.Time
	if mints {
		token, expires, err := s.mintRenderToken(r, who, record.Name, req.Token)
		if err != nil {
			slog.Error("could not mint an enrolment token for a render",
				"template", record.Name, "error", err)
			writeError(w, http.StatusInternalServerError, "internal",
				"could not mint the enrolment token this template substitutes")
			return
		}
		params[provision.TokenPlaceholder] = token
		tokenExpiresAt = &expires
	}

	rendered, err := provision.Render(string(body), params)
	if err != nil {
		// Unreachable in practice: the rehearsal above ran the same substitution over the same body
		// with the same parameter names. Handled rather than ignored, because "unreachable" is a
		// claim about today's Render and the credential has already been minted by this point.
		slog.Error("a rehearsed render failed on its second pass",
			"template", record.Name, "version", record.Version, "error", err)
		writeError(w, http.StatusBadRequest, "unrenderable", err.Error())
		return
	}

	// The name and version, and deliberately not the output: the output is the credential.
	slog.Info("template rendered",
		"template", record.Name, "version", record.Version, "tenant", who.Store.Tenant(),
		"operator", who.Principal(), "token_minted", tokenExpiresAt != nil)

	noStore(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"name":           record.Name,
		"version":        record.Version,
		"userData":       rendered,
		"warnings":       warningsOrEmpty(provision.Warnings(rendered)),
		"tokenExpiresAt": tokenExpiresAt,
		"note": "This output is a credential: it is shown once, and nothing stores it. Paste it into " +
			"your provisioner now, or render again for a fresh token.",
	})
}

// usesToken reports whether a body substitutes the reserved enrolment-token placeholder.
func usesToken(body string) bool {
	for _, name := range provision.Placeholders(body) {
		if name == provision.TokenPlaceholder {
			return true
		}
	}
	return false
}

// mintRenderToken issues the enrolment token a render substitutes.
//
// It goes through the same store method as POST /api/v1/tokens, so the token appears in the listing
// like any other and expires like any other. The label defaults to naming the template, because a page
// of tokens all called "render" answers nobody's question.
func (s *Server) mintRenderToken(r *http.Request, who operator, templateName string,
	cfg *renderTokenRequest) (string, time.Time, error) {

	if cfg == nil {
		cfg = &renderTokenRequest{}
	}
	ttl := s.cfg.TokenTTL
	if cfg.TTLSeconds > 0 {
		ttl = time.Duration(cfg.TTLSeconds) * time.Second
	}
	label := cfg.Label
	if label == "" {
		label = "rendered:" + templateName
	}

	token, hash, err := NewEnrollmentToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	record := store.EnrollmentToken{
		Hash:      hash,
		Label:     label,
		Group:     cfg.Group,
		Bootstrap: cfg.Bootstrap,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	if err := who.Store.CreateEnrollmentToken(r.Context(), record); err != nil {
		return "", time.Time{}, err
	}
	return token, record.ExpiresAt, nil
}

// noStore marks a response as holding a credential no cache may keep.
//
// no-store rather than no-cache: no-cache permits storing and requires revalidation, and a rendered
// template in a shared proxy's cache is precisely the disclosure being prevented.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

// warningsOrEmpty returns an empty slice rather than nil, so the JSON is [] and never null.
func warningsOrEmpty(warnings []string) []string {
	if warnings == nil {
		return []string{}
	}
	return warnings
}
