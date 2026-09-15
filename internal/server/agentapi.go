package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pascalgross/hostseal/internal/auth"
	"github.com/pascalgross/hostseal/internal/canonical"
	"github.com/pascalgross/hostseal/internal/notify"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/store"
)

// handleEnroll exchanges a bootstrap token and a CSR for a host-scoped client certificate.
//
// It is the only endpoint that does not require a client certificate, because a host enrolling does not
// have one yet. Everything that makes it safe is therefore in the token: single-use, time-limited,
// consumed atomically, and stored only as a hash.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	// The only endpoint reachable without a client certificate, and therefore the only one worth rate
	// limiting. A token is 256 bits of uniform randomness, so this defends against the load of guessing
	// rather than against its success — and against a misconfigured provisioning loop, which is the
	// case that actually happens.
	if !s.enrolLimiter.allow(auth.RequestSource(r), time.Now()) {
		w.Header().Set("Retry-After", strconv.Itoa(int(s.enrolLimiter.retryAfter().Seconds())))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many enrolment attempts")
		return
	}

	var req protocol.EnrollRequest
	if err := decodeJSON(w, r, protocol.MaxEnrollBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		return
	}
	if req.Token == "" || req.CSR == "" {
		writeError(w, http.StatusBadRequest, "malformed", "token and csr are both required")
		return
	}

	// The token names the tenant, and it is resolved before it is redeemed.
	//
	// This is how a machine joins a fleet, and it is the only way: the tenant is not in the URL and not
	// in the body, so the enrolling machine — which is not authenticated at this moment — has no say in
	// which customer it becomes part of. Resolving without consuming keeps the ordering below intact.
	tenantID, err := s.cfg.Store.TenantForEnrollmentToken(r.Context(), HashToken(req.Token))
	if errors.Is(err, store.ErrTokenUnusable) {
		// Unknown, expired and already used are one response. Telling an attacker which of the three
		// applies is free reconnaissance.
		writeError(w, http.StatusUnauthorized, "token_unusable", "the enrolment token cannot be used")
		return
	}
	if err != nil {
		slog.Error("could not resolve an enrolment token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the token")
		return
	}
	tenant := s.cfg.Store.In(tenantID)

	// The machine-id check comes before the token is consumed, so that a host retrying an enrolment it
	// has already completed does not burn a second token in the process of being told no. Revoked hosts
	// are not matched, so revoking one is the operator action that lets its machine enrol again — which
	// the message says, because a bare 409 on a machine somebody is trying to rebuild is a dead end.
	//
	// The claim is per tenant, and the answer names the existing host only because the presenter holds
	// a token for that same tenant. Across tenants this check would be an oracle — enrol a machine and
	// be told whether somebody else already manages it — which is why the constraint behind it is
	// (tenant_id, machine_id_hash) rather than the machine id alone.
	if req.MachineIDHash != "" {
		existing, err := tenant.GetHostByMachineID(r.Context(), req.MachineIDHash)
		switch {
		case err == nil:
			writeError(w, http.StatusConflict, "already_enrolled",
				"a host with this machine id is already enrolled as "+existing.ID+
					"; revoke or delete it to enrol this machine again")
			return
		case !errors.Is(err, store.ErrNotFound):
			slog.Error("machine id lookup failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "could not check for an existing host")
			return
		}
	}

	// Suspension and the host limit are checked here: after the machine-id claim and before the token
	// is consumed, so that a refusal leaves the token usable and the operator can retry once whatever
	// it names has been dealt with. Burning a token to say "not right now" would turn a billing
	// question into a support ticket about a spent credential.
	//
	// This check is for the message, not for the guarantee. It reads a count and then, several
	// statements later, a row is written, and two machines enrolling together with two valid tokens
	// both pass it. What actually enforces the limit is CreateEnrolledHost, which counts and writes
	// inside one transaction with the fleet's row locked. Both exist because they answer different
	// questions: this one refuses cheaply and without spending anything, that one refuses correctly.
	//
	// Both settings belong to the tenant and are administered by the platform role. Neither reaches a
	// host: this is the control plane declining to enrol a new machine, which it may always do, and not
	// an instruction to a machine that is already enrolled.
	tenantRow, err := s.cfg.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		slog.Error("could not read the enrolling tenant", "error", err, "tenant", tenantID)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the fleet")
		return
	}
	if tenantRow.Suspended {
		writeError(w, http.StatusForbidden, "tenant_suspended",
			"this fleet is suspended; its agents are not being answered. Nothing on this machine has "+
				"been changed and nothing needs to be undone.")
		return
	}
	if tenantRow.HostLimit != nil {
		counts, err := tenant.CountHosts(r.Context())
		if err != nil {
			slog.Error("could not count a fleet's hosts", "error", err, "tenant", tenantID)
			writeError(w, http.StatusInternalServerError, "internal", "could not count the fleet")
			return
		}
		if counts.Active >= *tenantRow.HostLimit {
			// The active count, not the total: revoking a host is how an operator makes room for
			// another one, and a limit measured against rows kept for the audit trail would make that
			// impossible for a reason nobody could see.
			slog.Info("enrolment refused by the fleet's host limit",
				"tenant", tenantID, "limit", *tenantRow.HostLimit, "active", counts.Active)
			writeError(w, http.StatusForbidden, "host_limit_reached",
				fmt.Sprintf("this fleet may hold %d host(s) and already has %d. Revoke one to make "+
					"room, or raise the limit.", *tenantRow.HostLimit, counts.Active))
			return
		}
	}

	// The bootstrap template is resolved before the certificate is issued and before the token is
	// consumed, for the same reason the CSR is checked before consumption: a refusal here must leave
	// the token usable, so the operator can fix what was named and retry — or retry without
	// --bootstrap — rather than being told their token is spent. Silence is not an acceptable answer
	// to a bootstrap request: either the template comes back signed, or the enrolment fails with a
	// message naming why, and the agent refuses to continue either way.
	bootstrap, ok := s.resolveBootstrap(w, r, tenant, HashToken(req.Token), req.RequestedBootstrap)
	if !ok {
		return // resolveBootstrap has written the refusal.
	}

	hostID, err := NewID()
	if err != nil {
		slog.Error("could not generate a host id", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not allocate a host id")
		return
	}

	// The certificate is issued before the token is consumed. A token is single-use, so a malformed CSR
	// would otherwise burn one and leave an operator to work out why their second attempt says the
	// token is unusable — which reads exactly like the token having been stolen. Nothing trusts a
	// certificate that was never recorded: authentication is a fingerprint lookup, so an issued
	// certificate that the enrolment then abandons authenticates nothing.
	certPEM, cert, err := s.cfg.Authority.Issue([]byte(req.CSR), hostID)
	if err != nil {
		slog.Warn("rejected a certificate request before consuming the token", "error", err)
		writeError(w, http.StatusBadRequest, "bad_csr", "the certificate request could not be signed")
		return
	}

	now := time.Now()
	token, err := tenant.ConsumeEnrollmentToken(r.Context(), HashToken(req.Token), hostID, now)
	if errors.Is(err, store.ErrTokenUnusable) {
		// Still checked here even though the token resolved a moment ago, because this is the atomic
		// redemption and the one above is only a read: two agents presenting the same token together
		// both resolve it, and exactly one of them redeems it.
		writeError(w, http.StatusUnauthorized, "token_unusable", "the enrolment token cannot be used")
		return
	}
	if err != nil {
		slog.Error("could not consume an enrolment token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not redeem the token")
		return
	}

	host := store.Host{
		ID:            hostID,
		Hostname:      req.Hostname,
		MachineIDHash: req.MachineIDHash,
		Group:         token.Group,
		AgentVersion:  req.AgentVersion,
		EnrolledAt:    now,
	}
	// The host and its certificate land together or not at all. A host row without a certificate holds
	// the machine-id hash while being unable to authenticate, so the machine could neither talk nor
	// enrol again — a permanent wedge caused by a failure that lasted a fraction of a second.
	if err := tenant.CreateEnrolledHost(r.Context(), host, store.Certificate{
		Fingerprint: Fingerprint(cert),
		HostID:      hostID,
		TenantID:    tenantID,
		Serial:      cert.SerialNumber.Text(16),
		IssuedAt:    now,
		NotAfter:    cert.NotAfter,
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "already_enrolled", "this host is already enrolled")
			return
		}
		if errors.Is(err, store.ErrHostLimitReached) {
			// The check above passed and this one did not, which means another machine took the last
			// slot in between. The token is spent by now — it had to be, since consuming it is what
			// proves this enrolment is the one that redeemed it — so the message says so rather than
			// leaving an operator to discover it on the retry. Same status and code as the early
			// refusal, because to the agent it is the same answer: the fleet is full, back off.
			slog.Info("enrolment lost the race for a fleet's last slot", "tenant", tenantID, "host", hostID)
			writeError(w, http.StatusForbidden, "host_limit_reached",
				"this fleet filled up while this enrolment was in flight. Nothing on this machine has "+
					"been changed. The enrolment token has been spent, so issue a new one after "+
					"revoking a host or raising the limit.")
			return
		}
		slog.Error("could not record an enrolment", "error", err, "host", hostID)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the host")
		return
	}

	slog.Info("host enrolled",
		"host", hostID, "tenant", tenantID, "hostname", req.Hostname, "group", token.Group,
		"agent_version", req.AgentVersion, "token_label", token.Label)
	s.emit(r.Context(), tenantID, notify.Event{
		Kind: notify.KindHostEnrolled, HostID: hostID, Hostname: req.Hostname, At: now,
		Summary: req.Hostname + " enrolled into group " + token.Group,
	})

	if bootstrap != nil {
		// The name and version, and never the body: the body reaches the journal on the host, printed
		// by the agent to the operator authorising it, which is where it belongs.
		slog.Info("bootstrap template issued",
			"host", hostID, "tenant", tenantID, "template", bootstrap.Name,
			"template_version", bootstrap.Version, "signer", bootstrap.SignerKeyID)
	}

	writeJSON(w, http.StatusOK, protocol.EnrollResponse{
		OnlineKey:            s.onlineKeyLine(),
		HostID:               hostID,
		Certificate:          string(certPEM),
		CABundle:             string(s.cfg.Authority.CertificatePEM()),
		ServerTime:           now.UTC(),
		NextHeartbeatSeconds: s.cfg.HeartbeatSeconds,
		Bootstrap:            bootstrap,
	})
}

// resolveBootstrap turns a requested template name into the signed template the response will carry.
//
// It returns (nil, true) when nothing was requested, (template, true) on success, and (nil, false)
// after writing a refusal — and a refusal is the only alternative to success, because an agent that
// asked for a template and silently received none must not proceed as though one had been applied.
//
// Two properties here carry the second paragraph of the guarantee:
//
// The token decides. A token names the one template it may request, at mint time, by an authenticated
// operator. A request naming anything else is refused before anything is consumed, so possession of a
// leaked token is not the authority to choose what runs on the machine being enrolled.
//
// The signature is not this control plane's to make. The stored signature was produced offline by
// `hostseal sign-template`, with a key this process does not hold, and it is handed over verbatim. An
// unsigned template is a refusal rather than an invitation to sign: a control plane that could sign a
// bootstrap template could run operator-authored configuration on a host at enrolment, which is
// precisely the hole the guarantee's second paragraph is scoped to keep narrow.
// TestGuaranteeTheControlPlaneCannotSignABootstrapTemplate asserts both directions of that.
func (s *Server) resolveBootstrap(w http.ResponseWriter, r *http.Request, tenant store.Scoped,
	tokenHash, requested string) (*protocol.Bootstrap, bool) {

	if requested == "" {
		return nil, true
	}

	token, err := tenant.GetEnrollmentToken(r.Context(), tokenHash)
	if err != nil {
		// The token resolved to a tenant a moment ago, so this is a race with its expiry or another
		// consumer rather than a guess; the answer is the same one either way.
		writeError(w, http.StatusUnauthorized, "token_unusable", "the enrolment token cannot be used")
		return nil, false
	}
	if token.Bootstrap != requested {
		// One message whether the token names a different template or none: what to fix is the token,
		// and naming the template it does carry would tell a token thief what this fleet provisions.
		writeError(w, http.StatusForbidden, "bootstrap_not_authorised",
			"this enrolment token does not authorise the bootstrap template "+requested+
				"; mint a token that names it")
		return nil, false
	}

	record, err := tenant.GetTemplateVersion(r.Context(), requested, 0)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusConflict, "no_such_template",
			"the template "+requested+" does not exist in this fleet; nothing was applied and the "+
				"enrolment was refused rather than continuing as though it had been")
		return nil, false
	}
	if err != nil {
		slog.Error("could not read a bootstrap template", "error", err, "template", requested)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the template")
		return nil, false
	}
	if !record.Signed() {
		writeError(w, http.StatusConflict, "unsigned_template",
			"the latest version of "+requested+" carries no offline signature, and this control plane "+
				"cannot produce one: a bootstrap template is signed by a key in the host's own "+
				"trusted-signers, which this control plane does not hold. Sign it with "+
				"`hostseal sign-template` and store the signed version.")
		return nil, false
	}

	body, err := s.cfg.TemplateKey.Open(record.BodySealed)
	if err != nil {
		slog.Error("could not decrypt a stored template; the sealing key does not match the database",
			"template", record.Name, "version", record.Version, "error", err)
		writeError(w, http.StatusInternalServerError, "sealed",
			"the stored template cannot be decrypted on this control plane")
		return nil, false
	}

	// Checked again here, and the repetition is the point — the same reason the signature is checked
	// again a few lines above. A token names a template, never a version, so the row resolved when the
	// token was minted and the row resolved now are two different reads of "the latest": storing a new
	// version during a token's lifetime is ordinary, and a check that ran only at mint time would let
	// that version through. This is where the bytes are actually chosen, so this is where it has to
	// hold.
	if !bootstrapDoesNotMintItsOwnToken(w, record.Name, string(body)) {
		return nil, false
	}

	return &protocol.Bootstrap{
		Name:        record.Name,
		Version:     record.Version,
		Body:        string(body),
		Signature:   record.Signature,
		SignerKeyID: record.SignerKeyID,
	}, true
}

// handleHeartbeat records a host's state and decides what to ask for next.
//
// The digest comparison here is the entire digest-first design. Five hundred hosts sending a full
// inventory every sixty seconds is hundreds of kilobytes per host per minute of write amplification;
// comparing a digest instead makes the steady state hundreds of bytes and full reports rare and
// event-driven.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, who caller) {
	host := who.Host
	var req protocol.HeartbeatRequest
	if err := decodeJSON(w, r, protocol.MaxHeartbeatBytes, &req); err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large",
				"the heartbeat body exceeded the limit; truncate a section and set its truncated flag")
			return
		}
		writeError(w, http.StatusBadRequest, "malformed", "the heartbeat body could not be read")
		return
	}

	now := time.Now()
	if err := who.Store.RecordHeartbeat(r.Context(), host.ID, store.HeartbeatUpdate{
		AgentVersion:       req.AgentVersion,
		BootID:             req.BootID,
		UptimeSeconds:      req.UptimeSeconds,
		ClockOffsetSeconds: req.ClockOffsetSeconds,
		Paused:             req.Paused,
		LastSeen:           now,
	}); err != nil {
		slog.Error("could not record a heartbeat", "error", err, "host", host.ID)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the heartbeat")
		return
	}

	s.storeDocumentIfPresent(r.Context(), who, "facts", req.Facts, req.FactsDigest)
	s.storeDocumentIfPresent(r.Context(), who, "policy", req.Policy, req.PolicyDigest)
	// req.Signers != nil rather than len() > 0: an empty trust anchor is a real answer and the default
	// one, and treating it as "not reported" would make the server ask for it forever.
	if req.Signers != nil {
		s.storeDocumentIfPresent(r.Context(), who, "signers", req.Signers, req.SignersDigest)
	}

	// host carries the digests of the documents the server actually holds, read before this beat was
	// applied; the store never records a digest a host merely claimed. A mismatch therefore means "I do
	// not have this document", and it keeps meaning that until one arrives — which is what makes a lost
	// full report recoverable rather than permanent. Recording the claim instead would make the server
	// ask exactly once, and if that one report were lost to a network failure it would compare the next
	// heartbeat against its own stored claim, conclude it was up to date, and never ask again.
	wantFacts := req.FactsDigest != "" && req.FactsDigest != host.FactsDigest && req.Facts == nil
	wantPolicy := req.PolicyDigest != "" && req.PolicyDigest != host.PolicyDigest && req.Policy == nil
	wantSigners := req.SignersDigest != "" && req.SignersDigest != host.SignersDigest && req.Signers == nil

	if req.ClockOffsetSeconds > protocol.MaxClockSkewSeconds ||
		req.ClockOffsetSeconds < -protocol.MaxClockSkewSeconds {
		// Logged rather than acted on. The host has already decided to refuse privileged intents; the
		// server's job is to make the reason visible before somebody spends an afternoon on it.
		slog.Warn("host clock is far from the control plane's",
			"host", host.ID, "hostname", host.Hostname, "offset_seconds", req.ClockOffsetSeconds)
	}

	writeJSON(w, http.StatusOK, protocol.HeartbeatResponse{
		OnlineKey:            s.onlineKeyLine(),
		ServerTime:           now.UTC(),
		NextHeartbeatSeconds: s.cfg.HeartbeatSeconds,
		WantFullReport:       wantFacts && wantPolicy,
		WantFacts:            wantFacts,
		WantPolicy:           wantPolicy,
		WantSigners:          wantSigners,
	})
}

// storeDocumentIfPresent persists one full document from a heartbeat, if it carried one.
//
// The digest is recomputed from the document rather than taken from the request. A host whose reported
// digest did not match what it sent would otherwise poison the comparison for every future beat: the
// server would believe it held something it did not, and would stop asking for the real thing.
func (s *Server) storeDocumentIfPresent(ctx context.Context, who caller, kind string, document any, claimed string) {
	if document == nil {
		return
	}
	hostID := who.Host.ID
	encoded, err := canonical.Marshal(document)
	if err != nil {
		slog.Warn("could not canonicalise a reported document", "kind", kind, "host", hostID, "error", err)
		return
	}
	actual := canonical.DigestBytes(encoded)
	if claimed != "" && claimed != actual {
		slog.Warn("a host reported a digest that does not match the document it sent",
			"kind", kind, "host", hostID, "claimed", claimed, "actual", actual)
	}

	var storeFn func(context.Context, string, string, []byte) error
	switch kind {
	case "facts":
		storeFn = who.Store.StoreFacts
	case "policy":
		storeFn = who.Store.StorePolicy
	case "signers":
		storeFn = who.Store.StoreSigners
	default:
		return
	}
	if err := storeFn(ctx, hostID, actual, encoded); err != nil {
		slog.Error("could not store a reported document", "kind", kind, "host", hostID, "error", err)
		return
	}

	// Unit monitoring rides the facts report, because the report arriving is the only moment a
	// "before" and an "after" both exist. who.Host still carries the document this one replaced —
	// it was loaded before the store above ran.
	if kind == "facts" {
		s.detectUnitTransitions(ctx, who, who.Host.Facts, encoded)
	}
}

// handleJobs is the long-poll that delivers work.
//
// The hold defaults to twenty-five seconds and is clamped to sixty. It must sit below the smallest idle
// timeout on the path — thirty to sixty seconds is the common default for proxies, load balancers and
// NAT tables — because a hold longer than that produces intermittent failures that look like network
// flakiness and get debugged as such for weeks. wait=0 degrades to plain polling, for environments that
// terminate held connections regardless.
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request, who caller) {
	host := who.Host
	wait := protocol.DefaultJobWaitSeconds
	if raw := r.URL.Query().Get("wait"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "malformed", "wait must be an integer number of seconds")
			return
		}
		wait = min(max(n, 0), protocol.MaxJobWaitSeconds)
	}

	// Subscribed before the queue is read, not after. The other order leaves a gap in which a job
	// inserted between the empty read and the subscription fires its notification with nobody
	// listening — and the agent then holds its long-poll for the full twenty-five seconds over work
	// that was already waiting. The consequence is only latency, which is precisely why nobody would
	// ever diagnose it.
	notified, unsubscribe := s.cfg.Store.Subscribe(host.ID)
	defer unsubscribe()

	jobs, err := who.Store.ClaimJobs(r.Context(), host.ID, 10)
	if err != nil {
		slog.Error("could not claim jobs", "error", err, "host", host.ID)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the job queue")
		return
	}
	if len(jobs) > 0 || wait == 0 {
		writeJSON(w, http.StatusOK, protocol.JobsResponse{Jobs: nonNil(jobs)})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(wait)*time.Second)
	defer cancel()

	// A wake-up may be spurious — the store says so — so the queue is re-read rather than trusted.
	// Returning an empty list after a spurious wake is correct and costs the agent one round trip.
	select {
	case <-notified:
		jobs, err = who.Store.ClaimJobs(r.Context(), host.ID, 10)
		if err != nil {
			slog.Error("could not claim jobs after a wake-up", "error", err, "host", host.ID)
			writeError(w, http.StatusInternalServerError, "internal", "could not read the job queue")
			return
		}
	case <-ctx.Done():
	}
	writeJSON(w, http.StatusOK, protocol.JobsResponse{Jobs: nonNil(jobs)})
}

// nonNil returns an empty slice rather than nil, so the JSON is [] and never null.
//
// A client that has to handle both is a client with a branch nobody tests, and docs/PROTOCOL.md shows
// an empty array.
func nonNil(jobs []protocol.Job) []protocol.Job {
	if jobs == nil {
		return []protocol.Job{}
	}
	return jobs
}

// handleResult records a job result idempotently.
//
// The agent retries until it receives a 2xx, and a repeated result for a job that already has one
// returns 200 and changes nothing. Work that succeeded but whose result was lost must never re-execute:
// that is how a retry turns one reboot into a reboot loop.
func (s *Server) handleResult(w http.ResponseWriter, r *http.Request, who caller) {
	host := who.Host
	jobID := r.PathValue("id")
	if jobID == "" {
		writeError(w, http.StatusBadRequest, "malformed", "the job id is missing from the path")
		return
	}

	var req protocol.ResultRequest
	if err := decodeJSON(w, r, protocol.MaxResultBytes, &req); err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large",
				"the result body exceeded the limit; output is truncated to its last 64 KiB")
			return
		}
		writeError(w, http.StatusBadRequest, "malformed", "the result body could not be read")
		return
	}
	if req.JobID != "" && req.JobID != jobID {
		writeError(w, http.StatusBadRequest, "malformed", "the job id in the body does not match the path")
		return
	}
	// The status is a closed set, and this is the one field of a result the control plane must not pass
	// through. Every client renders it as the job's state, so an unchecked word lets a host name its own
	// job "queued" — a job that has been claimed and has reported a result then looks untouched, and an
	// operator re-issues work that has already run. A future agent reporting a word this build does not
	// know is refused for the same reason and retries, rather than being displayed as a state.
	if !protocol.ValidStatus(req.Status) {
		slog.Warn("a host reported an unknown result status",
			"host", host.ID, "job", jobID, "status", req.Status)
		writeError(w, http.StatusBadRequest, "malformed",
			"the result status is not one this control plane knows; see docs/PROTOCOL.md §6")
		return
	}
	req.JobID = jobID
	req.Output, req.OutputTruncated = protocol.TruncateOutput(req.Output)

	first, err := who.Store.RecordResult(r.Context(), host.ID, req)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Either the job never existed or it belongs to a different host. The two are one response, as
		// everywhere else: distinguishing them would let an enrolled host enumerate other hosts' jobs.
		slog.Warn("a host reported a result for a job that is not its own",
			"host", host.ID, "job", jobID)
		writeError(w, http.StatusNotFound, "unknown_job", "no such job for this host")
		return
	case err != nil:
		slog.Error("could not record a job result", "error", err, "host", host.ID, "job", jobID)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the result")
		return
	}

	slog.Info("job result recorded",
		"host", host.ID, "job", jobID, "status", req.Status, "exit_code", req.ExitCode)

	// Emitted only for the first recording of a result: the agent retries until acknowledged, and an
	// operator paged twice per failure starts counting failures wrong. Failures and expiries only —
	// a refusal is the system working, and an event stream that treats refused_by_policy as an
	// incident teaches its readers to ignore incidents.
	if first {
		switch req.Status {
		case protocol.StatusFailed:
			s.emit(r.Context(), who.Store.Tenant(), notify.Event{
				Kind: notify.KindJobFailed, HostID: host.ID, Hostname: host.Hostname,
				At:      time.Now().UTC(),
				Summary: "a job failed on " + host.Hostname + ": " + firstLine(req.Error),
				Detail: map[string]any{
					"jobId": jobID, "status": req.Status, "exitCode": req.ExitCode,
				},
			})
		case protocol.StatusExpired:
			s.emit(r.Context(), who.Store.Tenant(), notify.Event{
				Kind: notify.KindJobExpired, HostID: host.ID, Hostname: host.Hostname,
				At: time.Now().UTC(),
				Summary: "a job expired unexecuted on " + host.Hostname +
					"; it sat past its validity window and the host refused to run stale work",
				Detail: map[string]any{"jobId": jobID, "status": req.Status},
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

// firstLine trims an error report to something a one-line summary can carry.
//
// Job errors legitimately arrive as multi-line helper output, and a summary is a sentence in a chat
// message or an inbox row — the full text is on the job's own page.
func firstLine(s string) string {
	if s == "" {
		return "no error text was reported"
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		// Cut on a rune boundary, not a byte one. Helper output is whatever a package's maintainer
		// scripts printed, which is routinely translated — and half a rune reaches a mail subject
		// line and a chat message as a replacement character that looks like corruption.
		cut := 200
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// handleRenew issues a fresh certificate for an already-authenticated host.
//
// The identity comes from the presenting certificate and never from the CSR. A CSR is an untrusted
// document: honouring the subject in it would let a host re-key a certificate for a different host
// entirely, which is a full compromise of the fleet's identity from one enrolled machine.
//
// Three bounds surround the issuing, and each closes something the other two do not. The limiter bounds
// the rate at which one host may spend a CA signature and a row in a table every tenant shares. The cap
// bounds the total, because a rate limit alone permits an unbounded number of certificates given
// enough time. And the presenting certificate is superseded after a short overlap, which is what makes
// the agent's key rotation worth anything: without it, somebody who read agent.pem on day ten kept a
// working authentication path until day ninety, and could spend the renewals themselves to keep it.
//
// The cap and both writes are one store operation rather than three calls, and that is not tidiness.
// Counting and then inserting separately is check-then-act, and the limiter's burst is exactly the
// concurrency that reaches it — several requests for one host each seeing room and each taking it. And
// recording the replacement without retiring the presented certificate is unrecoverable rather than
// merely untidy: a later renewal retires the fingerprint *it* presents, which by then is the
// replacement, so the forgotten certificate would live to its natural expiry and the 48-hour bound
// would be gone with nothing saying so. Either both writes land or the renewal is not acknowledged.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request, who caller) {
	host := who.Host
	now := time.Now()

	if !s.renewLimiter.allow(host.ID, now) {
		w.Header().Set("Retry-After", strconv.Itoa(int(s.renewLimiter.retryAfter().Seconds())))
		writeError(w, http.StatusTooManyRequests, "rate_limited",
			"this host has renewed too often; a certificate lasts 90 days")
		return
	}

	var req protocol.RenewRequest
	if err := decodeJSON(w, r, protocol.MaxEnrollBytes, &req); err != nil || req.CSR == "" {
		writeError(w, http.StatusBadRequest, "malformed", "a csr is required")
		return
	}

	certPEM, cert, err := s.cfg.Authority.Issue([]byte(req.CSR), host.ID)
	if err != nil {
		slog.Warn("rejected a renewal request", "error", err, "host", host.ID)
		writeError(w, http.StatusBadRequest, "bad_csr", "the certificate request could not be signed")
		return
	}

	// The CA has signed by now and the store may still refuse. That order costs one wasted signature on
	// a host at its cap, and the alternative costs correctness: a count taken before the signature is a
	// count taken outside the transaction that acts on it.
	supersedeAt := now.Add(renewalOverlap)
	switch err := who.Store.RenewCertificate(r.Context(), store.Renewal{
		Replacement: store.Certificate{
			Fingerprint: Fingerprint(cert),
			HostID:      host.ID,
			TenantID:    who.Store.Tenant(),
			Serial:      cert.SerialNumber.Text(16),
			IssuedAt:    now,
			NotAfter:    cert.NotAfter,
		},
		Presented:   who.Fingerprint,
		SupersedeAt: supersedeAt,
		MaxLive:     maxLiveCertificatesPerHost,
		Now:         now,
	}); {
	// 429 rather than 409, because it is transient by construction: the certificates in the way are
	// superseded or expiring, and the agent's existing handling of 429 does the right thing without a
	// change on the host side.
	case errors.Is(err, store.ErrTooManyCertificates):
		slog.Warn("refused a renewal: too many live certificates",
			"host", host.ID, "cap", maxLiveCertificatesPerHost)
		w.Header().Set("Retry-After", strconv.Itoa(int(s.renewLimiter.retryAfter().Seconds())))
		writeError(w, http.StatusTooManyRequests, "too_many_certificates",
			"this host already holds the maximum number of valid certificates")
		return
	case err != nil:
		// Nothing was written, so nothing is acknowledged. The agent keeps its current credential and
		// retries; acknowledging here would be telling a host to promote a certificate the control
		// plane has no record of.
		slog.Error("could not record a renewal", "error", err, "host", host.ID)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the certificate")
		return
	}

	slog.Info("certificate renewed", "host", host.ID,
		"not_after", cert.NotAfter.Format(time.RFC3339),
		"previous_valid_until", supersedeAt.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, protocol.RenewResponse{
		Certificate: string(certPEM),
		CABundle:    string(s.cfg.Authority.CertificatePEM()),
		NotAfter:    cert.NotAfter,
	})
}

// onlineKeyLine renders the control plane's own public key for an agent to store.
//
// Empty when there is no online key, which an agent reads as "nothing to say" rather than as "forget
// what you have". The distinction matters on a control plane that has been restarted without its key
// directory: an agent that cleared its copy on the first such heartbeat would lose the routine tier
// fleet-wide, in a way that looks like the agents breaking rather than the server being misconfigured.
//
// A failure to render is logged and treated as absence for the same reason. It cannot happen with the
// key type this returns, and if it ever did, refusing to answer a heartbeat over it would take a fleet
// offline for the sake of a field that governs one intent.
func (s *Server) onlineKeyLine() string {
	if s.cfg.OnlineKey == nil {
		return ""
	}
	line, err := s.cfg.OnlineKey.PublicLine()
	if err != nil {
		slog.Error("could not render the online key for agents", "error", err)
		return ""
	}
	return line
}

// jsonOrNull returns raw JSON bytes, or the literal null, for embedding a stored document in a response.
//
// Stored documents are already JSON, so re-encoding them would double-escape. A host that has never
// sent one has an empty column, and the API renders that as null rather than as an empty string, so a
// client can tell "not reported yet" from "reported as empty".
func jsonOrNull(raw []byte) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return json.RawMessage(raw)
}
