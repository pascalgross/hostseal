// Package store persists the control plane's state.
//
// The Store interface exists so that tests do not need a database. It is **not** a portability layer,
// and pull requests adding MySQL or SQLite backends will be declined — docs/EXTENDING.md says so and
// this comment says so again, because the interface's existence is the thing that invites the
// misunderstanding.
//
// HostSeal depends on PostgreSQL features that are load-bearing rather than incidental: JSONB with GIN
// indexes for facts that gain fields constantly, partial indexes for the job claim, LISTEN/NOTIFY to
// wake long-polls without Redis, and SELECT … FOR UPDATE SKIP LOCKED for atomic claiming. Abstracting
// those away would mean reimplementing a job queue and a pub/sub system badly, and then shipping a
// second service as a dependency — which is precisely the four-service Compose stack this project
// chose not to be.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/pascalgross/hostseal/internal/protocol"
)

// Sentinel errors every implementation returns for the same conditions.
//
// They are values rather than strings so that handlers can map them to status codes without matching on
// text, which is how a reworded error message turns into a 500 that used to be a 404.
var (
	// ErrNotFound reports that no such row exists.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict reports a uniqueness violation, such as a second host with the same machine id.
	ErrConflict = errors.New("store: conflict")

	// ErrTooManyCertificates reports a host already holding as many live certificates as it may.
	//
	// A distinct error because the caller answers it differently from a failure: it is transient by
	// construction — the certificates in the way are superseded or expiring — so it is a 429 rather
	// than a 500, and the agent's existing backoff does the right thing with no change on the host.
	ErrTooManyCertificates = errors.New("store: too many live certificates for this host")

	// ErrTokenUnusable reports a bootstrap token that is unknown, expired or already consumed.
	//
	// It deliberately covers all three. Telling an attacker which of the three applies is free
	// reconnaissance, so the distinction is not carried out of the store at all rather than being
	// carried and then remembered not to reveal.
	ErrTokenUnusable = errors.New("store: token unusable")

	// ErrHostLimitReached reports a fleet that already holds as many active hosts as it may.
	//
	// It comes from CreateEnrolledHost rather than from a check the caller makes, because a caller's
	// check cannot be atomic with the insert: two machines enrolling at once with two valid tokens
	// would both read a count with room in it and both write. The server checks the limit early too,
	// to refuse before it spends a token, and this is the one that decides.
	ErrHostLimitReached = errors.New("store: fleet is at its host limit")
)

// EnrollmentToken authorises exactly one enrolment.
type EnrollmentToken struct {
	// Hash is the SHA-256 of the token as issued. The token itself is never stored.
	//
	// Storing only the hash means a database dump does not let its holder enrol hosts. The token is
	// shown to the operator once, at creation, and is not recoverable afterwards.
	Hash string

	// Label is what the operator called it, for the UI.
	Label string

	// Group is the fleet group hosts enrolled with this token join.
	Group string

	// Bootstrap names a provisioning template this token may request, empty for none.
	Bootstrap string

	// CreatedAt is when it was issued.
	CreatedAt time.Time

	// ExpiresAt is when it stops working.
	ExpiresAt time.Time

	// ConsumedAt is when it was used, zero if unused.
	ConsumedAt time.Time

	// ConsumedByHost is the host that used it, empty if unused.
	ConsumedByHost string
}

// Usable reports whether a token may still be redeemed at the given instant.
func (t EnrollmentToken) Usable(now time.Time) bool {
	return t.ConsumedAt.IsZero() && now.Before(t.ExpiresAt)
}

// Host is one enrolled machine.
type Host struct {
	// ID is the control plane's identifier, and the certificate subject common name.
	ID string

	// Hostname is what the host calls itself, for display only.
	//
	// It is never used for identity: two hosts can share a hostname, and a host can change its own.
	Hostname string

	// MachineIDHash is the salted hash the host reported at enrolment.
	MachineIDHash string

	// Group is the fleet group, from the enrolment token.
	Group string

	// AgentVersion is the build reported in the last heartbeat.
	AgentVersion string

	// EnrolledAt is when the host first enrolled.
	EnrolledAt time.Time

	// LastSeen is the time of the last heartbeat, by the server's clock.
	LastSeen time.Time

	// BootID identifies the host's current boot, so a reboot is visible without comparing uptimes.
	BootID string

	// UptimeSeconds is what the host last reported.
	UptimeSeconds int64

	// ClockOffsetSeconds is the host's own measurement of its offset from the server.
	//
	// Beyond five minutes, privileged intents refuse on the host and the UI flags it. The value is
	// stored for display; nothing on the server adjusts anything because of it.
	ClockOffsetSeconds int64

	// Paused reports whether /etc/hostseal/paused exists on the host.
	Paused bool

	// FactsDigest, PolicyDigest and SignersDigest are what the host last reported.
	//
	// They are compared against the stored documents to decide whether to ask for a full report. That
	// comparison is the entire digest-first design: without it, five hundred hosts send their whole
	// inventory every minute.
	FactsDigest   string
	PolicyDigest  string
	SignersDigest string

	// Facts, Policy and Signers are the last full documents received, as JSON.
	Facts   []byte
	Policy  []byte
	Signers []byte

	// Revoked reports that this host's certificates are no longer accepted.
	Revoked bool
}

// Event is one entry in a tenant's event inbox.
//
// The inbox is the durable half of notification delivery: the SSE stream and the webhook are
// best-effort, and best-effort delivery must look best-effort — an event a browser tab missed has to
// be visible on the next load rather than simply absent, which is only possible if something kept it.
type Event struct {
	// ID identifies the event, generated by the control plane.
	ID string

	// Kind is one member of the closed vocabulary in internal/notify.
	Kind string

	// HostID is the host the event concerns, empty for fleet-wide events.
	HostID string

	// Hostname is carried for display, because an inbox full of opaque identifiers helps nobody.
	Hostname string

	// Summary is one line of human-readable text.
	Summary string

	// At is when the event happened, by the control plane's clock.
	At time.Time

	// Detail carries event-specific fields, as an opaque JSON object.
	Detail map[string]any
}

// EventFilter narrows an event listing.
type EventFilter struct {
	// Kind limits the listing to one event kind, empty for all.
	Kind string

	// Limit bounds how many are returned, newest first. Zero takes DefaultEventLimit.
	Limit int
}

// DefaultEventLimit is how many events a listing returns when the caller does not say.
const DefaultEventLimit = 100

// MaxEventLimit is the largest event listing a caller may ask for.
const MaxEventLimit = 500

// MaxEventsPerTenant bounds the inbox, oldest evicted first.
//
// The inbox answers "what happened recently", not "what has ever happened" — the audit trail for jobs
// is the jobs table, which is kept for ever. Without a bound, a busy fleet's notifications would grow
// a table nobody reads past the first page of, until the day the insert path is what times out.
const MaxEventsPerTenant = 1000

// UnitTransition is one observed change of a systemd unit's state on one host.
//
// Recorded on the control plane at the resolution of the heartbeat: a unit that fails and recovers
// between two beats is invisible, which is a stated property of the digest-first design rather than a
// surprise to be discovered during an incident. What the history buys is the question a point-in-time
// view cannot answer — "this has been flapping since Tuesday" is visible instead of inferred.
type UnitTransition struct {
	// HostID is the host the unit runs on.
	HostID string

	// Unit is the systemd unit name.
	Unit string

	// From is the previous active state.
	From string

	// To is the active state the unit moved to.
	To string

	// At is when the control plane observed the change, which is bounded by the heartbeat interval.
	At time.Time
}

// MaxUnitTransitionsPerHost bounds the per-host history, oldest evicted first.
const MaxUnitTransitionsPerHost = 500

// AlertCondition is one thing an alert rule can watch.
//
// A closed set, like the intents and the event kinds: a condition is code in the evaluator, not a
// query language, because "alerting rules" that grow expressions grow a second place to be wrong
// about what the data means.
type AlertCondition string

// The conditions a rule can watch.
const (
	// ConditionHostSilent fires when a host has not heartbeaten for Threshold minutes.
	ConditionHostSilent AlertCondition = "host_silent"

	// ConditionSecurityUpdates fires when a host reports at least Threshold pending security updates.
	ConditionSecurityUpdates AlertCondition = "security_updates"

	// ConditionSecurityUpdatesAge fires when a host has had security updates pending for Threshold
	// days.
	//
	// The other half of the condition issue #7 names: "pending security updates > N, **or older than
	// N days**". Count and age are different questions — one host with twelve updates published this
	// morning is healthy, and one with a single update from a fortnight ago is not — and it is the
	// second that describes a machine nobody is patching.
	//
	// The age is measured from when this control plane first saw the backlog become non-empty, which
	// is what the evaluator's Since field already records. That is an honest answer rather than an
	// exact one: a host enrolled today with a month-old backlog reads as new, because nothing on the
	// wire carries when an update was published. It is stated in docs/SECURITY.md §8 rather than left
	// to be discovered.
	ConditionSecurityUpdatesAge AlertCondition = "security_updates_age"

	// ConditionRebootRequired fires when a host has needed a reboot for Threshold days.
	ConditionRebootRequired AlertCondition = "reboot_required"

	// ConditionUnitFailed routes service.failed events; the events fire with or without a rule.
	ConditionUnitFailed AlertCondition = "unit_failed"

	// ConditionJobFailed routes job.failed and job.expired events; the events fire with or without a
	// rule.
	ConditionJobFailed AlertCondition = "job_failed"
)

// Valid reports whether a condition is one of the closed set.
func (c AlertCondition) Valid() bool {
	switch c {
	case ConditionHostSilent, ConditionSecurityUpdates, ConditionSecurityUpdatesAge,
		ConditionRebootRequired, ConditionUnitFailed, ConditionJobFailed:
		return true
	default:
		return false
	}
}

// MeasuredInDays reports whether this condition's threshold is a number of days the raw condition has
// held, rather than a level the raw condition crosses.
//
// The two shapes need different arithmetic in the evaluator and different words in a summary, and they
// are the difference between "a reboot is needed" — which is Tuesday — and "a reboot has been needed
// for a fortnight", which is the thing that never gets done until it is an incident.
func (c AlertCondition) MeasuredInDays() bool {
	return c == ConditionRebootRequired || c == ConditionSecurityUpdatesAge
}

// Evaluated reports whether the evaluator drives this condition, as opposed to it only routing events
// that fire on their own.
func (c AlertCondition) Evaluated() bool {
	return c == ConditionHostSilent || c == ConditionSecurityUpdates ||
		c == ConditionSecurityUpdatesAge || c == ConditionRebootRequired
}

// AlertRule is one tenant's decision about which events are worth waking somebody for.
//
// Rules live here and not in policy.toml, deliberately: that file is the host's authority over what
// may be done to it, and an alerting rule is the control plane's business. Putting them together
// would blur the one distinction the whole design rests on.
//
// A rule produces a notification. A rule never produces a job — auto-remediation is a different
// feature with a different threat model, and it gets its own argument or it does not happen.
type AlertRule struct {
	// ID identifies the rule, generated by the control plane.
	ID string

	// Condition is what the rule watches.
	Condition AlertCondition

	// Threshold parameterises the condition: minutes silent, pending security updates, or days a
	// reboot has been outstanding. Ignored by the event-routing conditions.
	Threshold int

	// CooldownSeconds bounds how often one firing (rule, host) pair may notify again.
	//
	// Not optional in spirit: a flapping unit or a host on a bad link is simultaneously the most
	// interesting case and the noisiest, and a rule that mails every flap trains its recipients to
	// filter the folder.
	CooldownSeconds int

	// EmailTo lists the SMTP recipients for this rule, empty for none.
	//
	// The inbox, the stream and the tenant webhook receive the event regardless; mail is the one
	// delivery an operator has to opt into per rule, because it is the one that interrupts somebody.
	EmailTo []string

	// Enabled reports whether the rule is evaluated at all. Disabled rules keep their history.
	Enabled bool

	// CreatedAt is when the rule was created.
	CreatedAt time.Time

	// CreatedBy is the operator who created it.
	CreatedBy string

	// LastDeliveryAt is when this rule last attempted to mail somebody, zero for never.
	LastDeliveryAt time.Time

	// LastDeliveryError is why that attempt failed, empty when it succeeded.
	//
	// It exists because an alert that was the only thing between a fleet and an outage must not fail
	// into a log line nobody reads. The event itself is in the inbox either way; this is the record
	// of the delivery that did not happen, rendered on the rule an operator is already looking at.
	LastDeliveryError string
}

// AlertKey identifies the thing one firing is tracked under.
//
// Rule and host are the pair issue #7 asks for — "cooldown per rule per host" — and Subject is the
// dimension that pair turned out to be missing. A unit_failed rule can fire about more than one thing
// on one machine, and keying its cooldown on the host alone meant the second failing unit lost the
// claim to the first and was dropped in silence: no mail, and no record that no mail went out.
//
// It is a struct rather than three parameters because it travels through four store methods and an
// evaluator, and a triple passed positionally is a bug waiting for somebody to swap two strings.
type AlertKey struct {
	// RuleID is the rule half.
	RuleID string

	// HostID is the host half, empty for a fleet-wide digest row.
	HostID string

	// Subject narrows the key below the host: a unit name for unit_failed, and empty everywhere the
	// rule can only be about the machine as a whole.
	//
	// Empty rather than a sentinel, because that is what every row written before this existed holds
	// and what the column defaults to — a rule that is about the host keeps the key it always had.
	Subject string
}

// AlertState is the evaluator's memory of one alert key.
//
// Persisted rather than held in the process, because the two things it prevents — a re-notification
// before the cooldown, and a missing recovery event — are exactly what a restart would otherwise
// cause: a control plane deploy at 09:00 must not re-page everybody about the host that has been down
// since 03:00.
type AlertState struct {
	// AlertKey is what this state is about.
	AlertKey

	// Firing reports whether the condition held at the last evaluation.
	Firing bool

	// Since is when the condition started holding, zero when it is not.
	Since time.Time

	// LastNotified is when this pair last produced a notification, zero for never.
	LastNotified time.Time
}

// TemplateVersion is one immutable version of a provisioning template.
//
// A version, not a document: the row is written once and never updated, because Tier 2 records "this
// host was bootstrapped with standard-server v3" and that record is worthless if the row it names can
// be edited afterwards. Superseding a template means creating the next version, and every version
// stays readable for as long as a host's bootstrap record can name it.
type TemplateVersion struct {
	// Name is the identifier an operator types, shared by every version of one template.
	Name string

	// Version numbers this revision, starting at 1. Assigned by the store, never by the caller.
	Version int

	// BodySealed is the cloud-init user-data, encrypted at rest by internal/seal.
	//
	// The store holds ciphertext and only ciphertext, so that a database dump does not yield the
	// enrolment tokens and break-glass credentials operators put into template bodies. The key lives
	// beside the CA, outside the database, which is what makes the encryption mean something against
	// the backup-shaped threat docs/SECURITY.md §7 names.
	BodySealed []byte

	// Signature is a detached signature over the canonical {name, body} payload, base64, empty for an
	// unsigned version.
	//
	// It is produced offline by `hostseal sign-template`, with a key this control plane does not hold,
	// and is stored and handed over verbatim. An unsigned version can be rendered for Terraform; only a
	// signed one can be issued to an enrolling host, because the agent verifies it against the host's
	// own trusted-signers and a control plane cannot make that check pass.
	Signature string

	// SignerKeyID names the key that signed it, empty for an unsigned version.
	SignerKeyID string

	// SignerAlgorithm is "ed25519" or "ecdsa-p256", empty for an unsigned version.
	SignerAlgorithm string

	// CreatedAt is when this version was stored.
	CreatedAt time.Time

	// CreatedBy is the operator who stored it, for the audit trail.
	CreatedBy string
}

// Signed reports whether this version carries an offline signature.
//
// It is a method rather than three comparisons at each site so that "signed" means the same thing on
// the enrolment path, in the listing and in the UI — the site that checked only Signature would treat
// a version with a signature and no named key as issuable, and the record on the host would then name
// nobody.
func (t TemplateVersion) Signed() bool {
	return t.Signature != "" && t.SignerKeyID != "" && t.SignerAlgorithm != ""
}

// TemplateSummary is one template name as a listing renders it.
//
// A summary rather than the version rows, because the listing is read on every load of the templates
// page and the bodies are both sealed and potentially large; a client that wants a body names a
// version and asks for it.
type TemplateSummary struct {
	// Name is the template's identifier.
	Name string

	// LatestVersion is the highest version stored under this name.
	LatestVersion int

	// CreatedAt is when the latest version was stored.
	CreatedAt time.Time

	// CreatedBy is who stored the latest version.
	CreatedBy string

	// Signed reports whether the latest version carries an offline signature, which is what decides
	// whether an enrolling host can be issued this template at all.
	Signed bool
}

// TemplateRevision is one stored version of a template, without its body.
//
// It exists because "every save is a new immutable version" is a property an operator has to be able to
// *see*: a host's bootstrap record names a version, and a version nobody can enumerate is one nobody
// can resolve back to what ran. The body is deliberately absent — it is sealed, it is potentially
// large, and a listing that carried every revision's body would decrypt a template's whole history to
// answer "which versions are there".
type TemplateRevision struct {
	// Version is this revision's number, starting at 1.
	Version int

	// CreatedAt is when it was stored.
	CreatedAt time.Time

	// CreatedBy is who stored it.
	CreatedBy string

	// Signed reports whether this revision carries an offline signature, which is what decides whether
	// an enrolling host can be issued it at all.
	Signed bool

	// SignerKeyID names the key that signed it, empty when unsigned.
	SignerKeyID string
}

// Online reports whether the host has been heard from recently enough to be considered up.
//
// The threshold is generous relative to the heartbeat interval because a host that missed one beat is
// not down, and a fleet list that flickers red teaches its reader to ignore red.
func (h Host) Online(now time.Time, heartbeatSeconds int) bool {
	if h.LastSeen.IsZero() {
		return false
	}
	grace := time.Duration(heartbeatSeconds) * time.Second * 3
	return now.Sub(h.LastSeen) < grace
}

// Certificate is one issued agent certificate.
type Certificate struct {
	// Fingerprint is the SHA-256 of the DER certificate, lower-case hex.
	//
	// This is the revocation mechanism: every authenticated request looks the fingerprint up, and a
	// row that is absent or revoked ends the request. No CRL, no OCSP, no distribution delay.
	Fingerprint string

	// HostID is the host this certificate identifies.
	HostID string

	// TenantID is the tenant that host belongs to.
	//
	// It is carried here because this lookup is where an agent request finds out which tenant it is:
	// the certificate is presented before anything else is known, and everything the request goes on to
	// touch is scoped by the answer. Storing it on the row rather than joining to hosts also means the
	// composite foreign key can refuse a certificate that claims one tenant and points at another's
	// host, which is the exact shape of a successful cross-tenant write.
	TenantID TenantID

	// Serial is the certificate serial, hex, for correlating with logs.
	Serial string

	// IssuedAt and NotAfter bound its validity.
	IssuedAt time.Time
	NotAfter time.Time

	// Revoked reports that this certificate is no longer accepted.
	Revoked bool

	// RevokedAt is when it was revoked, zero if it was not.
	RevokedAt time.Time

	// SupersededAt is when a renewal's replacement takes over, zero if this certificate is current.
	//
	// It is distinct from Revoked because the two say different things and an operator reading a host's
	// history needs to tell them apart: revoked is somebody withdrawing a host's identity, and
	// superseded is the ordinary end of a certificate that has been renewed. The value is a short
	// overlap after the renewal rather than the renewal itself, because the agent promotes its new
	// credential with one rename and a host interrupted between the two has to be able to come back on
	// the old one.
	SupersededAt time.Time
}

// Renewal is everything one certificate renewal writes, so it can be written at once.
//
// It is a struct rather than five arguments because the fields have to travel together: a caller that
// could pass a replacement without a fingerprint to retire, or a cap without a clock to measure it
// against, would be a caller that could half-perform the operation this type exists to make whole.
type Renewal struct {
	// Replacement is the certificate to record.
	Replacement Certificate

	// Presented is the fingerprint of the certificate that asked for the renewal.
	//
	// It comes from the connection and never from the request body. Taking it from anything the caller
	// sent would let one host retire a certificate belonging to another.
	Presented string

	// SupersedeAt is when the presented certificate stops being accepted.
	//
	// A short overlap after the renewal rather than the renewal itself: the agent promotes its new
	// credential with one rename, and a host interrupted between obtaining a certificate and promoting
	// it has to be able to come back on the old one.
	SupersedeAt time.Time

	// MaxLive is how many of the host's certificates may authenticate at once, counted before insert.
	MaxLive int

	// Now is the instant liveness is measured against, so the decision is the caller's clock and not
	// the database's.
	Now time.Time
}

// Account is one person who signs in, with an address and a password.
//
// It exists because operators were one shared bearer token, which made the audit trail name nobody and
// made second-person approval unsatisfiable: that rule compares the approver's principal against the
// job's creator, and under one credential those two strings are always equal.
//
// An account belongs to a fleet exactly as a host does — or to none at all, which is what makes it the
// installation's own administrator rather than a customer's operator. The two kinds are one table so
// that "an address identifies exactly one account" is a constraint the database states rather than a
// rule two tables would have to be remembered to agree on.
type Account struct {
	// ID is the control plane's identifier for this account.
	ID string

	// TenantID is the fleet this operator acts in, empty for a platform administrator.
	//
	// Carried on the record for the same reason Certificate carries one: resolving an address to an
	// account happens before any tenant is known, and the answer is what scopes the rest of the
	// request. Empty is not a missing value — it is the whole of what makes an account a platform one.
	TenantID TenantID

	// Email is the address as it was entered, for display and for the audit log.
	Email string

	// EmailKey is the SHA-256 of the normalised address, which is what the row is found by.
	//
	// Separate from Email so that the lookup names one row through the same session setting the
	// certificate and enrolment-token resolvers use, rather than introducing a second shape of key for
	// the policy to admit.
	EmailKey string

	// DisplayName is what to call this person in the interface, empty for the address.
	DisplayName string

	// PasswordHash is the Argon2id PHC string. The password itself is never stored.
	PasswordHash string

	// CreatedAt is when the account was made.
	CreatedAt time.Time

	// LastSignedInAt is when it last signed in, zero for never.
	LastSignedInAt time.Time
}

// Session is one signed-in browser.
//
// It exists because a browser cannot hold a password: signing in exchanges one for an opaque token
// this process generated, and only the token's SHA-256 is stored — the same discipline as an enrolment
// token, and correct here for the same reason, which is that the input is uniform randomness rather
// than something a person chose.
//
// It carries no tenant. A session belongs to the account that created it and the account is the single
// source of truth for which side of the tenant boundary it sits on; a tenant on this row would be a
// second copy of that answer, and the failure it invites — a session claiming one fleet while naming
// another's account — is one nothing would refuse.
type Session struct {
	// TokenHash is the SHA-256 of the session token. The token itself is never stored.
	TokenHash string

	// AccountID is whose session it is.
	AccountID string

	// CreatedAt is when the operator signed in.
	CreatedAt time.Time

	// ExpiresAt is when the session stops authenticating anybody.
	//
	// It moves. A session that is being used is extended, so that a working day is not interrupted by
	// one; a session that is not is left to run out. See SessionMaxAge for the bound that stops the
	// extension being indefinite.
	ExpiresAt time.Time

	// LastUsedAt is when a request last presented it, zero for never.
	LastUsedAt time.Time

	// UserAgent and Source are what the browser called itself and where the request came from.
	//
	// Advisory and clearly so: a user agent is a string the client chooses, and behind a proxy the
	// address is the proxy's. They exist because "that one is not me" is a judgement somebody makes
	// from weak evidence or not at all, and the alternative is a list of six sessions that are all
	// just "a session".
	UserAgent string
	Source    string
}

// Valid reports whether a session still authenticates at the given instant.
//
// Against the caller's clock rather than the database's, matching every other validity window in
// HostSeal: docs/SECURITY.md treats clock skew as a boundary, and a credential that outlived its window
// because two machines disagreed would be the least visible way for that to matter.
func (s Session) Valid(now time.Time) bool { return now.Before(s.ExpiresAt) }

// APIToken is a credential belonging to one account, for the scripts a password cannot serve.
//
// It is a bearer token, and that is not a contradiction with having removed the other one. What was
// wrong with a shared admin token was not the word "bearer": it was one credential for a whole fleet,
// held in a flag, naming nobody in the audit trail, never expiring, and withdrawable only by restarting
// the control plane and telling everybody. This one belongs to a person, acts as that person, expires,
// and is revoked from a page in a second.
type APIToken struct {
	// Hash is the SHA-256 of the token as issued. The token itself is never stored.
	Hash string

	// AccountID is whose token it is, and therefore who its actions are recorded against.
	AccountID string

	// Label is what the operator called it, so that revoking the right one is possible.
	Label string

	// CreatedAt is when it was issued.
	CreatedAt time.Time

	// ExpiresAt is when it stops working, zero for never.
	ExpiresAt time.Time

	// LastUsedAt is when a request last presented it, zero for never.
	LastUsedAt time.Time
}

// Usable reports whether a token may still be presented at the given instant.
//
// A zero expiry means no expiry, which is a decision somebody made rather than a missing value — see
// migration 0010 for why that is nullable rather than a far-future date.
func (t APIToken) Usable(now time.Time) bool {
	return t.ExpiresAt.IsZero() || now.Before(t.ExpiresAt)
}

// WallboardShare is a link that publishes one screen of a fleet's own state to whoever holds it.
//
// It is a bearer credential in a URL, which is the thing docs/SECURITY.md §4.5 removed for operators,
// so it is worth stating exactly what is different. That one was a write credential for the whole
// administrative API, held for ever, by everybody, naming nobody. This one reaches a single fixed-shape
// summary of a single fleet, expires on a date somebody chose, is withdrawn by deleting a row, and
// records who published it. What it does not and cannot record is who reads it — see §4.6, which says
// so rather than implying otherwise.
//
// The secret is not here, only its digest. The link is shown once, at creation, exactly as an enrolment
// token and an API token are, so that a database dump is not a set of live wallboards.
type WallboardShare struct {
	// ID names the share in the interface and in the route that withdraws it.
	//
	// Separate from the secret because an operator has to be able to revoke a link without holding it:
	// the secret is shown once and then exists only on a television.
	ID string

	// SecretHash is the SHA-256 of the whole key, including the tenant segment it carries.
	//
	// The whole key rather than its secret half, which is what makes the tenant segment load-bearing
	// rather than decorative: a key edited to name another fleet digests to a value no row holds, so
	// the tenant is refused by the lookup before the policy is reached.
	SecretHash string

	// PasswordHash is Argon2id in PHC string format, empty for a share with no passphrase.
	//
	// Empty rather than absent, matching Account.PasswordHash, so that "no passphrase" has one
	// representation instead of two.
	PasswordHash string

	// Label is what the operator called it, and the heading the published screen shows.
	//
	// Required rather than defaulted: a list of four shares called "share" is a list nobody revokes
	// from, and a screen whose heading is blank tells the room nothing about which fleet it is showing.
	Label string

	// CreatedAt is when it was published.
	CreatedAt time.Time

	// CreatedBy is the principal of whoever published it.
	//
	// The one name attached to a share, and the one that matters: a share names no reader, so the
	// question it can answer is who decided this fleet could be published.
	CreatedBy string

	// ExpiresAt is when it stops answering.
	//
	// Never zero. A share that never expires is the credential §4.5 removed wearing a different name,
	// so the absence of a "never" option is the point rather than an omission.
	ExpiresAt time.Time

	// LastSeenAt is when a screen last polled it, zero for never.
	LastSeenAt time.Time
}

// Live reports whether a share may still answer at the given instant.
//
// Written here so that the memory store, the listing and the tests all mean the same thing by it. The
// PostgreSQL lookup does not call it — its predicate is in the SQL, which is what keeps an unknown
// secret and an expired share one code path — and TestAShareIsLiveByTheSameRuleInBothStores pins the
// two together.
func (s WallboardShare) Live(now time.Time) bool {
	return now.Before(s.ExpiresAt)
}

// MaxWallboardSharesPerTenant bounds how many live links one fleet may have published at once.
//
// Twenty. An unbounded set of live public credentials is an unbounded set of things to revoke, and the
// number is chosen so that the list stays something an operator can read on one screen and recognise
// every entry of — which is the property that makes "there is a share here I do not remember" a thing
// somebody notices.
const MaxWallboardSharesPerTenant = 20

// HeartbeatUpdate is what one heartbeat changes about a host.
//
// It is a separate struct from Host so that a heartbeat cannot accidentally overwrite fields it does
// not carry — enrolment time, group, the stored facts document — by writing a zero value over them.
type HeartbeatUpdate struct {
	// AgentVersion is the build the host reported.
	AgentVersion string

	// BootID identifies the host's current boot.
	BootID string

	// UptimeSeconds is what the host reported.
	UptimeSeconds int64

	// ClockOffsetSeconds is the host's own measurement.
	ClockOffsetSeconds int64

	// Paused reports the host's kill-switch state.
	Paused bool

	// LastSeen is the server's clock reading for this heartbeat.
	LastSeen time.Time
}

// Note that a heartbeat deliberately carries no digests.
//
// The digest columns on a host record what the *server holds*, and are written only by StoreFacts,
// StorePolicy and StoreSigners — that is, only when a document actually arrives. Recording the digest a
// host claimed would make the server believe it held a document it had never received: it would ask
// once, and if that one full report were lost to a network failure it would compare the next heartbeat
// against the claim it had stored, conclude it was up to date, and never ask again.

// NewJob is a job as the control plane creates it.
//
// It is a separate type from protocol.Job because the two answer different questions. protocol.Job is
// what goes on the wire to a host and carries only what the host needs; this carries what the control
// plane must remember about the decision to issue it — who asked, and whether a second person still
// has to agree.
type NewJob struct {
	// Job is what the host will receive, unchanged.
	Job protocol.Job

	// HostID is the host it is issued to.
	HostID string

	// CreatedBy is the operator identity that asked for it, for the audit trail.
	//
	// It is recorded even though the guarantee does not rest on it. A compromised administrator account
	// is inside the threat model by construction; what this protects is the ability to answer "who
	// asked for this reboot" afterwards, which is a different and still necessary thing.
	CreatedBy string

	// ApprovalRequired reports whether somebody must release this job before a host may claim it.
	//
	// It comes from the tenant's approval mode and the intent's class, and it is a field rather than
	// something derived on read so that the row records the rule as it stood when the job was created.
	// Two different changes would otherwise rewrite history: a later build that classified an intent
	// differently, and — since the rule became a tenant setting — an operator who relaxed the setting
	// after queueing the job.
	ApprovalRequired bool

	// ApprovalDistinctOperator reports whether the release must come from somebody other than CreatedBy.
	//
	// Separate from ApprovalRequired because they are separate questions, and a tenant answers them
	// separately: "somebody must deliberately release this" is worth having in an installation with one
	// operator, where "somebody else must" would be a requirement nobody could meet.
	ApprovalDistinctOperator bool
}

// JobRecord is one job as the control plane holds it, with its result if one has arrived.
type JobRecord struct {
	// Job is what the host receives.
	Job protocol.Job

	// HostID is the host it was issued to.
	HostID string

	// CreatedAt is when the control plane created it.
	CreatedAt time.Time

	// CreatedBy is the operator who asked for it.
	CreatedBy string

	// ApprovalRequired reports whether somebody had to release it.
	ApprovalRequired bool

	// ApprovalDistinctOperator reports whether that somebody had to be other than its creator.
	//
	// Carried out of the store so that a client can say which rule this job was created under, rather
	// than reporting the tenant's current setting beside a job the setting no longer governs.
	ApprovalDistinctOperator bool

	// ApprovedAt is when it was released, zero if it has not been.
	ApprovedAt time.Time

	// ApprovedBy is who released it, empty if nobody has.
	ApprovedBy string

	// ClaimedAt is when a host took it, zero if none has.
	ClaimedAt time.Time

	// CompletedAt is when a result arrived, zero if none has.
	CompletedAt time.Time

	// Result is what the host reported, nil until it does.
	Result *protocol.ResultRequest
}

// AwaitingApproval reports whether this job is waiting for somebody to release it.
//
// It exists so that the two store implementations, the API's state word and the partial index in
// migration 0004 all mean the same thing by "awaiting approval". The predicate is small enough to write
// out at each site and that is exactly the problem: the copy somebody forgets to update is the one that
// decides whether a destructive job appears on the page a second operator is reading.
func (r JobRecord) AwaitingApproval() bool {
	return r.ApprovalRequired && r.ApprovedAt.IsZero()
}

// Claimable reports whether a host may take this job now.
//
// It exists so that the API and the UI answer the question the same way the claim query does, rather
// than each deciding for itself what "waiting" means and disagreeing on the one row where it matters.
func (r JobRecord) Claimable() bool {
	if !r.ClaimedAt.IsZero() || !r.CompletedAt.IsZero() {
		return false
	}
	return !r.AwaitingApproval()
}

// JobFilter narrows a job listing.
type JobFilter struct {
	// HostID limits the listing to one host, empty for the whole fleet.
	HostID string

	// Limit bounds how many are returned, newest first. Zero takes DefaultJobLimit.
	Limit int

	// AwaitingApproval narrows the listing to jobs that require a second operator and have not had
	// one.
	//
	// It exists because those are the only jobs whose visibility is load-bearing. Everything else in
	// the list is history, and history that scrolls off the end is a nuisance; a destructive job that
	// scrolls off the end before anybody approved it is docs/SECURITY.md §3 failing quietly, because
	// the second person the mechanism depends on can no longer find the thing to look at.
	AwaitingApproval bool
}

// DefaultJobLimit is how many jobs a listing returns when the caller does not say.
//
// A screenful with room to scroll. It is small on purpose: the list is read on every page load and the
// rows carry parameter objects and result output.
const DefaultJobLimit = 100

// MaxJobLimit is the largest listing a caller may ask for.
//
// A ceiling rather than no ceiling, because one query that asks for everything is how a control plane
// with a year of history becomes a control plane that times out. A caller that needs more than this
// wants the awaiting-approval filter or a per-host listing, both of which are cheaper and are what the
// question behind the request usually is.
const MaxJobLimit = 500

// TenantID identifies one tenant: one isolated fleet, with its own hosts, its own operators and its
// own settings.
//
// It is a defined type rather than a string so that a host id, a job id or an operator subject cannot
// be passed where a tenant belongs. Every one of those is also a bare identifier, and the compiler is
// the only reader that will reliably notice.
type TenantID string

// ApprovalMode is how one tenant releases a destructive job.
//
// It is a property of the tenant rather than of the installation because a control plane that serves a
// one-person shop and a regulated customer at the same time cannot answer the question once for both.
// See docs/SECURITY.md §3.
type ApprovalMode string

// The three ways a tenant can answer "who has to agree before a host may claim this".
const (
	// ApprovalNone releases a destructive job as soon as it is created.
	//
	// The offline signature is then the whole of the control-plane-side authorisation, which is also
	// the only part the guarantee in docs/SECURITY.md §1 rests on: the key is one this control plane
	// does not hold, and the host verifies it against its own trust anchor. This is the default.
	ApprovalNone ApprovalMode = "none"

	// ApprovalSelf requires somebody to release the job, and lets that be whoever created it.
	//
	// It buys the deliberate second act and an audit row naming who took it, in an installation with
	// one operator where requiring a second person would mean requiring the impossible.
	ApprovalSelf ApprovalMode = "self"

	// ApprovalSecondPerson requires somebody other than the creator to release the job.
	ApprovalSecondPerson ApprovalMode = "second_person"
)

// Valid reports whether a mode is one of the three.
//
// Checked on the way in rather than trusted, because the column has the same CHECK constraint and a
// value that fails it would surface as a database error at the moment somebody was configuring their
// tenant.
func (m ApprovalMode) Valid() bool {
	switch m {
	case ApprovalNone, ApprovalSelf, ApprovalSecondPerson:
		return true
	default:
		return false
	}
}

// RequiresApproval reports whether a destructive job under this mode waits for a release.
func (m ApprovalMode) RequiresApproval() bool { return m == ApprovalSelf || m == ApprovalSecondPerson }

// RequiresDistinctOperator reports whether the release must come from somebody other than the creator.
func (m ApprovalMode) RequiresDistinctOperator() bool { return m == ApprovalSecondPerson }

// Tenant is one isolated fleet.
type Tenant struct {
	// ID is the identifier every scoped row carries.
	ID TenantID

	// Slug is a short stable handle for URLs, logs and support tickets.
	//
	// Separate from DisplayName because a customer renaming themselves must not change the identifier
	// everything else refers to.
	Slug string

	// DisplayName is what the tenant is called in the interface.
	DisplayName string

	// CreatedAt is when the tenant was created.
	CreatedAt time.Time

	// ApprovalMode is how this tenant releases a destructive job.
	ApprovalMode ApprovalMode

	// WebhookURL is where this tenant's events are posted, empty for nowhere.
	//
	// It belongs to the tenant rather than to the process because the alternative was not a missing
	// feature but a leak: one list of sinks for the whole installation delivers one customer's
	// hostnames and operator names to another customer's endpoint.
	WebhookURL string

	// HostLimit is how many hosts may be enrolled into this fleet, or nil for no limit.
	//
	// A pointer rather than an int, because zero is a limit somebody means — a fleet that may hold no
	// hosts yet — and "no limit" has to be a different value from "none allowed". Every installation
	// that is not selling this leaves it nil, which is what `hostseal-server serve` creates.
	//
	// It gates enrolment and nothing else. Lowering it below a fleet's current size revokes nothing and
	// reaches no machine: the hosts that are enrolled stay enrolled, and the next machine to present a
	// token is refused. A setting that could take a running host away from its operator would be a
	// lever on an enrolled host, which is the one thing this control plane does not build.
	HostLimit *int

	// Suspended is whether the control plane refuses this fleet's agent requests.
	//
	// It is refusal rather than reach: a suspended fleet's agents keep running, keep applying the
	// host's own local policy and keep installing security updates on their own timer, exactly as they
	// do when the control plane is unreachable for any other reason. Nothing is uninstalled and nothing
	// is deleted.
	Suspended bool
}

// TenantPatch is the subset of a tenant's settings a caller is changing.
//
// A pointer per field, because "leave this alone" and "set this to its zero value" are different
// requests and a plain struct cannot tell them apart: an empty display name, an empty webhook URL and
// `suspended = false` are all things somebody legitimately asks for.
//
// It exists so that a tenant update is one statement rather than a read, a change and a write. The
// read-modify-write it replaced lost concurrent edits by construction — each caller wrote back every
// field from the row it had read, so whichever committed last silently restored the other's stale
// values. With the hosting layer setting the host limit and the suspension through two separate
// requests, that was a fleet coming out of suspension because somebody renamed it at the wrong moment.
type TenantPatch struct {
	// DisplayName, ApprovalMode and WebhookURL are written when non-nil.
	DisplayName  *string
	ApprovalMode *ApprovalMode
	WebhookURL   *string

	// HostLimit needs two fields rather than one, because nil is a value here: it means "no limit".
	// SetHostLimit is what says the caller is writing the column at all.
	HostLimit    *int
	SetHostLimit bool

	// Suspended is written when non-nil.
	Suspended *bool
}

// HostCounts is how large a fleet is, and nothing else about it.
//
// It exists so that the platform role can be told a number without being given a fleet. Whoever runs an
// installation for other people has to be able to count what they are charging for; letting them read
// a host list to do it would mean hostnames, facts and jobs for a question whose answer is an integer.
type HostCounts struct {
	// Total is every host row this fleet holds, revoked ones included.
	Total int

	// Active is the hosts whose certificates the control plane still accepts.
	//
	// This is the number a host limit is checked against and the number a hosting provider bills for.
	// A revoked host keeps its row for the audit trail and stops counting the moment it is revoked.
	Active int
}

// Store is the control plane's persistence.
//
// Every method takes a context because every one of them can be waiting on a database that has stopped
// answering, and a control plane that cannot shed a stuck query is a control plane a single slow host
// can take down.
//
// What is on *this* interface rather than on Scoped is the complete list of operations that are not
// scoped to a tenant, and it is short on purpose. Two of them are the lookups that *discover* which
// tenant a caller belongs to, so they cannot be behind a gate that requires already knowing the answer;
// the rest administer tenants themselves, or belong to no tenant at all. Everything that touches a
// tenant's data is on Scoped and is unreachable without naming a tenant — see In.
type Store interface {
	// Migrate brings the schema up to date. It is safe to call on every start.
	Migrate(ctx context.Context) error

	// In returns everything an operator or an agent can reach, scoped to one tenant.
	//
	// This is the whole isolation design in one method. A tenant-scoped operation is not a method you
	// remember to pass a tenant to; it is a method you cannot reach without one, and in PostgreSQL the
	// returned handle runs every statement inside a transaction that has set the tenant, so
	// row-level security refuses a row from anywhere else even if the statement's own WHERE clause
	// forgot to.
	In(tenant TenantID) Scoped

	// LookupCertificate returns a certificate by fingerprint, or ErrNotFound.
	//
	// This is called on every authenticated agent request, it is the revocation check, and it is how an
	// agent request finds out which tenant it belongs to — which is why it is here and not on Scoped.
	// The fingerprint is the SHA-256 of a certificate this CA issued, so naming one is not a way of
	// discovering another.
	LookupCertificate(ctx context.Context, fingerprint string) (Certificate, error)

	// TenantForEnrollmentToken returns the tenant a token belongs to, or ErrTokenUnusable.
	//
	// Enrolment needs the tenant before it has anything else: the machine-id check is per tenant, and a
	// token is how a new machine joins one. It deliberately returns nothing but the tenant, and it does
	// not consume the token — a host retrying an enrolment it has already completed must not burn a
	// second token in the course of being told no.
	TenantForEnrollmentToken(ctx context.Context, hash string) (TenantID, error)

	// Platform returns the accounts of the installation's own administrators.
	//
	// The counterpart to In(tenant), and it exists for the same reason: which side of the tenant
	// boundary an operation is on is not a flag a caller remembers to pass, it is a handle they cannot
	// obtain without saying. A platform account carries no tenant, so it is unreachable from any
	// In(tenant) handle — `NULL = 'anything'` is NULL and not true — and this is the only door to it.
	//
	// It returns the same interface In(tenant) satisfies for accounts, so nothing above this layer has
	// to know which kind it is holding. That is what lets the sign-in path be one path.
	Platform() AccountScope

	// AccountByEmail returns the account an address names, or ErrNotFound.
	//
	// Here rather than behind a handle because it is the third of the lookups that must happen before
	// the caller's side of the boundary is known: a sign-in form names an address and nothing else, and
	// finding the row is how the fleet — or the absence of one — is discovered.
	//
	// Unlike the certificate and token resolvers, the key here is guessable: an address is not a
	// secret. The refusal that keeps that from being a disclosure lives in the endpoint above this
	// method, which answers an unknown address and a wrong password identically; migration 0010 says so
	// at the policy, and this comment says so at the method, because the two have to stay true together.
	AccountByEmail(ctx context.Context, emailKey string) (Account, error)

	// SessionByToken returns a session and the account it belongs to, or ErrNotFound.
	//
	// The fourth pre-tenant lookup, and the closest analogue to LookupCertificate: it runs on every
	// request a signed-in browser makes, and what it returns is what scopes everything after it. It
	// answers both halves because they are one question — "who is this request" — and because the
	// account id that answers the second half is produced by the first: splitting them would mean a
	// second transaction naming a key the first one had just found.
	//
	// Expiry is not checked here. The caller checks it against its own clock, for the reason
	// Session.Valid gives.
	SessionByToken(ctx context.Context, tokenHash string) (Session, Account, error)

	// APITokenByHash returns a token and the account it belongs to, or ErrNotFound.
	//
	// The fifth, and the same shape as the fourth: a script presents a token, and the row is where the
	// request finds out whose it is. Usability is left to the caller for the reason expiry is.
	APITokenByHash(ctx context.Context, hash string) (APIToken, Account, error)

	// CreateTenant records a new tenant.
	CreateTenant(ctx context.Context, t Tenant) error

	// GetTenant returns one tenant, or ErrNotFound.
	GetTenant(ctx context.Context, id TenantID) (Tenant, error)

	// ListTenants returns every tenant, oldest first.
	ListTenants(ctx context.Context) ([]Tenant, error)

	// UpdateTenant applies a tenant's display name, approval mode and webhook.
	//
	// The slug is not among them. It is what logs, support tickets and any external system refer to a
	// tenant by, so a rename would leave every one of those pointing at a name that no longer answers.
	//
	// Changing the approval mode affects jobs created afterwards and nothing already queued. That is
	// deliberate and it is the same rule migration 0002 wrote down for approval_required: a job records
	// what it required, so relaxing the setting cannot release work that was queued under a stricter
	// one.
	//
	// It takes a patch rather than a whole tenant because a whole tenant is a lost update waiting to
	// happen: two callers that each read the row, change one field and write all of them will each
	// restore the other's stale values. That is not hypothetical here — the hosting layer sets the host
	// limit and the suspension in two separate requests, so an administrator editing the approval mode
	// in between could put a suspended fleet back into service. Only the fields the patch carries are
	// written, in one statement, so there is no window between the read and the write to lose.
	UpdateTenant(ctx context.Context, id TenantID, patch TenantPatch) (Tenant, error)

	// DeleteTenant removes a tenant and everything belonging to it.
	DeleteTenant(ctx context.Context, id TenantID) error

	// Subscribe registers interest in work for a host and returns a channel closed when some arrives.
	//
	// It is deliberately separate from claiming, and the caller must subscribe *before* it looks at the
	// queue. Doing it the other way round leaves a gap: a job inserted between the empty read and the
	// subscription fires its notification with nobody listening, and the agent then holds a long-poll
	// for its full duration over work that was already waiting. The gap is small and the consequence is
	// only latency, which is exactly why it would never be diagnosed.
	//
	// This is what makes the long-poll a long-poll rather than a sleep. In PostgreSQL it is LISTEN on a
	// channel the job insert NOTIFYs, which is why HostSeal needs no Redis. The channel may be closed
	// spuriously — the caller re-checks the queue — but a wake-up must not be missed indefinitely.
	//
	// It is not tenant-scoped, and that is a decision rather than an omission. A wake-up carries no
	// data — a waiter is either closed or it is not — and it is keyed on a host id, which is 128 bits
	// of randomness generated here. Scoping it would mean one LISTEN connection per tenant, which is
	// the resource problem the single fan-out connection exists to avoid, and with hosting the tenant
	// count is the number that grows. What somebody who guessed a host id could learn is that work
	// arrived for it; the work itself is behind the claim, which is scoped.
	//
	// The returned function releases the subscription and must always be called, or a fleet whose
	// agents reconnect every twenty-five seconds accumulates one dead waiter per poll.
	Subscribe(hostID string) (<-chan struct{}, func())

	// Ping reports whether the database is reachable, and reads nothing.
	//
	// It exists because the health endpoint is unauthenticated, and the query behind it used to be a
	// tenant listing: one row per fleet, read in full, on every hit from anybody who could reach the
	// port. That is a load an unauthenticated caller chooses for the shared database, and it answers a
	// question nobody asked — liveness is whether a round trip completes, not what the rows say.
	//
	// It carries no tenant for the same reason it reads nothing: there is no fleet whose health this
	// is, and a probe that named one would be answering about that fleet rather than about the process.
	Ping(ctx context.Context) error

	// Close releases the store's resources.
	Close() error
}

// Scoped is every operation that touches one tenant's data.
//
// It is a separate interface rather than a tenant argument on twenty-four methods because the two fail
// differently. An argument is something a caller can pass wrongly and a reviewer has to notice; a
// handle is something a caller cannot obtain without saying whose data they are asking for. The
// PostgreSQL implementation then sets that tenant on the transaction, so the database refuses rows
// from anywhere else — the predicate in each statement is the optimisation, and the policy is the rule.
type Scoped interface {
	// AccountScope is every operation on this tenant's operator accounts and their credentials.
	//
	// Embedded rather than repeated because the platform side needs exactly the same set and gets it
	// from Store.Platform(), so the sign-in path can be written once against whichever handle a
	// credential resolved to.
	AccountScope

	// Tenant reports whose data this handle reaches, for logs and for assertions.
	Tenant() TenantID

	// CreateEnrollmentToken records a new token by its hash.
	CreateEnrollmentToken(ctx context.Context, t EnrollmentToken) error

	// ConsumeEnrollmentToken atomically redeems a token, or reports ErrTokenUnusable.
	//
	// Atomicity is the whole point: two agents presenting the same token in the same instant must not
	// both enrol, and checking-then-updating in the handler would let them.
	ConsumeEnrollmentToken(ctx context.Context, hash, hostID string, now time.Time) (EnrollmentToken, error)

	// ListEnrollmentTokens returns this tenant's tokens for the UI, newest first.
	ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error)

	// GetEnrollmentToken returns one token by hash without consuming it, or ErrTokenUnusable.
	//
	// It exists for the one read enrolment must make between resolving a token and redeeming it:
	// whether the token authorises the bootstrap template the agent asked for. That check has to come
	// before consumption — a refusal that burnt the token would leave the operator retrying with a
	// credential that now really is unusable, which reads exactly like the token having been stolen.
	// Unknown, expired and consumed are one error here for the same reason they are everywhere else.
	GetEnrollmentToken(ctx context.Context, hash string) (EnrollmentToken, error)

	// CreateEnrolledHost records a newly enrolled host and its first certificate together, if the
	// fleet's host limit leaves room. It answers ErrHostLimitReached when it does not.
	//
	// The two writes are one operation because half of it is worse than neither. A host row without its
	// certificate is a machine that cannot authenticate and, because its machine-id hash is taken,
	// cannot enrol again either — permanently stuck on a failure that happened once, in a fraction of a
	// second, on the server.
	//
	// The limit is enforced *here*, inside that same transaction, rather than being left to the caller.
	// A caller can only count and then write, and between those two statements another enrolment fits:
	// two machines presenting two valid tokens into a fleet with one slot left both see room and both
	// take it. Autoscaling and batch provisioning make that the ordinary case rather than the unlucky
	// one. The limit read here is the one current at the moment of the write, so raising a limit takes
	// effect immediately and lowering one still revokes nothing.
	CreateEnrolledHost(ctx context.Context, h Host, c Certificate) error

	// GetHost returns one host by id, or ErrNotFound.
	GetHost(ctx context.Context, id string) (Host, error)

	// GetHostByMachineID returns the live host with a machine-id hash, or ErrNotFound.
	//
	// Revoked hosts are excluded, which is what makes a revoked machine able to enrol again. Its old row
	// stays for the audit trail; what it loses is its claim on the machine id.
	//
	// The claim is per tenant. Across the installation it would be an oracle: enrolling a machine that
	// belongs to somebody else would tell you that it belongs to somebody else.
	GetHostByMachineID(ctx context.Context, hash string) (Host, error)

	// ListHosts returns every host in this tenant, ordered by hostname.
	ListHosts(ctx context.Context) ([]Host, error)

	// CountHosts returns how many hosts this tenant has, without returning any of them.
	//
	// A separate method rather than len(ListHosts(...)) for two reasons that are not about speed. The
	// platform API answers a usage question with it, and a method that returns two integers cannot be
	// made to leak a hostname by a later refactor; and the enrolment path calls it on every enrolment
	// into a limited fleet, where loading a fleet to count it would be work proportional to the fleet
	// for an answer that is not.
	CountHosts(ctx context.Context) (HostCounts, error)

	// RecordHeartbeat applies a heartbeat's fields to a host.
	RecordHeartbeat(ctx context.Context, hostID string, u HeartbeatUpdate) error

	// StoreFacts records a full facts document and its digest.
	StoreFacts(ctx context.Context, hostID, digest string, document []byte) error

	// StorePolicy records a host's effective policy and its digest.
	StorePolicy(ctx context.Context, hostID, digest string, document []byte) error

	// StoreSigners records a host's trusted key identities and their digest.
	StoreSigners(ctx context.Context, hostID, digest string, document []byte) error

	// AddCertificate records an issued certificate by fingerprint.
	AddCertificate(ctx context.Context, c Certificate) error

	// SupersedeCertificate sets when a renewed-away certificate stops being accepted.
	//
	// Setting it again on an already-superseded certificate keeps the earlier time. A host that renews
	// twice in quick succession must not be able to extend the life of the credential it has already
	// replaced.
	//
	// The renewal path does not use this; it uses RenewCertificate, which does the same thing in the
	// transaction that records the replacement. This stays for the operations that retire a certificate
	// on its own — and for tests, which is the only caller today.
	SupersedeCertificate(ctx context.Context, fingerprint string, at time.Time) error

	// RenewCertificate admits a replacement certificate and retires the one that asked for it.
	//
	// One operation rather than three, and every part of that is load-bearing.
	//
	// The cap is checked and the replacement inserted in the same transaction, under a lock on the
	// host. Counting and then inserting in two transactions is check-then-act: the renewal limiter
	// permits a burst, so several requests for one host can each observe a count below the cap and
	// each insert — leaving more live certificates than the cap advertises, after which honest
	// renewals are refused until the extra ones expire.
	//
	// The supersession is in the same transaction for a sharper reason. If the replacement were
	// recorded and the retirement failed, no later renewal could correct it: a renewal retires the
	// fingerprint *it* presents, which by then is the replacement, and the forgotten certificate would
	// stay valid to its natural expiry — which is the whole of what the 48-hour bound exists to
	// prevent. Either both writes land or neither does, and the caller must not acknowledge a renewal
	// it did not get.
	//
	// It returns ErrTooManyCertificates when the host is at the cap, which the caller answers 429: the
	// certificates in the way are superseded or expiring, so it clears on its own.
	RenewCertificate(ctx context.Context, r Renewal) error

	// CountLiveCertificates returns how many of a host's certificates could still authenticate.
	//
	// Live means not revoked, not expired, and not past a supersession that has taken effect — the same
	// three conditions requireAgent applies, asked as a count rather than about one row. It exists for
	// the cap on renewals: without one, a host holding a valid certificate can mint rows in a table
	// every tenant shares, and the CA will sign each of them.
	CountLiveCertificates(ctx context.Context, hostID string, now time.Time) (int, error)

	// RevokeHost marks a host and all its certificates as revoked, taking effect on the next request.
	RevokeHost(ctx context.Context, hostID string) error

	// DeleteHost removes a host and everything that references it.
	//
	// Revocation is the ordinary answer and this is not a substitute for it: a revoked host keeps its
	// history, which is what an audit needs. Deletion exists for the row that should never have been
	// there — an enrolment abandoned midway, a test host, a machine that has been decommissioned and
	// whose facts nobody will ever read again.
	DeleteHost(ctx context.Context, hostID string) error

	// CreateJob records a job for a host and wakes any long-poll waiting for it.
	//
	// It returns ErrConflict when the job id is already taken in this tenant, or when a signed job's
	// nonce has already been queued for that host. The host refuses a replayed nonce itself and that is
	// the check the guarantee rests on; this one is earlier and cheaper, because a job queued twice is
	// delivered twice, refused on the host, and reported as a failure nobody can explain.
	CreateJob(ctx context.Context, j NewJob) error

	// ApproveJob records an operator's release of a job, making it claimable.
	//
	// Whether the approver may be the job's creator is recorded on the job row at creation, from the
	// tenant's approval mode, and is enforced *here* rather than only in the handler — because it must
	// hold against two requests arriving at once. A read-then-write in the caller would let the same
	// operator approve their own job by racing it against itself, which is the one way this check could
	// be defeated by someone who already has the credential.
	//
	// It returns ErrNotFound for a job that does not exist, and ErrConflict for one that needs no
	// approval, already has it, or would be released by whoever created it under a mode that forbids
	// that.
	ApproveJob(ctx context.Context, jobID, approver string, now time.Time) error

	// ListJobs returns jobs newest first, with their results.
	ListJobs(ctx context.Context, f JobFilter) ([]JobRecord, error)

	// GetJob returns one job and its result, or ErrNotFound.
	GetJob(ctx context.Context, jobID string) (JobRecord, error)

	// ClaimJobs atomically takes up to limit jobs for a host.
	//
	// Atomic claiming is what lets a control plane run more than one replica. In PostgreSQL it is
	// SELECT … FOR UPDATE SKIP LOCKED against a partial index; the interface says nothing about that,
	// but the guarantee it makes — a job is delivered to one agent, once — is the one callers rely on.
	//
	// A job still waiting to be released is never returned. That check belongs here rather than in the
	// handler: the handler is not the only thing that will ever claim, and an approval requirement
	// enforced by whoever remembers to ask is not a requirement.
	ClaimJobs(ctx context.Context, hostID string, limit int) ([]protocol.Job, error)

	// RecordResult stores a job result idempotently, keyed by job id, and reports whether it was the
	// first.
	//
	// A repeated result for a job that already has one changes nothing, does not error, and returns
	// false. Work that succeeded but whose result was lost must never re-execute: that is how a retry
	// turns one reboot into a reboot loop. The boolean exists for the event path: the agent retries
	// results until acknowledged, so without it every retried failure would notify twice, and an
	// operator who is paged twice per incident starts counting incidents wrong.
	//
	// A result for a job that does not belong to hostID returns ErrNotFound. Every enrolled host is
	// authenticated but none of them is trusted: without this check any host could post a result for
	// another host's job, and because recording is idempotent the forged result would then suppress the
	// real one when it arrived.
	RecordResult(ctx context.Context, hostID string, r protocol.ResultRequest) (bool, error)

	// CreateTemplateVersion stores the next version of a template and returns the number it was given.
	//
	// The version is assigned here, atomically against concurrent writers, rather than chosen by the
	// caller: two operators saving at once must produce v3 and v4, never two rows both claiming v3 and
	// never a lost update. There is deliberately no method that updates a stored body — a version is
	// immutable because the Tier 2 bootstrap record on a host names one, and a record that resolves to
	// bytes that can change afterwards is not a record.
	CreateTemplateVersion(ctx context.Context, t TemplateVersion) (int, error)

	// ListTemplates returns one summary per template name, newest latest-version first.
	ListTemplates(ctx context.Context) ([]TemplateSummary, error)

	// ListTemplateVersions returns every stored revision of one template, newest first.
	//
	// Bodies are not included: this answers "what revisions exist and who made them", which is the
	// question an operator asks when a host's bootstrap record names version 3 and the current one is
	// 7. A caller that wants a body names a version and asks for it.
	//
	// An unknown name returns ErrNotFound rather than an empty list, because "this template has no
	// versions" is not a state that can exist — a template comes into being by having one.
	ListTemplateVersions(ctx context.Context, name string) ([]TemplateRevision, error)

	// GetTemplateVersion returns one version of a template, or ErrNotFound.
	//
	// Version 0 means the latest, which is what enrolment issues and what the editor opens; a positive
	// version names one exactly, which is what a bootstrap record on a host resolves against.
	GetTemplateVersion(ctx context.Context, name string, version int) (TemplateVersion, error)

	// RecordEvent appends one event to the tenant's inbox, evicting past MaxEventsPerTenant.
	RecordEvent(ctx context.Context, e Event) error

	// ListEvents returns inbox events, newest first.
	ListEvents(ctx context.Context, f EventFilter) ([]Event, error)

	// RecordUnitTransitions appends observed unit-state changes for one host, evicting past
	// MaxUnitTransitionsPerHost.
	//
	// One call per heartbeat rather than one per transition, because a host coming back from a bad
	// night can carry dozens and the eviction should run once against the batch.
	RecordUnitTransitions(ctx context.Context, hostID string, transitions []UnitTransition) error

	// ListUnitTransitions returns one host's unit-state history, newest first, bounded by limit.
	ListUnitTransitions(ctx context.Context, hostID string, limit int) ([]UnitTransition, error)

	// CreateAlertRule records a new rule.
	CreateAlertRule(ctx context.Context, r AlertRule) error

	// ListAlertRules returns every rule, oldest first.
	ListAlertRules(ctx context.Context) ([]AlertRule, error)

	// UpdateAlertRule applies a rule's threshold, cooldown, recipients and enabled flag.
	//
	// The condition is not among them: a rule that changed from host_silent to unit_failed would
	// inherit firing state that means something else entirely. Changing what is watched is a new rule.
	UpdateAlertRule(ctx context.Context, r AlertRule) error

	// DeleteAlertRule removes a rule and its firing state.
	DeleteAlertRule(ctx context.Context, id string) error

	// RecordAlertDelivery stamps a rule with the outcome of its most recent mail attempt.
	//
	// Separate from UpdateAlertRule because the two have different writers: an operator edits a rule,
	// and the notification path reports on it. Merging them would let a delivery report racing an
	// edit put back the threshold the operator just changed.
	//
	// A rule deleted between the attempt and the report is not an error: the outcome has nowhere to
	// go and nobody to tell, which is the correct end of that story.
	RecordAlertDelivery(ctx context.Context, ruleID string, at time.Time, failure string) error

	// ListAlertStates returns the evaluator's memory for every key it holds one for.
	ListAlertStates(ctx context.Context) ([]AlertState, error)

	// ClaimAlertNotification takes the right to notify for one alert key, atomically.
	//
	// It reports whether this caller won: true means the cooldown had elapsed (or nothing had ever
	// notified) and last_notified is now `at`, false means somebody else has it and this caller must
	// not send.
	//
	// It exists because reading the cooldown and then writing it are two statements, and event-routed
	// alerts run one detached goroutine per event: two units failing on the same heartbeat both read
	// "no recent notification" and both mail, which is precisely the flapping-unit noise the cooldown
	// exists to stop. One statement in the database is the only version of this that holds — across
	// goroutines and across control-plane processes alike.
	ClaimAlertNotification(ctx context.Context, key AlertKey, at time.Time,
		cooldown time.Duration) (bool, error)

	// ReleaseAlertFiring clears one alert key's firing flag, atomically, keeping its cooldown.
	//
	// It reports whether this caller was the one that cleared it: true means the key was firing and
	// is not any more, false means it was already clear and somebody else has already said so.
	//
	// The cooldown deliberately survives. Clearing last_notified here would make the cooldown
	// unreachable for any condition that oscillates: a host crossing its threshold, dropping back and
	// crossing again mails on every crossing, for ever, because each recovery hands the next firing a
	// clean claim. Keeping the stamp is the whole of flap suppression — one firing per cooldown,
	// whatever the condition does in between — and it is why a flapping unit costs one mail rather
	// than one per loop.
	//
	// The counterpart to ClaimAlertNotification, and needed for the same reason. Every firing has an
	// un-firing, and two control planes both reading "this was firing and is not now" would both send
	// the recovery — which for a partition that heals is the moment an operator is least able to
	// absorb a duplicate of every message.
	ReleaseAlertFiring(ctx context.Context, key AlertKey) (bool, error)

	// UpsertAlertState records one key's state, keyed on the key.
	UpsertAlertState(ctx context.Context, s AlertState) error

	// CreateWallboardShare records a link that publishes this fleet's status screen.
	//
	// It returns ErrConflict when the fleet already holds MaxWallboardSharesPerTenant live shares. That
	// is checked here rather than in the handler because it is a property of the rows, and two
	// operators publishing at once would both read "nineteen" and both insert.
	CreateWallboardShare(ctx context.Context, share WallboardShare) error

	// ListWallboardShares returns this fleet's shares, newest first, expired ones included.
	//
	// Expired shares are listed rather than hidden: a share that stopped working is the first thing
	// somebody looks for when a screen in the corridor has gone dark, and a listing that omitted it
	// would answer "there is no such link" to the person holding it.
	ListWallboardShares(ctx context.Context) ([]WallboardShare, error)

	// WallboardShareBySecret returns the live share whose secret hashes to this, or ErrNotFound.
	//
	// "Live" is in the query rather than in a check afterwards, which is what makes an unknown secret,
	// a revoked share and an expired one one code path taking one amount of time. A caller that
	// filtered in Go would have three refusals to keep matched, and they would drift.
	WallboardShareBySecret(ctx context.Context, secretHash string, now time.Time) (WallboardShare, error)

	// DeleteWallboardShare removes one share by id, or returns ErrNotFound.
	//
	// A delete rather than a revoked flag, exactly as revoking an API token is. What a withdrawn share
	// leaves behind is nothing, and that is the honest state: a share names no reader, so there is no
	// history attached to it worth keeping a row for.
	DeleteWallboardShare(ctx context.Context, id string) error

	// TouchWallboardShare stamps when a screen last polled one share, best effort.
	//
	// Throttled by the caller the way api_tokens.last_used_at is, and for the same reason: it is a
	// write on the path of every poll of every screen, and nothing reads it more precisely than
	// "somebody is still showing this". It exists because "which of these four links is still on a
	// wall" has to be answerable before somebody revokes one and waits to see who complains.
	TouchWallboardShare(ctx context.Context, id string, at time.Time) error
}

// AccountScope is every operation on the accounts of one side of the tenant boundary.
//
// It is an interface of its own rather than methods on Scoped because there are two sides and only one
// of them is a tenant. A fleet's operators are reached through Store.In(tenant); the installation's own
// administrators, who carry no tenant at all, are reached through Store.Platform(). Everything above
// this layer — the sign-in path, the account page, the token endpoints — is written against this
// interface and never learns which of the two it is holding, which is what keeps "a platform
// administrator signs in exactly like anybody else" true in code rather than by parallel implementation.
//
// The session and token methods take an account id rather than being reached through a per-account
// handle. A session belongs to an account and not to a fleet — migration 0010 moved the row-level
// security policy to say so — and a third handle for it would be indirection with one reader.
type AccountScope interface {
	// CreateAccount records a new account, or ErrConflict if the address is taken.
	//
	// The address is unique across the installation rather than within a fleet, so ErrConflict can mean
	// an address another fleet already uses, or one the platform administrator holds. Migration 0010
	// says why that is the right trade and why the disclosure it implies is bounded: accounts are
	// created on the machine, by somebody who can already read the table.
	CreateAccount(ctx context.Context, a Account) error

	// GetAccount returns one of this side's accounts by id, or ErrNotFound.
	GetAccount(ctx context.Context, id string) (Account, error)

	// ListAccounts returns this side's accounts, oldest first.
	ListAccounts(ctx context.Context) ([]Account, error)

	// UpdateAccountPassword replaces one account's password hash, or returns ErrNotFound.
	//
	// It is also how a hash written under weaker Argon2id parameters is rewritten, at the one moment
	// the password is known: sign-in. That is why it takes a hash rather than a password — this package
	// does not know how to make one, and should not.
	UpdateAccountPassword(ctx context.Context, id, passwordHash string) error

	// RecordAccountSignIn stamps when an account last signed in, or returns ErrNotFound.
	RecordAccountSignIn(ctx context.Context, id string, at time.Time) error

	// DeleteAccount removes an account and every credential it holds, or returns ErrNotFound.
	//
	// Sessions and API tokens go with it, because the account is the only thing that made them mean
	// anything and a credential outliving its account is one nobody can revoke by name. The schema's
	// ON DELETE CASCADE performs it; this method is where the guarantee is written down.
	DeleteAccount(ctx context.Context, id string) error

	// CreateSession records a signed-in browser and clears that account's expired sessions.
	//
	// The two happen together and that is the whole of session housekeeping: the table grows by one row
	// per sign-in and shrinks by all of that account's dead rows at the next one, so there is no sweeper
	// to schedule and nothing to forget to run.
	CreateSession(ctx context.Context, s Session) error

	// ListSessions returns one account's sessions, newest first.
	//
	// It exists so that "sign out everywhere" is a decision somebody makes rather than a button they
	// press blind. Nothing here returns a token or its hash to a caller that did not already hold one.
	ListSessions(ctx context.Context, accountID string) ([]Session, error)

	// TouchSession extends one session and records that it was used.
	//
	// The extension is what stops a session expiring in the middle of a working day, and it is a
	// separate method rather than a side effect of the lookup because it is a write: the caller decides
	// how often it is worth one. See auth.SessionRenewAfter.
	TouchSession(ctx context.Context, accountID, tokenHash string, expiresAt, usedAt time.Time) error

	// DeleteSession ends one session, whether or not it had expired.
	//
	// Idempotent: a token that names no row is not an error, because a second sign-out — or a sign-out
	// of a session that had already expired — is not a failure a caller should have to distinguish.
	DeleteSession(ctx context.Context, accountID, tokenHash string) error

	// DeleteSessionsFor ends every session one account holds, and reports how many.
	//
	// This is "sign out everywhere", which is the only thing an operator can do about a session they
	// cannot identify — and the thing to do after a laptop goes missing. The count is returned because
	// "signed out of 3 other places" is a different message from "signed out of nothing".
	DeleteSessionsFor(ctx context.Context, accountID string) (int, error)

	// CreateAPIToken records a token belonging to one account.
	CreateAPIToken(ctx context.Context, t APIToken) error

	// ListAPITokens returns one account's tokens, newest first.
	//
	// The token itself is absent, because only its hash was ever stored. That is worth being visible in
	// the shape rather than only in a comment: a field that could hold the secret and does not is a
	// question somebody asks once.
	ListAPITokens(ctx context.Context, accountID string) ([]APIToken, error)

	// TouchAPIToken records that a token was used, or returns ErrNotFound.
	//
	// Separate from the lookup for the same reason TouchSession is: it is a write on a read path, and
	// how often to pay for one is the caller's decision rather than the store's.
	TouchAPIToken(ctx context.Context, accountID, hash string, usedAt time.Time) error

	// DeleteAPIToken revokes one token, or returns ErrNotFound.
	//
	// ErrNotFound rather than silence, unlike DeleteSession: revoking a token is a deliberate act aimed
	// at a row somebody is looking at, so "there was nothing there" is information they want.
	DeleteAPIToken(ctx context.Context, accountID, hash string) error
}

// Compile-time proof that both implementations satisfy the interface.
//
// Without it, a method added to Store is a compile error only where a Store value is assigned — which
// in this package's tests is inside a test helper, so a missing method on one implementation surfaces
// as a confusing failure in an unrelated test rather than here, next to the interface it belongs to.
var (
	_ Store = (*Postgres)(nil)
	_ Store = (*Memory)(nil)
)

// clampJobLimit turns a caller's requested listing size into one the store will run.
//
// It is shared by both implementations rather than written twice, because a default that differed
// between them would make the in-memory store — which every server test runs against — prove a page
// size the shipped store does not have.
func clampJobLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultJobLimit
	case n > MaxJobLimit:
		return MaxJobLimit
	default:
		return n
	}
}
