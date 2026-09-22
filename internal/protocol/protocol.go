// Package protocol defines the wire types shared by the HostSeal agent and control plane.
//
// It is one package used by both sides rather than two that agree, which is most of the reason both
// components are written in Go. The intent catalogue and the signature verifier are literally the same
// code on the agent and on the server; so are these structures. Two implementations of a protocol agree
// until the day they do not, and that day is always during an incident.
//
// docs/PROTOCOL.md is the specification and this is the implementation of it. Where they disagree, the
// document wins and this is the bug.
//
// Two conventions here are load-bearing rather than stylistic. Unknown fields are ignored in both
// directions, so the control plane can add a field without a fleet-wide agent upgrade and an old agent
// keeps working; and every duration is an explicit integer number of seconds rather than a Go duration
// string, so that a third-party implementation reading this document does not have to reimplement Go's
// duration parser.
package protocol

import (
	"crypto/tls"
	"regexp"
	"time"
)

// Version is the protocol version, which appears in every path.
//
// It changes only for a breaking change. Additive changes — new response fields, new intents, new
// result fields — do not bump it, which is why both sides ignore unknown fields.
const Version = "v1"

// The five endpoint paths. They are constants so that the agent, the server's router and the
// documentation tests cannot drift apart.
const (
	// PathEnroll exchanges a bootstrap token and a CSR for a host-scoped client certificate.
	PathEnroll = "/agent/" + Version + "/enroll"

	// PathHeartbeat reports host state, digest-first.
	PathHeartbeat = "/agent/" + Version + "/heartbeat"

	// PathJobs long-polls for work.
	PathJobs = "/agent/" + Version + "/jobs"

	// PathResults reports a job result. The job id is appended.
	PathResults = "/agent/" + Version + "/jobs/"

	// PathRenew re-keys a client certificate before it expires.
	PathRenew = "/agent/" + Version + "/renew"
)

// Bounds the protocol places on a single request, from docs/PROTOCOL.md §4.5.
const (
	// MaxHeartbeatBytes is the largest heartbeat body a server accepts.
	//
	// In multi-tenant hosting, one host filling the database fills it for other customers, which is why
	// this is enforced at the server rather than trusted to well-behaved agents.
	MaxHeartbeatBytes = 1 << 20

	// MaxResultBytes is the largest job result body a server accepts.
	MaxResultBytes = 1 << 20

	// MaxEnrollBytes is the largest enrolment body a server accepts.
	MaxEnrollBytes = 256 << 10

	// MaxJobOutputBytes is the amount of a job's output that is kept.
	//
	// It is the *last* 64 KiB rather than the first, because the failure is at the end.
	MaxJobOutputBytes = 64 << 10
)

// Long-poll timing, from docs/PROTOCOL.md §5.
const (
	// DefaultJobWaitSeconds is the recommended hold for the job long-poll.
	//
	// It must sit below the smallest idle timeout on the path. Thirty to sixty seconds is the common
	// default for proxies, load balancers and NAT tables, and a hold longer than that produces
	// intermittent failures that look like network flakiness and are debugged as such for weeks.
	DefaultJobWaitSeconds = 25

	// MaxJobWaitSeconds is the longest hold a server will honour.
	MaxJobWaitSeconds = 60

	// DefaultHeartbeatSeconds is the pacing a server suggests unless it says otherwise.
	DefaultHeartbeatSeconds = 60

	// MinHeartbeatSeconds and MaxHeartbeatSeconds clamp what an agent will accept.
	//
	// The clamp exists so that a compromised or simply buggy control plane cannot induce a hot loop
	// across an entire fleet by returning nextHeartbeatSeconds of zero.
	MinHeartbeatSeconds = 15
	MaxHeartbeatSeconds = 3600

	// MaxClockSkewSeconds is the offset beyond which privileged intents refuse.
	//
	// Read-only intents still run; privileged ones fail closed; the UI flags the host. The offset is
	// computed from the server's reported time and used for that decision and for display only — never
	// to adjust the local clock or any validity check. See docs/SECURITY.md §4.3.
	MaxClockSkewSeconds = 300
)

// EnrollRequest is the body of POST /agent/v1/enroll.
type EnrollRequest struct {
	// Token is the single-use bootstrap token issued by the control plane.
	Token string `json:"token"`

	// CSR is a PEM certificate signing request. The private key never leaves the host.
	CSR string `json:"csr"`

	// Hostname is the host's own name, for display.
	Hostname string `json:"hostname"`

	// MachineIDHash is a salted SHA-256 of /etc/machine-id.
	//
	// The raw value is documented by systemd as confidential and is never transmitted. The salt is
	// generated per host at installation and never leaves the machine, so the same machine-id under two
	// fleets does not produce a correlatable value.
	MachineIDHash string `json:"machineIdHash"`

	// AgentVersion is the agent build, so the control plane knows what it is talking to.
	AgentVersion string `json:"agentVersion"`
}

// EnrollResponse is the body of a successful enrolment.
type EnrollResponse struct {
	// HostID is the control plane's identifier for this host.
	HostID string `json:"hostId"`

	// Certificate is the issued client certificate, PEM.
	Certificate string `json:"certificate"`

	// CABundle is the CA chain the agent should pin, PEM.
	CABundle string `json:"caBundle"`

	// ServerTime is used solely to compute and report a clock offset.
	ServerTime time.Time `json:"serverTime"`

	// NextHeartbeatSeconds is the pacing the agent should adopt.
	NextHeartbeatSeconds int `json:"nextHeartbeatSeconds"`

	// OnlineKey is the control plane's own signing key, in the trusted-signers line format.
	//
	// It is what a routine intent is verified against, and it arrives from the control plane rather
	// than from the operator — which would be unacceptable for the destructive tier and is acceptable
	// here for a reason docs/SECURITY.md §3 states outright: what bounds a routine intent is the host's
	// local policy, not this key. The control plane can at most make a host do sooner what it already
	// permits itself to do unattended, so a control plane that rotated this key at will would gain
	// nothing it did not already have.
	//
	// Empty when the control plane has no online key, in which case the agent refuses routine intents
	// exactly as it did before there was one.
	OnlineKey string `json:"onlineKey,omitempty"`
}

// HeartbeatRequest is the body of POST /agent/v1/heartbeat.
//
// The steady state carries digests, not inventory. Five hundred hosts sending a full inventory every
// sixty seconds is hundreds of kilobytes per host per minute of write amplification on the control
// plane's database; digest-first makes the steady state hundreds of bytes and full reports rare and
// event-driven. Skipping it is a production incident rather than an inefficiency.
type HeartbeatRequest struct {
	// AgentVersion is the agent build.
	AgentVersion string `json:"agentVersion"`

	// BootID identifies this boot, so a reboot is visible without comparing uptimes.
	BootID string `json:"bootId"`

	// UptimeSeconds is how long the host has been up.
	UptimeSeconds int64 `json:"uptimeSeconds"`

	// FactsDigest is the canonical digest of the full facts document.
	FactsDigest string `json:"factsDigest"`

	// PolicyDigest is the canonical digest of the effective local policy.
	PolicyDigest string `json:"policyDigest"`

	// SignersDigest is the canonical digest of the host's trusted-signers set.
	//
	// It exists so an operator can see that hosts which should have the same signers do, without any
	// host transmitting its trust anchor anywhere. A fleet where one machine quietly has an extra key
	// is exactly what this makes visible.
	SignersDigest string `json:"signersDigest"`

	// ClockOffsetSeconds is the agent's own measurement of its offset from the server.
	ClockOffsetSeconds int64 `json:"clockOffsetSeconds"`

	// Paused reports whether /etc/hostseal/paused exists.
	Paused bool `json:"paused"`

	// Facts is the full inventory, sent only when the server asked for it.
	Facts any `json:"facts,omitempty"`

	// Policy is the effective local policy, sent only when the server asked for it.
	Policy any `json:"policy,omitempty"`

	// Signers is the host's trusted key identities, sent only when the server asked for it.
	//
	// Only the identities and algorithms, never the file. The control plane has no business holding a
	// copy of a host's trust anchor, and displaying "ops-yubikey-1 (PKCS#11)" needs no more than this.
	//
	// It deliberately has no omitempty. An empty trust anchor is the shipped default and the most
	// important thing this field can say — "this host will execute nothing destructive" — so it must be
	// distinguishable on the wire from "the host did not report". With omitempty the two are identical,
	// and the server would ask for a document the agent had already sent, on every single heartbeat,
	// for the life of every unconfigured host in the fleet.
	Signers []SignerSummary `json:"signers"`
}

// SignerSummary is one trusted key as reported to the control plane, for display.
type SignerSummary struct {
	// KeyID is the identity from the host's trusted-signers file.
	KeyID string `json:"keyId"`

	// Algorithm is the signature algorithm.
	Algorithm string `json:"algorithm"`

	// Backend is the administrator's own annotation of how the key is held, if present.
	Backend string `json:"backend,omitempty"`
}

// HeartbeatResponse is the control plane's reply to a heartbeat.
type HeartbeatResponse struct {
	// ServerTime is used solely to compute and report a clock offset.
	//
	// The agent must never adjust its clock, its timers, or any validity check to this value. A
	// compromised control plane could otherwise extend a signature's validity window by lying about
	// the time. See docs/SECURITY.md §4.3.
	ServerTime time.Time `json:"serverTime"`

	// NextHeartbeatSeconds is authoritative pacing and may change on any response.
	//
	// It exists so a control plane can spread load across the minute, or back an entire fleet off
	// during an incident, without deploying a new agent.
	NextHeartbeatSeconds int `json:"nextHeartbeatSeconds"`

	// WantFullReport asks for everything on the next heartbeat.
	WantFullReport bool `json:"wantFullReport"`

	// WantFacts asks for the facts document on the next heartbeat.
	WantFacts bool `json:"wantFacts"`

	// WantPolicy asks for the effective policy on the next heartbeat.
	WantPolicy bool `json:"wantPolicy"`

	// WantSigners asks for the trusted key identities on the next heartbeat.
	WantSigners bool `json:"wantSigners"`

	// OnlineKey is the control plane's own signing key, in the trusted-signers line format.
	//
	// Sent on every heartbeat rather than digest-first like the documents above, and the asymmetry is
	// deliberate. Digest-first exists because a facts document is kilobytes and a fleet of five hundred
	// would send its whole inventory every minute; this is one short line. Sending it unconditionally
	// means key rotation propagates on its own, with no state machine, no "want" flag, and no host left
	// on a key that no longer verifies because it missed one exchange.
	//
	// Empty when the control plane has no online key. An agent that receives an empty value keeps what
	// it has: an absent field means "nothing to say", not "forget your key", because the second reading
	// would let one malformed response disable a fleet's routine tier until somebody noticed.
	OnlineKey string `json:"onlineKey,omitempty"`
}

// Job is one unit of work, as delivered to an agent.
//
// It is a typed intent with typed parameters. It is never a command, a script, a path to execute, or a
// URL to fetch code from, and there is no field here into which any of those could be placed.
type Job struct {
	// ID identifies the job. Results are keyed by it and are idempotent.
	ID string `json:"id"`

	// Intent is the catalogue member. An agent that does not recognise it reports unsupported_intent
	// and must not attempt any fallback interpretation.
	Intent string `json:"intent"`

	// Params is the parameter object, validated by the intent's own decoder on the agent.
	Params map[string]any `json:"params"`

	// Class is the authorisation tier the server believes this intent has.
	//
	// The agent does not trust it: the class is a property of the catalogue entry the agent looked up,
	// and a server that labelled host.reboot as "read" would defeat the signature requirement without
	// touching the signature code. It is carried for display and for debugging a mismatch.
	Class string `json:"class"`

	// IssuedAt is when the control plane created the job, for the local age limit.
	IssuedAt time.Time `json:"issuedAt"`

	// NotBefore and NotAfter bound the signature's validity, checked against the local clock only.
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`

	// Nonce is persisted by the host to refuse a replayed signature.
	Nonce string `json:"nonce"`

	// Signature is base64, over the canonical payload described in docs/PROTOCOL.md §8.
	Signature string `json:"signature,omitempty"`

	// SignerKeyID names the key that signed it. For a destructive intent it must be a key in the
	// host's own trusted-signers; a signature by the control plane's online key is not acceptable.
	SignerKeyID string `json:"signerKeyId,omitempty"`

	// SignerAlgorithm is "ed25519" or "ecdsa-p256".
	SignerAlgorithm string `json:"signerAlgorithm,omitempty"`
}

// SignedPayload returns the exact structure a job's signature is computed over.
//
// It is built here, in the shared package, so that the agent verifying a signature and the tool
// producing one cannot construct different payloads from the same job. Note what is absent: Class is
// not signed, because the agent derives it from its own catalogue rather than from the wire, and
// signing a value nobody trusts would only make it look authoritative.
func (j Job) SignedPayload(hostID string) map[string]any {
	params := j.Params
	if params == nil {
		params = map[string]any{}
	}
	return map[string]any{
		"jobId":     j.ID,
		"hostId":    hostID,
		"intent":    j.Intent,
		"params":    params,
		"notBefore": j.NotBefore.UTC().Format(time.RFC3339),
		"notAfter":  j.NotAfter.UTC().Format(time.RFC3339),
		"nonce":     j.Nonce,
	}
}

// JobsResponse is the body of GET /agent/v1/jobs.
type JobsResponse struct {
	// Jobs is the work available for this host, possibly empty.
	Jobs []Job `json:"jobs"`
}

// MaxJobIDBytes bounds a job identifier.
//
// A generated one is 26 characters, so this is room for a signer who wants a readable id
// ("reboot-web01-2026-08-23" is a legitimate thing to want) without the id becoming a place to put a
// kilobyte. It is a filename on the host and a path segment on the wire, and both have limits well
// above this.
const MaxJobIDBytes = 64

// jobIDPattern is the only shape a job identifier may take.
//
// Crockford base32 is upper-case alphanumeric without I, L, O and U, so an allowlist is exact rather
// than a list of characters somebody thought to exclude. Lower case is permitted so that an identifier
// that has been through a case-normalising layer still round-trips.
//
// The rule lives here, in the package both sides share, rather than on either side of the wire. The id
// is a path segment in POST /agent/v1/jobs/{id}/result and a filename in the agent's result spool, so a
// control plane that accepted an id the agent refuses would produce work whose result has nowhere to go
// — and one that accepted a "/" would produce work whose result POST does not route at all.
var jobIDPattern = regexp.MustCompile(`^[0-9A-Za-z]+$`)

// ValidJobID reports whether an identifier is one both sides will carry.
func ValidJobID(id string) bool {
	return id != "" && len(id) <= MaxJobIDBytes && jobIDPattern.MatchString(id)
}

// JobIDShape describes the accepted shape, for an error message that says what to do instead.
const JobIDShape = "letters and digits only, at most 64 of them"

// MaxHostIDBytes bounds a host identifier.
//
// Generated ones are 26 characters. The bound is here rather than assumed because a host id is
// assigned by the control plane and read by the agent, and the agent does not get to assume the
// control plane is well behaved — the whole design is what remains true when it is not.
const MaxHostIDBytes = 64

// ValidHostID reports whether a host identifier is one the agent will carry.
//
// It shares jobIDPattern because both come from internal/id and both end up in places where a
// character outside the alphabet changes the meaning of a document rather than the value of a field.
// For a host id that place is cloud-init's meta-data: the agent writes `instance-id: <host id>` into a
// YAML document cloud-init parses and acts on, so an id carrying a newline would let whoever assigned
// it add keys to that document — `public-keys`, which cc_ssh installs into authorized_keys. That is a
// path from a control plane to an SSH key on a host, and it would run beside the bootstrap template
// rather than inside it: not covered by the offline signature, not shown to the operator, not written
// into the permanent record. Validating here is what keeps the enrolment-time exception in
// docs/SECURITY.md §1 to exactly the template its operator named.
func ValidHostID(id string) bool {
	return id != "" && len(id) <= MaxHostIDBytes && jobIDPattern.MatchString(id)
}

// HostIDShape describes the accepted shape, for an error message that says what to do instead.
const HostIDShape = "letters and digits only, at most 64 of them"

// Result statuses. They are stable strings because they end up in the UI, in the audit log and in
// operators' alerting rules, and renaming one silently breaks somebody's dashboard.
const (
	// StatusSucceeded means the operation completed.
	StatusSucceeded = "succeeded"

	// StatusFailed means it was attempted and did not succeed.
	StatusFailed = "failed"

	// StatusRefusedByPolicy means the host's own policy declined it.
	StatusRefusedByPolicy = "refused_by_policy"

	// StatusRefusedUnsigned means the required signature was absent or did not verify.
	StatusRefusedUnsigned = "refused_unsigned"

	// StatusRefusedClockSkew means the host's clock is too far from the server's to act safely.
	StatusRefusedClockSkew = "refused_clock_skew"

	// StatusUnsupportedIntent means this agent does not implement the intent.
	StatusUnsupportedIntent = "unsupported_intent"

	// StatusExpired means the job's validity window had closed by the local clock.
	StatusExpired = "expired"
)

// statuses is the closed set, as a set, for the check below.
var statuses = map[string]bool{
	StatusSucceeded:         true,
	StatusFailed:            true,
	StatusRefusedByPolicy:   true,
	StatusRefusedUnsigned:   true,
	StatusRefusedClockSkew:  true,
	StatusUnsupportedIntent: true,
	StatusExpired:           true,
}

// ValidStatus reports whether a reported status is one of the seven above.
//
// The control plane checks this on the way in because the status is what every client renders as the
// job's state. Passing an unknown word through means a host can choose that word — including one of the
// control plane's own state words, so that a job which has been claimed and has reported a result
// renders as though nobody had touched it, and an operator re-issues work that already ran.
func ValidStatus(s string) bool { return statuses[s] }

// ResultRequest is the body of POST /agent/v1/jobs/{id}/result.
//
// It is idempotent, keyed by job id, and persisted on the host before the first send attempt. Work that
// succeeded but whose result was lost must never re-execute: that is how a retry turns one reboot into
// a reboot loop.
type ResultRequest struct {
	// JobID identifies the job. It is repeated in the body as well as the path so a stored result is
	// self-describing.
	JobID string `json:"jobId"`

	// Status is one of the Status constants above.
	Status string `json:"status"`

	// StartedAt and FinishedAt bound the execution, by the host's own clock.
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`

	// ExitCode is the helper's exit status, where one applies.
	ExitCode int `json:"exitCode"`

	// Output is the last MaxJobOutputBytes of combined output.
	Output string `json:"output,omitempty"`

	// OutputTruncated reports that the output was cut.
	OutputTruncated bool `json:"outputTruncated,omitempty"`

	// Result is the intent-specific typed result, where the intent produces one.
	Result any `json:"result,omitempty"`

	// Error is a human-readable failure reason, empty on success.
	Error string `json:"error,omitempty"`
}

// RenewRequest is the body of POST /agent/v1/renew, authenticated by the current certificate.
type RenewRequest struct {
	// CSR is a PEM certificate signing request for the same host identity.
	CSR string `json:"csr"`
}

// RenewResponse carries a freshly issued certificate.
type RenewResponse struct {
	// Certificate is the new client certificate, PEM.
	Certificate string `json:"certificate"`

	// CABundle is the CA chain, PEM, in case it has rotated.
	CABundle string `json:"caBundle"`

	// NotAfter is when the new certificate expires.
	NotAfter time.Time `json:"notAfter"`
}

// ErrorBody is the problem document a server returns with a non-2xx status.
//
// Agents must not require it and must never parse Message for control flow: the status code and Error
// are the contract, and Message is for the human reading the journal.
type ErrorBody struct {
	// Error is a stable machine-readable code.
	Error string `json:"error"`

	// Message is human-readable text.
	Message string `json:"message"`
}

// ClampHeartbeatSeconds bounds a server-supplied pacing value.
//
// The clamp is applied by the agent, not the server, because it exists to protect the fleet from the
// control plane: a compromised or buggy server returning zero would otherwise turn five hundred agents
// into a denial-of-service against it.
func ClampHeartbeatSeconds(n int) int {
	switch {
	case n < MinHeartbeatSeconds:
		return MinHeartbeatSeconds
	case n > MaxHeartbeatSeconds:
		return MaxHeartbeatSeconds
	default:
		return n
	}
}

// TruncateOutput keeps the last MaxJobOutputBytes of a job's output.
//
// The tail is kept rather than the head because the failure is at the end. The boolean is returned
// rather than inferred so a reader of the result knows the output is partial by design.
func TruncateOutput(s string) (string, bool) {
	if len(s) <= MaxJobOutputBytes {
		return s, false
	}
	return s[len(s)-MaxJobOutputBytes:], true
}

// TLSMinVersion is the floor for every HostSeal TLS connection, on both ends.
//
// 1.2 rather than 1.3, and the reason is the listener rather than the protocol. One port carries three
// kinds of client — an agent enrolling, an enrolled agent, and an operator's browser — and only the
// first two are built from this repository. A 1.3 floor would be free for them and would refuse a
// browser somebody is stuck with, on a control plane that is otherwise working, with a handshake error
// that says nothing about why.
//
// What 1.2 costs is closed by TLSCipherSuites below rather than by the floor.
const TLSMinVersion = tls.VersionTLS12

// TLSCipherSuites is the TLS 1.2 half of the connection, stated rather than defaulted.
//
// Go's default 1.2 selection includes ECDHE with AES-CBC and SHA-1 HMAC, which is the encrypt-then-MAC
// construction every 1.2 padding-oracle result of the last decade has been about. Nothing needs it
// here: the two ends that matter are Go, and every browser that can reach a control plane at all has
// done AEAD for years. So the list is AEAD only, forward-secret only, and it is written down instead of
// inherited — a default is a decision somebody else makes on a schedule this project does not control.
//
// It says nothing about TLS 1.3, which is the point of 1.3: its suites are not negotiable and Go
// ignores this field for them. A connection that reaches 1.3 has already skipped everything below.
var TLSCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}
