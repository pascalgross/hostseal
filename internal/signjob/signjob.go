// Package signjob assembles the job document an offline signature covers.
//
// It exists because there are now two places an operator signs a destructive job from — `hostseal
// sign` at a terminal, and the loopback signer the web interface asks — and exactly one of these
// rules may exist. The identifier, the nonce, both edges of the validity window and the truncation to
// whole seconds are all inputs to a signature that a host checks against its own clock and its own
// replay record; two copies that drifted would produce signatures that verify in one place and are
// refused in the other, months apart, with nothing to point at.
//
// The other half of why it is a package rather than a function in a command: none of these values may
// come from whoever asked for the signature. docs/SECURITY.md §3 puts the destructive tier behind a
// key the control plane does not hold, and the control plane refuses to choose a signed job's id,
// nonce or window for exactly the same reason — so the signer chooses them, here, and a caller
// supplies the host, the intent and the parameters and nothing else.
package signjob

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pascalgross/hostseal/internal/id"
	"github.com/pascalgross/hostseal/internal/intent"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/signing"
)

// DefaultValidity is how long a signed job stays valid when the caller does not say.
//
// An hour, because the window is the blast radius of a signature. A job signed this morning and
// delivered to a host that was offline until Friday is the failure the window exists to prevent, and
// the honest default is "long enough to reach a fleet that is mostly up, short enough that forgetting
// about it is not dangerous". An operator who needs longer says so and sees the value in the summary.
const DefaultValidity = time.Hour

// Request is what a caller supplies, which is deliberately less than a signed job carries.
//
// The host, the intent and the parameters describe the operation; everything else about the document
// — its identifier, its nonce, its window — is decided by Draft. A caller that could choose a nonce
// could replay a signature, and one that could choose a window could sign something valid for a year.
type Request struct {
	// HostID is the host this job is for. It is covered by the signature, which is what binds a
	// signed job to exactly one machine.
	HostID string

	// Intent is the catalogue member, such as service.restart.
	Intent string

	// RawParams is the parameter object as JSON, empty for none.
	RawParams []byte

	// JobID overrides the generated identifier, for an operator who has one to reuse. Empty
	// generates one, which is the ordinary case and the only one the browser path allows.
	JobID string

	// NotBefore is an RFC3339 instant the job becomes valid, empty for now less a skew tolerance.
	NotBefore string

	// ValidFor is how long the signature stays valid, zero for DefaultValidity.
	ValidFor time.Duration
}

// Draft assembles the job a signature will cover, and decodes its parameters against the catalogue.
//
// Decoding here rather than only on the host is what lets the caller describe the operation to a
// human. It also means an operator who mistypes a unit name is told so before they enter a PIN or
// touch a token, rather than when a host refuses the job hours later.
//
// The identifier, the nonce and both edges of the validity window are decided here and are never a
// caller's to supply from outside — `hostseal sign` takes an optional --id and --not-before from the
// person at the terminal, and the browser path supplies neither. That is the same rule the control
// plane keeps at the other end: what a job request may carry follows from what the signature covers,
// so every one of these values arrives from the signer.
func Draft(req Request) (protocol.Job, intent.Spec, intent.Params, error) {
	jobID, name := req.JobID, req.Intent
	rawParams, notBefore, validFor := req.RawParams, req.NotBefore, req.ValidFor
	if len(rawParams) == 0 {
		rawParams = []byte("{}")
	}
	if validFor == 0 {
		validFor = DefaultValidity
	}

	spec, decoded, err := intent.Decode(intent.Name(name), rawParams)
	if err != nil {
		return protocol.Job{}, intent.Spec{}, nil, err
	}
	if !spec.Class.RequiresOfflineSignature() {
		return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf(
			"%s is a %s intent and is not signed offline. A read intent is authorised by mTLS alone "+
				"and a routine one by the control plane's own key; only the destructive tier needs a "+
				"key the control plane does not hold. See docs/SECURITY.md §3",
			spec.Name, spec.Class)
	}

	if jobID == "" {
		generated, genErr := id.New()
		if genErr != nil {
			return protocol.Job{}, intent.Spec{}, nil, genErr
		}
		jobID = generated
	}
	if !protocol.ValidJobID(jobID) {
		return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf(
			"the job id must be %s: it is a path segment in the result endpoint and a filename in the "+
				"agent's spool", protocol.JobIDShape)
	}

	nonce, err := id.New()
	if err != nil {
		return protocol.Job{}, intent.Spec{}, nil, err
	}

	// One reading of the clock for all three instants below. Two calls to time.Now would put the
	// issue time and the window on different sides of a second boundary often enough to matter, and a
	// signature is the wrong place for a value that depends on how long the line above it took.
	now := time.Now().UTC()

	// The window opens a little before now by default, for the same reason the control plane backdates
	// the one it signs itself: the host checks it against its own clock, and a machine a second behind
	// would otherwise find a job whose window had not opened and report it expired. The tolerance is
	// the skew a host would still act on at all; beyond it the agent refuses on the clock, which is the
	// refusal that names the real problem.
	//
	// The backdating moves the opening edge only, which is why the expiry is measured from a separate
	// instant. Deriving it from the backdated start instead would silently turn --valid-for=1h into
	// fifty-five minutes, and the symptom — a job signed for an hour and refused as expired before the
	// hour was up — reads as a clock problem on the host rather than as arithmetic here.
	start, expireFrom := now.Add(-protocol.MaxClockSkewSeconds*time.Second), now
	if notBefore != "" {
		parsed, parseErr := time.Parse(time.RFC3339, notBefore)
		if parseErr != nil {
			return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf(
				"the start instant is not RFC3339: %w", parseErr)
		}
		// An operator who names the start has said what the duration runs from: there is no useful
		// "from now" for a window that opens next Tuesday, and no skew tolerance to add to an edge they
		// chose deliberately.
		start, expireFrom = parsed.UTC(), parsed.UTC()
	}
	if validFor < 0 {
		return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf("the validity must be positive")
	}

	// Truncated to the second because that is the resolution the canonical payload carries: a signature
	// made over a time the payload cannot represent would verify against a different value than the one
	// signed here, and the failure would look like a broken key.
	var reencoded map[string]any
	if err := json.Unmarshal(rawParams, &reencoded); err != nil {
		return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf("the parameters are not a JSON object: %w", err)
	}
	if reencoded == nil {
		reencoded = map[string]any{}
	}

	return protocol.Job{
		ID:        jobID,
		Intent:    spec.Name.String(),
		Params:    reencoded,
		Class:     string(spec.Class),
		IssuedAt:  now.Truncate(time.Second),
		NotBefore: start.Truncate(time.Second),
		NotAfter:  expireFrom.Add(validFor).Truncate(time.Second),
		Nonce:     nonce,
	}, spec, decoded, nil
}

// Document renders the request body that POST /api/v1/jobs takes.
//
// One function for both signing paths, because this document is the signature's envelope: every field
// in it either is covered by the signature or names the key that made it, and a second copy that left
// one out would produce a job the control plane stores and every host refuses. The control plane
// re-derives the canonical payload from exactly these fields — see internal/server/jobsapi.go — so
// what is here is not a rendering choice.
func Document(job protocol.Job, hostID string, signature []byte, signer signing.Signer) map[string]any {
	return map[string]any{
		"id":              job.ID,
		"hostId":          hostID,
		"intent":          job.Intent,
		"params":          job.Params,
		"notBefore":       job.NotBefore.UTC().Format(time.RFC3339),
		"notAfter":        job.NotAfter.UTC().Format(time.RFC3339),
		"nonce":           job.Nonce,
		"signature":       base64.StdEncoding.EncodeToString(signature),
		"signerKeyId":     signer.KeyID(),
		"signerAlgorithm": string(signer.Algorithm()),
	}
}
