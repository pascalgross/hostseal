package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/canonical"
	"github.com/pascalgross/hostseal/internal/intent"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/signing"
	"github.com/pascalgross/hostseal/internal/signing/backend/file"
	"github.com/pascalgross/hostseal/internal/signjob"
)

// draftJob assembles a signable job the way `hostseal sign` does.
//
// A wrapper around signjob.Draft with the flags' own argument order, so that the specifications below
// read as the command reads: --id, --host, --intent, --params, --not-before, --valid-for. The rules
// themselves moved to internal/signjob when the loopback signer began drafting jobs too — one copy of
// how a nonce and a window are chosen, two places that sign — and these tests stayed here because what
// they hold is a property of this command: that what an operator is shown is what gets signed.
func draftJob(jobID, host, name, rawParams, notBefore string, validFor time.Duration) (
	protocol.Job, intent.Spec, intent.Params, error) {
	return signjob.Draft(signjob.Request{
		JobID:     jobID,
		HostID:    host,
		Intent:    name,
		RawParams: []byte(rawParams),
		NotBefore: notBefore,
		ValidFor:  validFor,
	})
}

// TestGuaranteeWhatIsShownIsWhatIsSigned is the property this command exists for.
//
// A control plane that handed the tool a digest to sign could render "restart nginx on web-01" while
// having "reboot every host" signed, and no care by the operator would catch it. So the display is
// derived from the payload rather than alongside it, and this asserts the two cannot drift: the bytes
// printed as "signed payload, verbatim" are the bytes the signature covers, and the human-readable
// summary is decoded from the same job.
func TestGuaranteeWhatIsShownIsWhatIsSigned(t *testing.T) {
	job, spec, decoded, err := draftJob(
		"", "01JTESTHOST", "service.restart", `{"unit":"nginx.service"}`, "", time.Hour)
	if err != nil {
		t.Fatalf("building a signable job: %v", err)
	}

	payload, err := canonical.Marshal(job.SignedPayload("01JTESTHOST"))
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}

	// Everything the operator is shown has to appear in, or be derived from, the bytes being signed.
	for _, shown := range []string{job.ID, job.Nonce, "01JTESTHOST", "service.restart", "nginx.service"} {
		if !strings.Contains(string(payload), shown) {
			t.Errorf("the summary shows %q, which the signed payload does not contain", shown)
		}
	}
	if decoded.Describe() != "service.restart nginx.service" {
		t.Errorf("the operation is described as %q", decoded.Describe())
	}
	if spec.Class != intent.ClassDestructive {
		t.Errorf("class is %q; this test is about the tier that needs an offline signature", spec.Class)
	}

	// And the window is the one the summary reports, to the second the payload can carry. A signature
	// made over a time the payload cannot represent would verify against a different value than the one
	// displayed, and the failure would look like a broken key rather than a rounding decision.
	if !job.NotBefore.Equal(job.NotBefore.Truncate(time.Second)) {
		t.Error("notBefore carries sub-second precision the canonical payload discards")
	}
	if !job.NotAfter.Equal(job.NotAfter.Truncate(time.Second)) {
		t.Error("notAfter carries sub-second precision the canonical payload discards")
	}
}

// TestGuaranteeASignedJobVerifiesAgainstTheHostsOwnAnchor is the end of the chain this command starts.
//
// It signs with the file backend exactly as the command does, then verifies with signing.SignerSet
// exactly as the agent does — against a trusted-signers set built from the key's own public half. The
// two halves live in different packages and are written from different ends; the failure this catches
// is a signature that is correct in isolation and does not verify where it has to.
func TestGuaranteeASignedJobVerifiesAgainstTheHostsOwnAnchor(t *testing.T) {
	keyPath := t.TempDir() + "/ops.key"
	signer, err := file.Generate(keyPath, "ops-laptop", signing.Ed25519, []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	t.Cleanup(func() { _ = signer.Close() })

	line, err := signing.TrustedSignerLine(signer)
	if err != nil {
		t.Fatalf("rendering the trusted-signers line: %v", err)
	}
	anchor, err := signing.ParseSigners(strings.NewReader(line), "test")
	if err != nil {
		t.Fatalf("parsing the anchor: %v", err)
	}

	const host = "01JTESTHOST"
	job, _, _, err := draftJob("", host, "host.reboot", `{"delaySeconds":60}`, "", time.Hour)
	if err != nil {
		t.Fatalf("building a signable job: %v", err)
	}
	payload, err := canonical.Marshal(job.SignedPayload(host))
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	key, err := anchor.Verify(payload, signature)
	if err != nil {
		t.Fatalf("a job this command signed does not verify against the host's own anchor: %v", err)
	}
	if key.KeyID != "ops-laptop" {
		t.Errorf("verified against %q", key.KeyID)
	}

	// And the signature is over *that host*. Binding to a host id is what stops a signature authorising
	// the same operation everywhere, and it is a property of the payload rather than of the transport.
	elsewhere, err := canonical.Marshal(job.SignedPayload("01JOTHERHOST"))
	if err != nil {
		t.Fatalf("canonicalising for another host: %v", err)
	}
	if _, err := anchor.Verify(elsewhere, signature); err == nil {
		t.Fatal("a signature made for one host verified for another")
	}
}

// TestSignRefusesAnIntentItCannotAuthorise covers the two tiers this command has no business signing.
//
// A read intent is authorised by mTLS and a routine one by the control plane's own key. Producing an
// offline signature for either would create a job the control plane refuses to accept, and the operator
// would have entered a passphrase to find that out.
func TestSignRefusesAnIntentItCannotAuthorise(t *testing.T) {
	for _, name := range []string{"facts.collect", "packages.applySecurity"} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := draftJob("", "01JTESTHOST", name, `{}`, "", time.Hour)
			if err == nil {
				t.Fatalf("%s was accepted for offline signing", name)
			}
			if !strings.Contains(err.Error(), "not signed offline") {
				t.Errorf("the refusal does not explain which tier signs it: %v", err)
			}
		})
	}
}

// TestSignRefusesAJobIdentifierAHostCannotReportAgainst keeps the operator-chosen id inside the shape
// the rest of the system can carry.
//
// The id becomes a path segment in the result endpoint and a filename in the agent's spool. Refused
// here rather than corrected, because the signature covers it: a normalised id would simply stop
// verifying, and the operator would be told their key was wrong.
func TestSignRefusesAJobIdentifierAHostCannotReportAgainst(t *testing.T) {
	for _, bad := range []string{"west/reboot", "reboot?now", "reboot-2026-08-23", strings.Repeat("A", 65)} {
		_, _, _, err := draftJob(bad, "01JTESTHOST", "host.reboot", `{}`, "", time.Hour)
		if err == nil {
			t.Errorf("job id %q was accepted", bad)
		}
	}
}

// TestSignedRequestCarriesEverythingTheSignatureCovers checks the body this command prints is the body
// the control plane needs.
//
// A signed job's id, nonce and validity window all arrive from the signer, because all four are covered
// by the signature and a value chosen by the control plane would invalidate it. Omitting one from the
// request would produce a 400 that reads as a malformed request rather than as a missing field.
func TestSignedRequestCarriesEverythingTheSignatureCovers(t *testing.T) {
	const host = "01JTESTHOST"
	job, _, _, err := draftJob("", host, "host.reboot", `{"delaySeconds":60}`, "", time.Hour)
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	payload := job.SignedPayload(host)
	for _, field := range []string{"jobId", "hostId", "intent", "params", "notBefore", "notAfter", "nonce"} {
		if _, present := payload[field]; !present {
			t.Errorf("the signed payload has no %q; docs/PROTOCOL.md §8 fixes the set", field)
		}
	}
	if len(payload) != 7 {
		t.Errorf("the signed payload has %d fields, want the 7 docs/PROTOCOL.md §8 fixes: %v",
			len(payload), payload)
	}

	// issuedAt is deliberately not among them: it is not signed, so an agent measures a signed job's
	// age from notBefore instead. A payload that gained it would let a control plane defeat the local
	// age limit by restating when it issued the job.
	if _, present := payload["issuedAt"]; present {
		t.Error("the signed payload carries issuedAt, which docs/PROTOCOL.md §8 excludes on purpose")
	}
}

// TestTheValidityRunsFromSigningAndNotFromTheBackdatedStart pins what --valid-for means.
//
// The window's opening edge is backdated by the clock-skew tolerance so that a host running a little
// behind does not find a job whose window has not opened yet. Measuring the expiry from that backdated
// edge would spend the tolerance twice: --valid-for=1h would produce a signature that expires
// fifty-five minutes after it was made, and an operator whose job is refused in that last five minutes
// would be looking for a clock problem on the host rather than for arithmetic in this file. So the two
// edges are computed from different instants, and this is the test that says so.
func TestTheValidityRunsFromSigningAndNotFromTheBackdatedStart(t *testing.T) {
	before := time.Now().UTC()
	job, _, _, err := draftJob(
		"", "01JTESTHOST", "service.restart", `{"unit":"nginx.service"}`, "", time.Hour)
	if err != nil {
		t.Fatalf("building a signable job: %v", err)
	}
	after := time.Now().UTC()

	// Bracketed by the two readings rather than compared to one, because the instant inside is neither.
	// Truncated on the lower bound because the payload carries whole seconds and the truncation can only
	// move the expiry earlier.
	if job.NotAfter.Before(before.Add(time.Hour).Truncate(time.Second)) {
		t.Errorf("--valid-for=1h expires at %s, less than an hour after signing at about %s",
			job.NotAfter.Format(time.RFC3339), before.Format(time.RFC3339))
	}
	if job.NotAfter.After(after.Add(time.Hour)) {
		t.Errorf("--valid-for=1h expires at %s, more than an hour after signing at about %s",
			job.NotAfter.Format(time.RFC3339), after.Format(time.RFC3339))
	}

	// And the opening edge is still backdated, which is the half this must not have broken.
	if !job.NotBefore.Before(before) {
		t.Errorf("notBefore is %s, which is not before the signing time %s: a host a second behind "+
			"would refuse this job as not yet valid",
			job.NotBefore.Format(time.RFC3339), before.Format(time.RFC3339))
	}
}

// TestAnExplicitStartIsTheInstantTheValidityRunsFrom is the other half of the same rule.
//
// There is no useful "from now" for a window an operator has scheduled for next Tuesday, and no skew
// tolerance to add to an edge they named deliberately. So --not-before both opens the window and starts
// the clock on --valid-for, and the window is then exactly as wide as it was asked to be.
func TestAnExplicitStartIsTheInstantTheValidityRunsFrom(t *testing.T) {
	start := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second)
	job, _, _, err := draftJob("", "01JTESTHOST", "service.restart",
		`{"unit":"nginx.service"}`, start.Format(time.RFC3339), 30*time.Minute)
	if err != nil {
		t.Fatalf("building a signable job: %v", err)
	}

	if !job.NotBefore.Equal(start) {
		t.Errorf("notBefore is %s; --not-before asked for %s",
			job.NotBefore.Format(time.RFC3339), start.Format(time.RFC3339))
	}
	if got := job.NotAfter.Sub(job.NotBefore); got != 30*time.Minute {
		t.Errorf("the window is %s wide; --valid-for asked for 30m", got)
	}
}

// TestAnExplicitlyZeroValidityIsRefusedRatherThanDefaulted keeps a typed number from meaning its
// opposite.
//
// `signjob.Draft` reads a zero duration as "the caller has no opinion, use an hour", because the
// caller that leaves it unset is a request over a socket that omitted the field. An operator who typed
// `--valid-for=0` has an opinion, and it is not an hour — so the command refuses before it reaches the
// seam where the difference between "unset" and "explicitly none" has already been lost.
func TestAnExplicitlyZeroValidityIsRefusedRatherThanDefaulted(t *testing.T) {
	for _, argv := range [][]string{
		{"--key", "/nonexistent.key", "--host", "01JTESTHOST", "--intent", "host.reboot",
			"--valid-for", "0"},
		{"--key", "/nonexistent.key", "--host", "01JTESTHOST", "--intent", "host.reboot",
			"--valid-for", "-5m"},
	} {
		if code := signCommand(argv); code != 2 {
			t.Errorf("%v exited %d, want 2 — refused before the key is opened", argv, code)
		}
	}
}
