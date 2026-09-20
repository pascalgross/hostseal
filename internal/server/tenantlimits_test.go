package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pascalgross/hostseal/internal/agent"
	"github.com/pascalgross/hostseal/internal/protocol"
)

// The two settings migration 0014 added, and the properties that make them safe.
//
// A host limit and a suspension are levers held by whoever runs the installation, which is a different
// person from whoever runs the fleet — so the tests that matter most here are the ones asserting what
// the levers *cannot* do. A limit that could take a running host away from its operator, or a
// suspension that changed something on a machine, would be the first thing in this control plane able
// to act on an enrolled host, and the guarantee would have to be rewritten around it.

// setHostLimit sets the harness fleet's host limit through the platform API.
//
// Through the API rather than the store, because the API is where the three-state decoding of
// `hostLimit` lives — absent, null, a number — and a test that wrote the column directly would not
// exercise the part most likely to be wrong.
func (h *harness) setHostLimit(t *testing.T, limit any) {
	t.Helper()
	status, body := h.adminJSON(t, h.platformToken, http.MethodPatch,
		"/api/v1/tenants/"+string(h.tenant), map[string]any{"hostLimit": limit})
	if status != http.StatusOK {
		t.Fatalf("setting hostLimit to %v got %d: %s", limit, status, body)
	}
}

// setSuspended suspends or resumes the harness fleet through the platform API.
func (h *harness) setSuspended(t *testing.T, suspended bool) {
	t.Helper()
	status, body := h.adminJSON(t, h.platformToken, http.MethodPatch,
		"/api/v1/tenants/"+string(h.tenant), map[string]any{"suspended": suspended})
	if status != http.StatusOK {
		t.Fatalf("setting suspended to %v got %d: %s", suspended, status, body)
	}
}

// tryEnrol attempts an enrolment and returns the error rather than failing the test.
//
// `enrolHost` is the happy path and calls t.Fatal; every test below is about a refusal, so it needs the
// error itself — and specifically the status and code, because the agent's own behaviour is decided by
// the status and never by parsing the message.
func (h *harness) tryEnrol(t *testing.T, name, token string) error {
	t.Helper()
	_, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		ServerURL: h.server.URL,
		Token:     token,
		StateDir:  filepath.Join(h.dir, "hosts", name),
		CABundle:  h.caFile,
		Hostname:  name,
	})
	return err
}

// refusal pulls the status and machine-readable code out of an agent error.
func refusal(t *testing.T, err error) (int, string) {
	t.Helper()
	var httpErr *agent.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("wanted an HTTP refusal, got %v", err)
	}
	return httpErr.Status, httpErr.Code
}

// TestGuaranteeAHostLimitNeverReachesAnEnrolledHost is the property the whole feature rests on.
//
// A limit lowered below a fleet's current size is not an instruction to shed hosts. It changes the
// answer the enrolment endpoint gives the *next* machine and nothing else: every host already enrolled
// keeps its certificate, keeps being accepted, and is not revoked, paused or told anything.
//
// This is the test to read first if the feature ever looks like it has grown. The moment a limit can
// remove a running host, the platform role has acquired a lever on an enrolled host — which is the one
// capability docs/SECURITY.md §1 is a promise about.
func TestGuaranteeAHostLimitNeverReachesAnEnrolledHost(t *testing.T) {
	h := newHarness(t)
	first := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	second := h.enrolHost(t, "web-02", h.issueToken(t, "web-prod"))

	// Below the current size, and by more than one: two hosts, room for none.
	h.setHostLimit(t, 0)

	for name, state := range map[string]*agent.State{"web-01": first, "web-02": second} {
		client := h.agentClient(t, state)
		if _, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{
			AgentVersion: "test", FactsDigest: "sha256:aaa",
		}); err != nil {
			t.Fatalf("%s stopped being accepted after the limit was lowered: %v", name, err)
		}

		host, err := h.scoped().GetHost(context.Background(), state.HostID)
		if err != nil {
			t.Fatalf("%s is gone from the store: %v", name, err)
		}
		if host.Revoked {
			t.Errorf("%s was revoked by a host limit; a limit gates enrolment and must touch nothing else", name)
		}
		if host.Paused {
			t.Errorf("%s was paused by a host limit; pausing is a local switch and the control plane cannot set it", name)
		}
	}
}

// TestAFleetAtItsLimitRefusesTheNextEnrolmentAndKeepsTheToken covers the ordering the handler relies on.
//
// The limit is checked before the token is consumed, exactly as the machine-id claim is, and for the
// same reason: a refusal has to leave the token usable. Burning a single-use credential to say "not
// right now" turns a billing question into a support ticket about a spent token — and the operator's
// next attempt fails with "the enrolment token cannot be used", which reads exactly like theft.
func TestAFleetAtItsLimitRefusesTheNextEnrolmentAndKeepsTheToken(t *testing.T) {
	h := newHarness(t)
	h.setHostLimit(t, 1)
	h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	token := h.issueToken(t, "web-prod")
	status, code := refusal(t, h.tryEnrol(t, "web-02", token))
	if status != http.StatusForbidden || code != "host_limit_reached" {
		t.Fatalf("enrolment past the limit answered %d %q, want 403 host_limit_reached", status, code)
	}

	// The same token, once there is room. If the refusal above had consumed it this fails, which is the
	// whole point of the assertion.
	h.setHostLimit(t, 2)
	if err := h.tryEnrol(t, "web-02", token); err != nil {
		t.Fatalf("the token refused by the limit was not usable afterwards: %v", err)
	}
}

// TestRevokingAHostMakesRoomUnderTheLimit is why the limit counts active hosts rather than rows.
//
// A revoked host keeps its row for the audit trail. If the limit were measured against every row, an
// operator who replaced a machine would find their fleet permanently one host smaller, for a reason no
// interface would show them.
func TestRevokingAHostMakesRoomUnderTheLimit(t *testing.T) {
	h := newHarness(t)
	h.setHostLimit(t, 1)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	if err := h.tryEnrol(t, "web-02", h.issueToken(t, "web-prod")); err == nil {
		t.Fatal("a second host enrolled into a fleet whose limit is one")
	}

	if err := h.scoped().RevokeHost(context.Background(), state.HostID); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if err := h.tryEnrol(t, "web-02", h.issueToken(t, "web-prod")); err != nil {
		t.Fatalf("revoking a host did not make room under the limit: %v", err)
	}
}

// TestNoLimitMeansNoLimit pins the default every self-hosted installation runs on.
//
// `hostseal-server serve` creates its fleet with no limit, and a fork that dropped these columns should
// behave the same. A default that quietly capped a fleet would be a licence check, which this is not.
func TestNoLimitMeansNoLimit(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"web-01", "web-02", "web-03", "web-04"} {
		if err := h.tryEnrol(t, name, h.issueToken(t, "web-prod")); err != nil {
			t.Fatalf("enrolling %s into an unlimited fleet: %v", name, err)
		}
	}

	// Explicitly clearing a limit restores that state, which is what `hostLimit: null` is for and why
	// the request type distinguishes it from an absent field.
	h.setHostLimit(t, 1)
	h.setHostLimit(t, nil)
	if err := h.tryEnrol(t, "web-05", h.issueToken(t, "web-prod")); err != nil {
		t.Fatalf("clearing a limit did not restore an unlimited fleet: %v", err)
	}
}

// TestASuspendedFleetIsRefusedRatherThanReached asserts what suspension is and what it is not.
//
// It is the control plane declining to answer. The agent keeps running, keeps applying the host's own
// local policy and keeps installing security updates on its own timer — which is exactly the state an
// unreachable control plane produces, and docs/INSTALL.md already documents that as supported. Nothing
// is uninstalled, nothing is deleted, and the host row is untouched.
func TestASuspendedFleetIsRefusedRatherThanReached(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)

	h.setSuspended(t, true)

	_, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:aaa",
	})
	status, code := refusal(t, err)
	if status != http.StatusForbidden || code != "tenant_suspended" {
		t.Fatalf("a suspended fleet's heartbeat answered %d %q, want 403 tenant_suspended", status, code)
	}

	// Enrolment is refused too, and again without consuming the token.
	token := h.issueToken(t, "web-prod")
	status, code = refusal(t, h.tryEnrol(t, "web-02", token))
	if status != http.StatusForbidden || code != "tenant_suspended" {
		t.Fatalf("enrolling into a suspended fleet answered %d %q, want 403 tenant_suspended", status, code)
	}

	// The host itself was not touched by any of it.
	host, err := h.scoped().GetHost(context.Background(), state.HostID)
	if err != nil {
		t.Fatalf("the host is gone from the store: %v", err)
	}
	if host.Revoked {
		t.Error("suspending a fleet revoked a host; suspension is refusal, not reach")
	}

	// And it is reversible, in one field, with nothing to repair.
	h.setSuspended(t, false)
	if _, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:aaa",
	}); err != nil {
		t.Fatalf("resuming a fleet did not restore its agents: %v", err)
	}
	if err := h.tryEnrol(t, "web-02", token); err != nil {
		t.Fatalf("the token refused by a suspension was not usable afterwards: %v", err)
	}
}

// TestUsageReportsSizeAndNothingElse is the disclosure this endpoint is allowed to make.
//
// It exists so that a hosting provider can count what it is charging for without holding an operator
// account inside the customer's fleet — a credential that could queue jobs, read facts and revoke
// hosts, held by somebody who wanted a number. The narrower answer is only narrower if it stays
// narrow, so this asserts what is absent as carefully as what is present.
func TestUsageReportsSizeAndNothingElse(t *testing.T) {
	h := newHarness(t)
	first := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	h.enrolHost(t, "database-primary", h.issueToken(t, "data"))
	if err := h.scoped().RevokeHost(context.Background(), first.HostID); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	h.setHostLimit(t, 3)

	status, body := h.adminJSON(t, h.platformToken, http.MethodGet,
		"/api/v1/tenants/"+string(h.tenant)+"/usage", nil)
	if status != http.StatusOK {
		t.Fatalf("usage answered %d: %s", status, body)
	}

	var usage struct {
		Hosts        int  `json:"hosts"`
		ActiveHosts  int  `json:"activeHosts"`
		RevokedHosts int  `json:"revokedHosts"`
		HostLimit    *int `json:"hostLimit"`
		Suspended    bool `json:"suspended"`
	}
	if err := json.Unmarshal(body, &usage); err != nil {
		t.Fatalf("decoding usage: %v", err)
	}
	if usage.Hosts != 2 || usage.ActiveHosts != 1 || usage.RevokedHosts != 1 {
		t.Errorf("usage reports %+v; the fleet holds two hosts, one of them revoked", usage)
	}
	if usage.HostLimit == nil || *usage.HostLimit != 3 {
		t.Errorf("usage reports hostLimit %v, want 3", usage.HostLimit)
	}

	// The hostnames are the point. A usage endpoint that leaked one would be a fleet listing with a
	// smaller response body, and the argument for adding it at all would be gone.
	for _, secret := range []string{"web-01", "database-primary", "web-prod", "data"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("the usage response contains %q; it must carry counts and no fleet contents: %s",
				secret, body)
		}
	}
}

// TestUsageIsPlatformOnly keeps the new route on the right side of the credential boundary.
//
// It is a platform route: it answers a question about a fleet that the fleet's own operators can answer
// for themselves by listing their hosts. An operator credential reaching it would not disclose anything
// new, but it would put a tenant-shaped question on a route whose handler does not scope by the
// caller's tenant — and the next person to extend that handler would be extending the wrong one.
func TestUsageIsPlatformOnly(t *testing.T) {
	h := newHarness(t)
	status, body := h.adminJSON(t, h.adminToken, http.MethodGet,
		"/api/v1/tenants/"+string(h.tenant)+"/usage", nil)
	if status != http.StatusForbidden {
		t.Fatalf("an operator credential got %d on the usage route, want 403: %s", status, body)
	}
}

// TestAHostLimitMustBeZeroOrMore refuses at the API what the schema would refuse at the constraint.
//
// A CHECK violation arrives as a 500, and a negative host limit is a caller's mistake they can correct
// from the message. Zero is allowed and means what it says: a fleet that may hold no hosts, which is
// what a tenant looks like between being created and being paid for.
func TestAHostLimitMustBeZeroOrMore(t *testing.T) {
	h := newHarness(t)
	status, body := h.adminJSON(t, h.platformToken, http.MethodPatch,
		"/api/v1/tenants/"+string(h.tenant), map[string]any{"hostLimit": -1})
	if status != http.StatusBadRequest {
		t.Fatalf("a negative host limit answered %d, want 400: %s", status, body)
	}
}
