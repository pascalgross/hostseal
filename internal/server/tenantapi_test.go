package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestGuaranteeThePlatformCredentialReachesNoTenantsData is the separation the platform role exists for.
//
// Running HostSeal for other people is a different job from reading what they run, and the difference
// has to be routing rather than restraint. A credential that could do both would make "the hoster
// cannot see your hosts" a promise about behaviour; this makes it a property of which handler answers.
//
// It is table-driven over the real operator surface rather than a sample of it, because the failure
// mode is one forgotten route — and the route somebody forgets is the one added last.
func TestGuaranteeThePlatformCredentialReachesNoTenantsData(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	for _, c := range []struct {
		// method and path are the operator route being attempted with a platform credential.
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/hosts"},
		{http.MethodGet, "/api/v1/hosts/" + state.HostID},
		{http.MethodPost, "/api/v1/hosts/" + state.HostID + "/revoke"},
		{http.MethodDelete, "/api/v1/hosts/" + state.HostID},
		{http.MethodGet, "/api/v1/tokens"},
		{http.MethodPost, "/api/v1/tokens"},
		{http.MethodGet, "/api/v1/catalogue"},
		{http.MethodGet, "/api/v1/jobs"},
		{http.MethodPost, "/api/v1/jobs"},
		{http.MethodGet, "/api/v1/jobs/01JANYTHING"},
		{http.MethodPost, "/api/v1/jobs/01JANYTHING/approve"},
		{http.MethodGet, "/api/v1/events"},
		{http.MethodGet, "/api/v1/services/failed"},
		{http.MethodGet, "/api/v1/alerts"},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			status, body := h.adminJSON(t, h.platformToken, c.method, c.path, map[string]any{})
			if status != http.StatusForbidden {
				t.Fatalf("a platform credential got %d on %s %s, want 403: %s",
					status, c.method, c.path, body)
			}
		})
	}
}

// TestWhoamiAnswersAPlatformCredentialWithNoTenant is the one route that answers both credentials.
//
// It used to be in the table above, and moving it out is a deliberate narrowing of what "reaches no
// tenant's data" is being asserted about rather than a hole in it. The guarantee is about a customer's
// hosts, jobs, tokens and results; the identity of the caller is not any of those. Refusing to say
// "you are the platform administrator" bought nothing and cost the interface its only way to tell
// somebody why the credential they had just pasted reached an empty console.
//
// So the assertion becomes the sharper one: the answer names the caller, says which role they hold,
// and carries no tenant at all — not a tenant with empty fields, which a client could render as a
// fleet called "".
func TestWhoamiAnswersAPlatformCredentialWithNoTenant(t *testing.T) {
	h := newHarness(t)

	status, body := h.adminJSON(t, h.platformToken, http.MethodGet, "/api/v1/whoami", nil)
	if status != http.StatusOK {
		t.Fatalf("a platform credential got %d on whoami: %s", status, body)
	}

	var answer struct {
		// Principal is the string every audit line would record for this caller.
		Principal string `json:"principal"`

		// Platform is what the interface reads to decide which of two interfaces to render.
		Platform bool `json:"platform"`

		// Tenant must be absent rather than empty.
		Tenant *json.RawMessage `json:"tenant"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		t.Fatalf("decoding whoami: %v", err)
	}
	if !answer.Platform {
		t.Error("whoami did not report a platform credential as one")
	}
	if answer.Tenant != nil {
		t.Errorf("whoami handed a platform credential a tenant: %s", *answer.Tenant)
	}
	if answer.Principal != "test:platform" {
		t.Errorf("whoami reports the principal %q", answer.Principal)
	}

	// The other side of it: an operator still gets their fleet, so widening the route did not cost the
	// answer the toolbar exists to render.
	status, body = h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/whoami", nil)
	if status != http.StatusOK {
		t.Fatalf("an operator got %d on whoami: %s", status, body)
	}
	var operatorAnswer struct {
		// Platform must be false for an operator.
		Platform bool `json:"platform"`

		// Tenant is the fleet this credential acts in.
		Tenant *struct {
			// Slug is the fleet's handle, which is what the assertion is about.
			Slug string `json:"slug"`
		} `json:"tenant"`
	}
	if err := json.Unmarshal(body, &operatorAnswer); err != nil {
		t.Fatalf("decoding whoami: %v", err)
	}
	if operatorAnswer.Platform {
		t.Error("an operator credential was reported as a platform one")
	}
	if operatorAnswer.Tenant == nil || operatorAnswer.Tenant.Slug != "alpha" {
		t.Errorf("an operator's whoami named the fleet %+v", operatorAnswer.Tenant)
	}
}

// TestGuaranteeAnOperatorCredentialCannotAdministerTenants is the same boundary from the other side.
//
// A customer's operator must not be able to see that other customers exist, let alone create, rename or
// delete one. The refusal is the same shape a platform credential gets on an operator route, so neither
// answer tells its holder anything about the installation beyond "not this credential".
func TestGuaranteeAnOperatorCredentialCannotAdministerTenants(t *testing.T) {
	h := newHarness(t)

	for _, c := range []struct {
		// method and path are the tenant route being attempted with an operator credential.
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/tenants"},
		{http.MethodPost, "/api/v1/tenants"},
		{http.MethodGet, "/api/v1/tenants/" + string(h.otherTenant)},
		{http.MethodPatch, "/api/v1/tenants/" + string(h.otherTenant)},
		{http.MethodDelete, "/api/v1/tenants/" + string(h.otherTenant)},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			status, body := h.adminJSON(t, h.adminToken, c.method, c.path, map[string]any{})
			if status != http.StatusForbidden {
				t.Fatalf("an operator credential got %d on %s %s, want 403: %s",
					status, c.method, c.path, body)
			}
		})
	}

	// And the neighbour still exists afterwards, which is the assertion that would catch a handler that
	// refused after doing the work rather than before.
	status, body := h.adminJSON(t, h.platformToken, http.MethodGet,
		"/api/v1/tenants/"+string(h.otherTenant), nil)
	if status != http.StatusOK {
		t.Fatalf("the neighbouring tenant is gone after an operator tried to delete it: %d %s", status, body)
	}
}

// TestAPlatformAdministratorProvisionsAFleet is the operation a hosting provider automates.
//
// It deliberately stops short of issuing that fleet a credential. Minting one belongs to the identity
// provider, and a tenant API that handed out tokens would let the platform administrator authenticate
// as any customer — which is the exact separation the role exists to keep.
func TestAPlatformAdministratorProvisionsAFleet(t *testing.T) {
	h := newHarness(t)

	status, body := h.adminJSON(t, h.platformToken, http.MethodPost, "/api/v1/tenants", map[string]any{
		"slug":        "acme",
		"displayName": "Acme Ltd",
	})
	if status != http.StatusCreated {
		t.Fatalf("creating a tenant returned %d: %s", status, body)
	}

	var created struct {
		// ID and Slug identify the new fleet, and ApprovalMode is what it defaults to.
		ID           string `json:"id"`
		Slug         string `json:"slug"`
		ApprovalMode string `json:"approvalMode"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decoding the tenant: %v", err)
	}
	if created.Slug != "acme" || created.ID == "" {
		t.Fatalf("the created tenant is %+v", created)
	}
	// A new fleet releases destructive jobs on the strength of their offline signature alone. Requiring
	// a second person by default would hand every new customer a tier they cannot reach until they have
	// hired somebody.
	if created.ApprovalMode != "none" {
		t.Errorf("a new tenant defaults to approval mode %q, want none", created.ApprovalMode)
	}

	// A duplicate slug is refused, because the slug is what logs and support tickets refer to.
	if status, body := h.adminJSON(t, h.platformToken, http.MethodPost, "/api/v1/tenants", map[string]any{
		"slug": "acme",
	}); status != http.StatusConflict {
		t.Errorf("a duplicate slug returned %d, want 409: %s", status, body)
	}

	// And a slug that could be mistaken for a path is refused outright.
	for _, bad := range []string{"../admin", "Acme", "has space", ""} {
		if status, _ := h.adminJSON(t, h.platformToken, http.MethodPost, "/api/v1/tenants", map[string]any{
			"slug": bad,
		}); status != http.StatusBadRequest {
			t.Errorf("slug %q was accepted with %d", bad, status)
		}
	}
}

// TestChangingAFleetsApprovalModeAppliesToTheNextJobAndNotTheLast is the rule that makes the setting
// safe to expose at all.
//
// A job records what it required when it was created. Reading the fleet's mode at approval time would
// defeat second-person approval in two calls: queue the job, relax the fleet, release it yourself. The
// store enforces it and has its own test; this is the same property through the API, because the API is
// where both halves of that sequence are reachable by the same credential.
func TestChangingAFleetsApprovalModeAppliesToTheNextJobAndNotTheLast(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	request, _ := signedRebootRequest(t, state.HostID)
	if status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", request); status != http.StatusCreated {
		t.Fatalf("queueing returned %d: %s", status, body)
	}
	jobID := request["id"].(string)

	// The platform administrator relaxes the fleet, which is a thing they are allowed to do.
	if status, body := h.adminJSON(t, h.platformToken, http.MethodPatch,
		"/api/v1/tenants/"+string(h.tenant), map[string]any{"approvalMode": "none"}); status != http.StatusOK {
		t.Fatalf("relaxing the tenant returned %d: %s", status, body)
	}

	// And the job queued a moment ago still needs the second person it was created under.
	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs/"+jobID+"/approve", nil)
	if status != http.StatusConflict {
		t.Fatalf("the creator released their own job after relaxing the fleet: %d %s", status, body)
	}

	// A job created afterwards does not, which is the half that shows the setting took effect at all.
	next, _ := signedRebootRequest(t, state.HostID)
	next["id"] = "01JSECONDREBOOT"
	next["nonce"] = "nonce-second-reboot"
	// Re-signed for the new id and nonce by signedRebootRequest's own key, so this asserts the approval
	// mode rather than the signature: a request that failed verification would be refused earlier and
	// for a different reason.
	status, body = h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", next)
	if status != http.StatusCreated {
		t.Fatalf("queueing under the relaxed mode returned %d: %s", status, body)
	}
	if view := jobViewOf(t, body); view["state"] != "queued" {
		t.Errorf("a job created under approval mode none is in state %v, want queued", view["state"])
	}
}

// TestRetiringAFleetRemovesItAndRejectsAWebhookNobodyShouldConfigure covers the two writes the fleets
// screen makes and the API had no test for.
//
// Deletion was reachable and untested, which is the combination the interface has now made ordinary:
// there is a control for it, so the route is what stands between a mistyped confirmation and a
// customer's history. The webhook check is here rather than in internal/notify because this is where an
// operator meets it — the sink's own refusal is the backstop for rows written before the rule.
func TestRetiringAFleetRemovesItAndRejectsAWebhookNobodyShouldConfigure(t *testing.T) {
	h := newHarness(t)

	status, body := h.adminJSON(t, h.platformToken, http.MethodPost, "/api/v1/tenants", map[string]any{
		"slug": "acme",
	})
	if status != http.StatusCreated {
		t.Fatalf("creating a tenant returned %d: %s", status, body)
	}
	var created struct {
		// ID is what the delete and patch routes name.
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decoding the tenant: %v", err)
	}

	// An http webhook is refused where it is configured, so an operator learns of it now rather than
	// from an event that did not arrive.
	if status, body := h.adminJSON(t, h.platformToken, http.MethodPatch,
		"/api/v1/tenants/"+created.ID, map[string]any{
			"webhookUrl": "http://hooks.example.org/acme",
		}); status != http.StatusBadRequest {
		t.Errorf("a plaintext webhook was accepted with %d: %s", status, body)
	}
	if status, body := h.adminJSON(t, h.platformToken, http.MethodPatch,
		"/api/v1/tenants/"+created.ID, map[string]any{
			"webhookUrl": "https://hooks.example.org/acme",
		}); status != http.StatusOK {
		t.Errorf("an https webhook was refused with %d: %s", status, body)
	}

	// The delete itself, and then the same delete again: the second must be a 404 rather than a second
	// success, or "it worked" would be what a retirement of something already gone looks like.
	if status, body := h.adminJSON(t, h.platformToken, http.MethodDelete,
		"/api/v1/tenants/"+created.ID, nil); status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("retiring the fleet returned %d: %s", status, body)
	}
	if status, _ := h.adminJSON(t, h.platformToken, http.MethodDelete,
		"/api/v1/tenants/"+created.ID, nil); status != http.StatusNotFound {
		t.Errorf("retiring an already-retired fleet returned %d, want 404", status)
	}

	// And it is gone from the listing, which is what the screen reads.
	status, body = h.adminJSON(t, h.platformToken, http.MethodGet, "/api/v1/tenants", nil)
	if status != http.StatusOK {
		t.Fatalf("listing tenants returned %d: %s", status, body)
	}
	if strings.Contains(string(body), created.ID) {
		t.Errorf("the retired fleet is still listed: %s", body)
	}
}
