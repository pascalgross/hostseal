package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/canonical"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/server"
	"github.com/pascalgross/hostseal/internal/store"
)

// templateBody is the cloud-init document most of these tests store.
//
// It carries one placeholder of each interesting kind: an ordinary parameter and the reserved
// enrolment-token one, plus a password field so the secret-shape warning path is exercised on the same
// document operators will actually write.
const templateBody = "#cloud-config\nhostname: {{hostname}}\n" +
	"runcmd:\n  - hostseal enroll --token {{enrollmentToken}}\n"

// saveTemplate stores one template version through the API and returns the decoded response.
func (h *harness) saveTemplate(t *testing.T, token string, body map[string]any) map[string]any {
	t.Helper()
	status, raw := h.adminJSON(t, token, http.MethodPost, "/api/v1/templates", body)
	if status != http.StatusCreated {
		t.Fatalf("saving a template: %d %s", status, raw)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decoding the save response: %v", err)
	}
	return decoded
}

// TestTemplateLifecycle walks a template from first save to a superseding version.
//
// One test for the whole arc because the pieces are only meaningful together: versioning matters
// because old versions stay readable, warnings matter because they arrive at save time, and the sealed
// column matters because the API round-trips plaintext while the store never holds it.
func TestTemplateLifecycle(t *testing.T) {
	h := newHarness(t)

	saved := h.saveTemplate(t, h.adminToken, map[string]any{
		"name": "standard-server",
		"body": templateBody + "password: hunter2\n",
	})
	if saved["version"].(float64) != 1 || saved["signed"].(bool) {
		t.Fatalf("first save: %+v", saved)
	}
	warnings := saved["warnings"].([]any)
	if len(warnings) != 1 || !strings.Contains(warnings[0].(string), "user-data.txt") {
		t.Fatalf("the password field did not warn with its consequence: %+v", warnings)
	}
	placeholders := saved["placeholders"].([]any)
	if len(placeholders) != 2 {
		t.Fatalf("placeholders: %+v", placeholders)
	}

	// The store holds ciphertext, not the document. This reaches past the API deliberately: the API
	// can only prove the round trip, and the property is about what a database dump would yield.
	stored, err := h.scoped().GetTemplateVersion(context.Background(), "standard-server", 1)
	if err != nil {
		t.Fatalf("reading the stored version: %v", err)
	}
	if strings.Contains(string(stored.BodySealed), "hunter2") ||
		strings.Contains(string(stored.BodySealed), "cloud-config") {
		t.Fatal("the stored template body is not encrypted")
	}

	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": templateBody})

	status, raw := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/templates", nil)
	if status != http.StatusOK {
		t.Fatalf("listing: %d %s", status, raw)
	}
	var listing struct {
		// Templates is the summary list under test.
		Templates []struct {
			// Name identifies the template.
			Name string `json:"name"`

			// LatestVersion is the highest stored version.
			LatestVersion int `json:"latestVersion"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(raw, &listing); err != nil {
		t.Fatalf("decoding the listing: %v", err)
	}
	if len(listing.Templates) != 1 || listing.Templates[0].LatestVersion != 2 {
		t.Fatalf("listing: %+v", listing)
	}

	// The superseded version stays readable by number, which is what a bootstrap record resolves.
	status, raw = h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/templates/standard-server?version=1", nil)
	if status != http.StatusOK {
		t.Fatalf("reading version 1: %d %s", status, raw)
	}
	var v1 map[string]any
	if err := json.Unmarshal(raw, &v1); err != nil {
		t.Fatalf("decoding version 1: %v", err)
	}
	if !strings.Contains(v1["body"].(string), "hunter2") {
		t.Fatalf("version 1 no longer resolves to its own bytes: %+v", v1)
	}
}

// TestTemplateBodiesAreNeverCacheable pins the header that keeps a body out of shared caches.
func TestTemplateBodiesAreNeverCacheable(t *testing.T) {
	h := newHarness(t)
	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": templateBody})

	for _, call := range []struct {
		// method and path identify the request under test.
		method, path string

		// body is the request payload, nil for a GET.
		body map[string]any
	}{
		{http.MethodGet, "/api/v1/templates/standard-server", nil},
		{http.MethodPost, "/api/v1/templates/standard-server/render",
			map[string]any{"params": map[string]string{"hostname": "web-01"}}},
	} {
		payload := []byte(nil)
		if call.body != nil {
			payload, _ = json.Marshal(call.body)
		}
		req, err := http.NewRequest(call.method, h.server.URL+call.path, strings.NewReader(string(payload)))
		if err != nil {
			t.Fatalf("building the request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+h.adminToken)
		res, err := h.server.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", call.method, call.path, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: %d", call.method, call.path, res.StatusCode)
		}
		if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s %s answered with Cache-Control %q; a rendered template is a credential and a "+
				"body is where operators put secrets", call.method, call.path, cc)
		}
	}
}

// TestRenderMintsTheTokenAndSubstitutes is the render path end to end.
func TestRenderMintsTheTokenAndSubstitutes(t *testing.T) {
	h := newHarness(t)
	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": templateBody})

	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/render", map[string]any{
			"params": map[string]string{"hostname": "web-01"},
			"token":  map[string]any{"group": "web-prod"},
		})
	if status != http.StatusOK {
		t.Fatalf("rendering: %d %s", status, raw)
	}
	var rendered struct {
		// UserData is the rendered document.
		UserData string `json:"userData"`

		// TokenExpiresAt reports the minted token's deadline.
		TokenExpiresAt *time.Time `json:"tokenExpiresAt"`
	}
	if err := json.Unmarshal(raw, &rendered); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if !strings.Contains(rendered.UserData, "hostname: web-01") {
		t.Fatalf("the parameter was not substituted: %q", rendered.UserData)
	}
	if strings.Contains(rendered.UserData, "{{") {
		t.Fatalf("a placeholder survived rendering: %q", rendered.UserData)
	}
	if rendered.TokenExpiresAt == nil {
		t.Fatal("no token was minted for a template that substitutes one")
	}

	// The minted token is a real one: it appears in the listing and it enrols a host. That is what
	// "the output carries a live enrolment token" means, and it is why the output is a credential.
	token := strings.TrimSpace(strings.Split(strings.Split(rendered.UserData, "--token ")[1], "\n")[0])
	state := h.enrolHost(t, "rendered-host", token)
	if state.HostID == "" {
		t.Fatal("the minted token did not enrol a host")
	}

	// Strictness: a missing parameter and a caller-supplied token are both refused with names.
	status, raw = h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/render", map[string]any{})
	if status != http.StatusBadRequest || !strings.Contains(string(raw), "hostname") {
		t.Fatalf("a missing parameter was not refused by name: %d %s", status, raw)
	}
	status, raw = h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/render", map[string]any{
			"params": map[string]string{"hostname": "web-01", "enrollmentToken": "pasted"},
		})
	if status != http.StatusBadRequest || !strings.Contains(string(raw), "minted") {
		t.Fatalf("a caller-supplied token was not refused: %d %s", status, raw)
	}
}

// TestTemplateSavesAreValidated pins the request-shape refusals.
func TestTemplateSavesAreValidated(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		// name labels the case.
		name string

		// body is the save request.
		body map[string]any

		// fragment must appear in the refusal.
		fragment string
	}{
		{"uppercase name", map[string]any{"name": "Standard", "body": "x"}, "lower-case"},
		{"empty body", map[string]any{"name": "standard-server"}, "body is required"},
		{"partial signature", map[string]any{
			"name": "standard-server", "body": "x", "signature": "c2ln",
		}, "together"},
		{"unknown algorithm", map[string]any{
			"name": "standard-server", "body": "x", "signature": "c2ln",
			"signerKeyId": "ops", "signerAlgorithm": "rsa",
		}, "ed25519"},
		{"undecodable signature", map[string]any{
			"name": "standard-server", "body": "x", "signature": "!!!",
			"signerKeyId": "ops", "signerAlgorithm": "ed25519",
		}, "base64"},
	} {
		status, raw := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/templates", tc.body)
		if status != http.StatusBadRequest || !strings.Contains(string(raw), tc.fragment) {
			t.Errorf("%s: %d %s", tc.name, status, raw)
		}
	}
}

// TestTemplatesAreTenantScoped proves one fleet's templates are invisible to another, through the API.
func TestTemplatesAreTenantScoped(t *testing.T) {
	h := newHarness(t)
	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": templateBody})

	status, raw := h.adminJSON(t, h.otherToken, http.MethodGet, "/api/v1/templates/standard-server", nil)
	if status != http.StatusNotFound {
		t.Fatalf("another tenant read the template: %d %s", status, raw)
	}
	status, raw = h.adminJSON(t, h.otherToken, http.MethodGet, "/api/v1/templates", nil)
	if status != http.StatusOK || strings.Contains(string(raw), "standard-server") {
		t.Fatalf("another tenant's listing names the template: %d %s", status, raw)
	}
}

// enrollDirect posts an enrolment request straight to the endpoint, bypassing the agent's own
// pre-checks.
//
// The agent refuses --bootstrap without a local trust anchor before it ever speaks to the server, and
// that anchor lives at a fixed root-owned path a test cannot write. What these tests need is the
// server's half of the conversation, so they speak the protocol directly with a freshly generated CSR.
func (h *harness) enrollDirect(t *testing.T, req protocol.EnrollRequest) (int, protocol.EnrollResponse, []byte) {
	t.Helper()

	if req.CSR == "" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating a key: %v", err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "hostseal-agent"},
		}, key)
		if err != nil {
			t.Fatalf("creating a CSR: %v", err)
		}
		req.CSR = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	}

	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("encoding the enrolment request: %v", err)
	}
	res, err := h.server.Client().Post(h.server.URL+protocol.PathEnroll, "application/json",
		strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("posting the enrolment: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := readAll(res)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	var decoded protocol.EnrollResponse
	_ = json.Unmarshal(raw, &decoded)
	return res.StatusCode, decoded, raw
}

// issueBootstrapToken stores an enrolment token that authorises one bootstrap template.
//
// Directly in the store rather than through the API, because half of these tests need a token naming a
// template the API would refuse to name — an unsigned one — to prove the enrolment path refuses it
// again rather than trusting mint-time validation that a migration or a direct write could have
// bypassed.
func (h *harness) issueBootstrapToken(t *testing.T, bootstrap string) string {
	t.Helper()

	token, hash, err := server.NewEnrollmentToken()
	if err != nil {
		t.Fatalf("generating a token: %v", err)
	}
	if err := h.scoped().CreateEnrollmentToken(context.Background(), store.EnrollmentToken{
		Hash:      hash,
		Label:     "bootstrap-test",
		Group:     "web-prod",
		Bootstrap: bootstrap,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("storing the token: %v", err)
	}
	return token
}

// TestGuaranteeTheControlPlaneCannotSignABootstrapTemplate is issue #19's central property, asserted
// rather than claimed in a comment.
//
// The signature on a bootstrap template is not the control plane's to make. An unsigned template is
// therefore a refusal — loudly, before the token is consumed — and never an invitation for the server
// to sign with anything it holds, including the online key it legitimately signs routine jobs with. A
// signed template is handed over byte-for-byte as the operator's tool produced it.
func TestGuaranteeTheControlPlaneCannotSignABootstrapTemplate(t *testing.T) {
	h := newHarness(t)

	// An unsigned template, stored directly so the mint-time validation cannot pre-empt the check
	// under test.
	if _, err := h.scoped().CreateTemplateVersion(context.Background(), store.TemplateVersion{
		Name: "unsigned", BodySealed: sealForHarness(t, h, "#cloud-config\n{}"),
		CreatedAt: time.Now().UTC(), CreatedBy: "test",
	}); err != nil {
		t.Fatalf("storing the unsigned template: %v", err)
	}
	token := h.issueBootstrapToken(t, "unsigned")

	status, _, raw := h.enrollDirect(t, protocol.EnrollRequest{
		Token: token, Hostname: "web-01", RequestedBootstrap: "unsigned",
	})
	if status != http.StatusConflict || !strings.Contains(string(raw), "unsigned_template") {
		t.Fatalf("an unsigned template was not refused: %d %s", status, raw)
	}
	if strings.Contains(string(raw), `"bootstrap"`) && strings.Contains(string(raw), `"body"`) {
		t.Fatalf("the refusal carried a template body: %s", raw)
	}

	// The refusal consumed nothing: the same token still enrols the machine without a bootstrap,
	// which is the retry an operator actually makes.
	status, res, raw := h.enrollDirect(t, protocol.EnrollRequest{Token: token, Hostname: "web-01"})
	if status != http.StatusOK || res.HostID == "" {
		t.Fatalf("the token did not survive the refusal: %d %s", status, raw)
	}

	// A signed template, produced the way the operator's tool produces it: an offline key, the shared
	// canonical payload, and nothing of the server's involved.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating the operator key: %v", err)
	}
	body := "#cloud-config\nhostname: bootstrapped\n"
	payload, err := canonical.Marshal(protocol.Bootstrap{Name: "standard-server", Body: body}.SignedPayload())
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))

	h.saveTemplate(t, h.adminToken, map[string]any{
		"name": "standard-server", "body": body,
		"signature": signature, "signerKeyId": "ops-laptop", "signerAlgorithm": "ed25519",
	})

	status, res, raw = h.enrollDirect(t, protocol.EnrollRequest{
		Token: h.issueBootstrapToken(t, "standard-server"), Hostname: "web-02",
		RequestedBootstrap: "standard-server",
	})
	if status != http.StatusOK || res.Bootstrap == nil {
		t.Fatalf("a signed template was not issued: %d %s", status, raw)
	}
	if res.Bootstrap.Signature != signature || res.Bootstrap.SignerKeyID != "ops-laptop" {
		t.Fatal("the stored signature was not handed over verbatim")
	}
	if res.Bootstrap.Body != body || res.Bootstrap.Name != "standard-server" {
		t.Fatalf("the template changed in transit: %+v", res.Bootstrap)
	}
	// And it verifies exactly as the enrolling host will verify it: over the canonical payload rebuilt
	// from what arrived, against the operator's key. A control plane that had re-signed or altered
	// anything fails here.
	arrived, err := canonical.Marshal(res.Bootstrap.SignedPayload())
	if err != nil {
		t.Fatalf("canonicalising the response: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(res.Bootstrap.Signature)
	if err != nil {
		t.Fatalf("decoding the response signature: %v", err)
	}
	if !ed25519.Verify(public, arrived, sig) {
		t.Fatal("the issued template does not verify against the operator's key")
	}
}

// TestGuaranteeABootstrapRequestNeedsItsTokensAuthority proves possession of a token is not the
// authority to choose a template.
func TestGuaranteeABootstrapRequestNeedsItsTokensAuthority(t *testing.T) {
	h := newHarness(t)
	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": "#cloud-config\n{}"})

	// A token minted with no bootstrap authorises none, whatever exists.
	token := h.issueToken(t, "web-prod")
	status, _, raw := h.enrollDirect(t, protocol.EnrollRequest{
		Token: token, Hostname: "web-01", RequestedBootstrap: "standard-server",
	})
	if status != http.StatusForbidden || !strings.Contains(string(raw), "bootstrap_not_authorised") {
		t.Fatalf("a plain token requested a bootstrap: %d %s", status, raw)
	}

	// And the refusal burnt nothing.
	status, res, raw := h.enrollDirect(t, protocol.EnrollRequest{Token: token, Hostname: "web-01"})
	if status != http.StatusOK || res.HostID == "" {
		t.Fatalf("the token did not survive: %d %s", status, raw)
	}
}

// TestGuaranteeABootstrapTemplateStaysInsideItsTenant proves a template signed for one fleet cannot be
// issued to another, even under the same name.
func TestGuaranteeABootstrapTemplateStaysInsideItsTenant(t *testing.T) {
	h := newHarness(t)

	// Alpha holds a signed standard-server; beta holds nothing.
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating the operator key: %v", err)
	}
	body := "#cloud-config\nhostname: alpha-only\n"
	payload, err := canonical.Marshal(protocol.Bootstrap{Name: "standard-server", Body: body}.SignedPayload())
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	h.saveTemplate(t, h.adminToken, map[string]any{
		"name": "standard-server", "body": body,
		"signature":   base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload)),
		"signerKeyId": "ops-laptop", "signerAlgorithm": "ed25519",
	})

	// A token in beta naming the same template name reaches beta's shelf, which is empty.
	token, hash, err := server.NewEnrollmentToken()
	if err != nil {
		t.Fatalf("generating a token: %v", err)
	}
	if err := h.store.In(h.otherTenant).CreateEnrollmentToken(context.Background(), store.EnrollmentToken{
		Hash: hash, Label: "beta", Bootstrap: "standard-server",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("storing beta's token: %v", err)
	}

	status, _, raw := h.enrollDirect(t, protocol.EnrollRequest{
		Token: token, Hostname: "intruder", RequestedBootstrap: "standard-server",
	})
	if status != http.StatusConflict || !strings.Contains(string(raw), "no_such_template") {
		t.Fatalf("beta's enrolment reached alpha's template: %d %s", status, raw)
	}
	if strings.Contains(string(raw), "alpha-only") {
		t.Fatalf("the refusal leaked alpha's template body: %s", raw)
	}
}

// sealForHarness encrypts a body with the harness server's own template key.
//
// Tests that store a template directly — bypassing the API on purpose — still have to store what the
// server would: ciphertext under the key beside the CA, which the enrolment path will try to open.
func sealForHarness(t *testing.T, h *harness, body string) []byte {
	t.Helper()
	sealed, err := h.templateKey.Seal([]byte(body))
	if err != nil {
		t.Fatalf("sealing a fixture body: %v", err)
	}
	return sealed
}

// countTokens reports how many enrolment tokens this fleet holds.
func (h *harness) countTokens(t *testing.T) int {
	t.Helper()
	tokens, err := h.scoped().ListEnrollmentTokens(context.Background())
	if err != nil {
		t.Fatalf("listing tokens: %v", err)
	}
	return len(tokens)
}

// TestARefusedRenderMintsNoToken keeps a failed render from leaving a live credential behind.
//
// A render that cannot finish is an ordinary mistake — a placeholder nobody filled in, a bootstrap
// named with a typo — and the operator sees an error and tries again. What must not happen is a
// working enrolment token being minted first and then orphaned by the failure: nobody was shown it,
// nobody can revoke it by name because nobody knows it exists, and it is valid until it expires.
func TestARefusedRenderMintsNoToken(t *testing.T) {
	h := newHarness(t)
	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": templateBody})
	before := h.countTokens(t)

	// A missing placeholder: the body needs a hostname and this render supplies nothing.
	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/render", map[string]any{"params": map[string]string{}})
	if status != http.StatusBadRequest {
		t.Fatalf("a render with no hostname answered %d %s", status, raw)
	}
	if after := h.countTokens(t); after != before {
		t.Fatalf("a refused render minted %d token(s)", after-before)
	}

	// A bootstrap the fleet does not have: refused for the same reason a mint would be, and before
	// anything is minted.
	status, raw = h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/render", map[string]any{
			"params": map[string]string{"hostname": "web-01"},
			"token":  map[string]any{"bootstrap": "no-such-template"},
		})
	if status != http.StatusNotFound {
		t.Fatalf("a render naming an unknown bootstrap answered %d %s", status, raw)
	}
	if after := h.countTokens(t); after != before {
		t.Fatalf("a render refused for its bootstrap minted %d token(s)", after-before)
	}

	// And the same request without the bad bootstrap does mint one, so the checks above are not
	// passing because rendering is broken.
	status, raw = h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/render", map[string]any{
			"params": map[string]string{"hostname": "web-01"},
		})
	if status != http.StatusOK {
		t.Fatalf("a complete render answered %d %s", status, raw)
	}
	if after := h.countTokens(t); after != before+1 {
		t.Fatalf("a successful render minted %d token(s)", after-before)
	}
}

// TestARenderRefusesAnUnsignedBootstrap applies the mint-time check to the second place that mints.
//
// A token may only name a template an enrolment could actually be issued, and an unsigned one cannot
// be: the agent verifies a bootstrap against its own trusted-signers, which this control plane holds
// no key for. Catching it here fails a person at a keyboard instead of a machine in a datacentre.
func TestARenderRefusesAnUnsignedBootstrap(t *testing.T) {
	h := newHarness(t)
	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": templateBody})

	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/render", map[string]any{
			"params": map[string]string{"hostname": "web-01"},
			"token":  map[string]any{"bootstrap": "standard-server"},
		})
	if status != http.StatusConflict {
		t.Fatalf("a render naming an unsigned bootstrap answered %d %s", status, raw)
	}
	if !strings.Contains(string(raw), "sign-template") {
		t.Fatalf("the refusal does not name the way out: %s", raw)
	}
}

// TestABootstrapThatMintsItsOwnTokenIsRefusedAtEveryPoint pins the one substitution a verbatim body
// cannot carry, and the much larger set it must.
//
// {{enrollmentToken}} is minted by the render endpoint, and a bootstrap never goes through it: the
// body is handed to the host exactly as the offline signature covers it. So a bootstrap carrying that
// placeholder reaches cloud-init with the braces intact and enrols nothing — there is no reading of it
// that works, which is what makes a refusal right rather than officious.
//
// Every other brace pair is the opposite case and the reason this check is one name wide. cloud-init
// resolves its own `## template: jinja` documents on the machine, and verbatim delivery is precisely
// what lets it: a per-host bootstrap is written that way. A broader check would refuse the templates
// this path exists to carry, and because the body is signed by a key the control plane does not hold,
// an operator could not edit their way past it without re-signing offline.
func TestABootstrapThatMintsItsOwnTokenIsRefusedAtEveryPoint(t *testing.T) {
	h := newHarness(t)
	store1 := func(name, body string) {
		t.Helper()
		if _, err := h.scoped().CreateTemplateVersion(context.Background(), store.TemplateVersion{
			Name: name, BodySealed: sealForHarness(t, h, body),
			Signature: "c2lnbmF0dXJl", SignerKeyID: "ops-1", SignerAlgorithm: "ed25519",
			CreatedAt: time.Now().UTC(), CreatedBy: "test",
		}); err != nil {
			t.Fatalf("storing %s: %v", name, err)
		}
	}

	// Signed, so the refusal under test is the placeholder one and not the unsigned-template check
	// that runs before it.
	store1("mints-a-token", templateBody)

	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/tokens", map[string]any{
		"label": "web", "group": "web-prod", "bootstrap": "mints-a-token",
	})
	if status != http.StatusConflict || !strings.Contains(string(raw), "unrendered_template") {
		t.Fatalf("a bootstrap substituting the reserved placeholder was issued: %d %s", status, raw)
	}
	if !strings.Contains(string(raw), "enrollmentToken") {
		t.Fatalf("the refusal does not name the placeholder that caused it: %s", raw)
	}
	if h.countTokens(t) != 0 {
		t.Fatalf("the refusal minted a token anyway")
	}

	// The render endpoint mints tokens too, and its token block names a bootstrap the same way. A
	// check that lived in only one of the two would be a check the other silently skipped.
	h.saveTemplate(t, h.adminToken, map[string]any{"name": "userdata", "body": templateBody})
	status, raw = h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/templates/userdata/render",
		map[string]any{
			"params": map[string]string{"hostname": "web-01"},
			"token":  map[string]any{"group": "web-prod", "bootstrap": "mints-a-token"},
		})
	if status != http.StatusConflict || !strings.Contains(string(raw), "unrendered_template") {
		t.Fatalf("the render path issued it: %d %s", status, raw)
	}
	if h.countTokens(t) != 0 {
		t.Fatalf("the render path minted a token before refusing")
	}

	// The half that matters more, because getting it wrong breaks templates that were working: a body
	// full of braces that are not HostSeal's is issuable. This is a real cloud-init jinja document —
	// the header cloud-init requires, a variable it resolves on the machine, and a write_files payload
	// carrying somebody else's template syntax to disk.
	store1("jinja", "## template: jinja\n#cloud-config\nhostname: {{ v1.local_hostname }}\n"+
		"write_files:\n  - path: /etc/prometheus/rules.yml\n    content: '{{ .Labels.alertname }}'\n")
	if status, raw := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/tokens", map[string]any{
		"label": "web", "group": "web-prod", "bootstrap": "jinja",
	}); status != http.StatusCreated {
		t.Fatalf("a cloud-init jinja bootstrap was refused, which is the class verbatim delivery "+
			"exists to carry: %d %s", status, raw)
	}
}

// TestABootstrapIsCheckedWhereItsBytesAreChosen closes the window between minting and enrolling.
//
// A token names a template, never a version. The row resolved when the token was minted and the row
// resolved when a host enrols are two separate reads of "the latest", and storing a new version during
// a token's lifetime is ordinary work — the default token lifetime is a day. So a check that ran only
// at mint time would let exactly the body it exists to refuse through, at the one moment it matters.
// This is the same reason the signature is checked in both places rather than trusted from the first.
func TestABootstrapIsCheckedWhereItsBytesAreChosen(t *testing.T) {
	h := newHarness(t)
	signed := func(body string) store.TemplateVersion {
		return store.TemplateVersion{
			Name: "standard-server", BodySealed: sealForHarness(t, h, body),
			Signature: "c2lnbmF0dXJl", SignerKeyID: "ops-1", SignerAlgorithm: "ed25519",
			CreatedAt: time.Now().UTC(), CreatedBy: "test",
		}
	}

	// v1 is issuable, and a token is minted naming it.
	if _, err := h.scoped().CreateTemplateVersion(context.Background(),
		signed("#cloud-config\nhostname: fixed\n")); err != nil {
		t.Fatalf("storing v1: %v", err)
	}
	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/tokens", map[string]any{
		"label": "web", "group": "web-prod", "bootstrap": "standard-server",
	})
	if status != http.StatusCreated {
		t.Fatalf("minting against a clean v1: %d %s", status, raw)
	}
	var minted struct {
		// Token is the credential a host would enrol with.
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &minted); err != nil {
		t.Fatalf("decoding the token: %v", err)
	}

	// v2 lands afterwards, signed, and substitutes the one thing a verbatim body cannot.
	if _, err := h.scoped().CreateTemplateVersion(context.Background(),
		signed("#cloud-config\nruncmd:\n  - hostseal enroll --token {{enrollmentToken}}\n")); err != nil {
		t.Fatalf("storing v2: %v", err)
	}

	status, _, raw = h.enrollDirect(t, protocol.EnrollRequest{
		Token: minted.Token, Hostname: "web-01", RequestedBootstrap: "standard-server",
	})
	if status != http.StatusConflict || !strings.Contains(string(raw), "unrendered_template") {
		t.Fatalf("a version stored after the token was minted reached the host: %d %s", status, raw)
	}
	if strings.Contains(string(raw), "enrollmentToken}}") && strings.Contains(string(raw), "runcmd") {
		t.Fatalf("the refusal carried the template body: %s", raw)
	}

	// The refusal consumed nothing: the same token still enrols the machine without a bootstrap,
	// which is the retry an operator actually makes.
	status, res, raw := h.enrollDirect(t, protocol.EnrollRequest{
		Token: minted.Token, Hostname: "web-01",
	})
	if status != http.StatusOK || res.HostID == "" {
		t.Fatalf("the token did not survive the refusal: %d %s", status, raw)
	}
}

// saveSignedTemplate stores one signed version through the API, signed the way an operator's offline
// tool signs it, and returns the base64 signature.
//
// A helper because more than one test now needs a template that is actually issuable at enrolment:
// the interesting refusals are the ones that happen to a template which would otherwise have been
// handed over, and an unsigned fixture would be refused a step earlier for an unrelated reason.
func (h *harness) saveSignedTemplate(t *testing.T, name, body string) string {
	t.Helper()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating the operator key: %v", err)
	}
	payload, err := canonical.Marshal(protocol.Bootstrap{Name: name, Body: body}.SignedPayload())
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	h.saveTemplate(t, h.adminToken, map[string]any{
		"name": name, "body": body,
		"signature": signature, "signerKeyId": "ops-laptop", "signerAlgorithm": "ed25519",
	})
	return signature
}

// TestArchivingRetiresATemplateWithoutDestroyingIt is the whole feature in one arc.
//
// The templates page has never had a delete button and is never going to have one: a version is what a
// host's bootstrap record names, and docs/SECURITY.md §7 rests on that record resolving to the bytes
// that ran. Archiving is what an operator reaching for that button actually wants — the name stops
// being usable — and this walks the difference: gone from the listing, refused for every use, and still
// readable version by version.
func TestArchivingRetiresATemplateWithoutDestroyingIt(t *testing.T) {
	h := newHarness(t)
	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": templateBody})

	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/archive", nil)
	if status != http.StatusOK {
		t.Fatalf("archiving: %d %s", status, raw)
	}

	// Gone from the listing an operator reads.
	if names := h.templateNames(t, ""); len(names) != 0 {
		t.Fatalf("an archived template is still listed: %v", names)
	}
	// Listable on request, and marked — otherwise it could never be restored.
	status, raw = h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/templates?include=archived", nil)
	if status != http.StatusOK {
		t.Fatalf("listing with archived: %d %s", status, raw)
	}
	if !strings.Contains(string(raw), `"archived":true`) ||
		!strings.Contains(string(raw), `"archivedBy"`) {
		t.Fatalf("the archived template is not marked in the listing: %s", raw)
	}

	// Still readable, version by version, which is the half a delete could not offer.
	status, raw = h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/templates/standard-server", nil)
	if status != http.StatusOK {
		t.Fatalf("reading an archived template: %d %s", status, raw)
	}
	var version map[string]any
	if err := json.Unmarshal(raw, &version); err != nil {
		t.Fatalf("decoding the version: %v", err)
	}
	if version["body"].(string) != templateBody {
		t.Fatalf("the body did not survive archiving: %+v", version)
	}
	if version["archived"] != true {
		t.Fatalf("the version pane is not told the template is archived: %+v", version)
	}
	status, raw = h.adminJSON(t, h.adminToken, http.MethodGet,
		"/api/v1/templates/standard-server/versions", nil)
	if status != http.StatusOK || !strings.Contains(string(raw), `"version":1`) {
		t.Fatalf("the revision history did not survive archiving: %d %s", status, raw)
	}

	// And every use of the name is refused, with the same code each time.
	for _, refusal := range []struct {
		what   string
		method string
		path   string
		body   map[string]any
	}{
		{"a new version", http.MethodPost, "/api/v1/templates",
			map[string]any{"name": "standard-server", "body": "#cloud-config\n{}"}},
		{"a render", http.MethodPost, "/api/v1/templates/standard-server/render",
			map[string]any{}},
		{"a token naming it", http.MethodPost, "/api/v1/tokens",
			map[string]any{"label": "t", "bootstrap": "standard-server"}},
	} {
		t.Run(refusal.what, func(t *testing.T) {
			status, raw := h.adminJSON(t, h.adminToken, refusal.method, refusal.path, refusal.body)
			if status != http.StatusConflict || !strings.Contains(string(raw), "archived_template") {
				t.Fatalf("%s against an archived template: %d %s", refusal.what, status, raw)
			}
		})
	}

	// Restoring puts it back, and the name works again exactly as before.
	status, raw = h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/restore", nil)
	if status != http.StatusOK {
		t.Fatalf("restoring: %d %s", status, raw)
	}
	if names := h.templateNames(t, ""); len(names) != 1 || names[0] != "standard-server" {
		t.Fatalf("a restored template is not listed: %v", names)
	}
	saved := h.saveTemplate(t, h.adminToken, map[string]any{
		"name": "standard-server", "body": "#cloud-config\n{}",
	})
	if saved["version"].(float64) != 2 {
		t.Fatalf("the version after a restore: %+v", saved)
	}
}

// templateNames lists the fleet's templates through the API and returns their names.
func (h *harness) templateNames(t *testing.T, query string) []string {
	t.Helper()

	status, raw := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/templates"+query, nil)
	if status != http.StatusOK {
		t.Fatalf("listing templates: %d %s", status, raw)
	}
	var decoded struct {
		Templates []struct {
			Name string `json:"name"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decoding the listing: %v", err)
	}
	names := make([]string, 0, len(decoded.Templates))
	for _, tpl := range decoded.Templates {
		names = append(names, tpl.Name)
	}
	return names
}

// TestAnArchivedTemplateIsRefusedAtEnrolment is where archiving has to hold, because it is the one
// path on which a template reaches a machine.
//
// A token names a template and never a version, so the decision of what to hand over is taken at
// enrolment — which is also where a template retired during that token's lifetime would otherwise slip
// through. The refusal is loud for the same reason every other refusal on this path is: an agent that
// asked for a bootstrap and silently received none would carry on as though one had been applied.
func TestAnArchivedTemplateIsRefusedAtEnrolment(t *testing.T) {
	h := newHarness(t)
	signature := h.saveSignedTemplate(t, "standard-server", "#cloud-config\nhostname: bootstrapped\n")

	// The token is minted while the template is live, so this is the race the check exists for: the
	// mint-time check passed, and the template was retired afterwards.
	token := h.issueBootstrapToken(t, "standard-server")
	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/archive", nil)
	if status != http.StatusOK {
		t.Fatalf("archiving: %d %s", status, raw)
	}

	code, _, body := h.enrollDirect(t, protocol.EnrollRequest{
		Token: token, Hostname: "web-01", RequestedBootstrap: "standard-server",
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "archived_template") {
		t.Fatalf("an archived template was not refused at enrolment: %d %s", code, body)
	}
	if strings.Contains(string(body), signature) {
		t.Fatalf("the refusal handed over the signature: %s", body)
	}

	// The refusal consumed nothing: the same token still enrols the machine without a bootstrap, which
	// is the retry an operator actually makes.
	code, res, body := h.enrollDirect(t, protocol.EnrollRequest{Token: token, Hostname: "web-01"})
	if code != http.StatusOK || res.HostID == "" {
		t.Fatalf("the token did not survive the refusal: %d %s", code, body)
	}
	if res.Bootstrap != nil {
		t.Fatalf("an enrolment that asked for nothing was issued %+v", res.Bootstrap)
	}

	// And restoring makes it issuable again — on the conditions that already governed it, signature
	// included, which is why undoing an archival can never be what lets something reach a host.
	status, raw = h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/restore", nil)
	if status != http.StatusOK {
		t.Fatalf("restoring: %d %s", status, raw)
	}
	code, res, body = h.enrollDirect(t, protocol.EnrollRequest{
		Token: h.issueBootstrapToken(t, "standard-server"), Hostname: "web-02",
		RequestedBootstrap: "standard-server",
	})
	if code != http.StatusOK || res.Bootstrap == nil || res.Bootstrap.Signature != signature {
		t.Fatalf("a restored template was not issued unchanged: %d %s", code, body)
	}
}

// TestArchivingIsScopedToOneFleet proves a withdrawal is a statement about one fleet's provisioning.
//
// Two fleets naming a template "standard-server" is ordinary, and one retiring theirs must not stop the
// other's enrolments — an outage one customer could inflict on another, reached through an endpoint
// that looks like housekeeping.
func TestArchivingIsScopedToOneFleet(t *testing.T) {
	h := newHarness(t)
	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": templateBody})
	if _, err := h.store.In(h.otherTenant).CreateTemplateVersion(context.Background(),
		store.TemplateVersion{
			Name: "standard-server", BodySealed: sealForHarness(t, h, "#cloud-config\n{}"),
			CreatedAt: time.Now().UTC(), CreatedBy: "test:beta",
		}); err != nil {
		t.Fatalf("storing beta's template: %v", err)
	}

	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/archive", nil)
	if status != http.StatusOK {
		t.Fatalf("alpha archiving: %d %s", status, raw)
	}

	archival, err := h.store.In(h.otherTenant).GetTemplateArchival(context.Background(),
		"standard-server")
	if err != nil {
		t.Fatalf("reading beta's archival: %v", err)
	}
	if archival.Archived() {
		t.Fatalf("alpha's archival withdrew beta's template: %+v", archival)
	}
}

// TestArchiveAndRestoreRefuseTheStatesTheyAreAlreadyIn proves a stale client is told it is stale.
//
// Two operators looking at the same page is the ordinary case, and a second archive answered with a
// success would leave them disagreeing about who retired what — the record names one of them.
func TestArchiveAndRestoreRefuseTheStatesTheyAreAlreadyIn(t *testing.T) {
	h := newHarness(t)
	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": templateBody})

	for _, absent := range []string{"/archive", "/restore"} {
		status, raw := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/templates/absent"+absent, nil)
		if status != http.StatusNotFound {
			t.Fatalf("%s against a name nobody stored: %d %s", absent, status, raw)
		}
	}

	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/restore", nil)
	if status != http.StatusConflict || !strings.Contains(string(raw), "not_archived") {
		t.Fatalf("restoring a live template: %d %s", status, raw)
	}

	// The first archival succeeds; the second is a conflict rather than a second success, in that
	// order, because the order is the property.
	for _, want := range []int{http.StatusOK, http.StatusConflict} {
		status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
			"/api/v1/templates/standard-server/archive", nil)
		if status != want {
			t.Fatalf("archiving answered %d, want %d: %s", status, want, raw)
		}
		if want == http.StatusConflict && !strings.Contains(string(raw), "archived_template") {
			t.Fatalf("the second archival did not say why: %s", raw)
		}
	}
}

// archiveOnRedemption is a store that withdraws one template the instant an enrolment token is spent.
//
// It stands in for the operator who presses Archive while a machine is enrolling. That interleaving
// has no other seam: the enrolment resolves the template, issues a certificate and redeems the token as
// three separate transactions, so the write that matters has to land from inside the request rather
// than before or after it.
type archiveOnRedemption struct {
	// Store is the real store; only the redemption is decorated.
	store.Store

	// name is the template withdrawn as the token is spent.
	name string
}

// In returns a scoped handle that archives the template as it consumes a token.
func (s archiveOnRedemption) In(tenant store.TenantID) store.Scoped {
	return archiveOnRedemptionScoped{Scoped: s.Store.In(tenant), name: s.name}
}

// archiveOnRedemptionScoped is one tenant's handle on archiveOnRedemption.
type archiveOnRedemptionScoped struct {
	// Scoped is the real handle; every method but the redemption is its own.
	store.Scoped

	// name is the template withdrawn as the token is spent.
	name string
}

// ConsumeEnrollmentToken redeems the token and then archives the template, in that order.
//
// The order is the whole point: the archival commits after the redemption that proved this enrolment
// is the one taking place, which is exactly the interleaving the re-check in the handler exists for.
func (s archiveOnRedemptionScoped) ConsumeEnrollmentToken(ctx context.Context, hash, hostID string,
	now time.Time) (store.EnrollmentToken, error) {

	token, err := s.Scoped.ConsumeEnrollmentToken(ctx, hash, hostID, now)
	if err != nil {
		return token, err
	}
	if archiveErr := s.Scoped.ArchiveTemplate(ctx, store.TemplateArchival{
		Name: s.name, ArchivedAt: now, ArchivedBy: "test:racer",
	}); archiveErr != nil {
		return token, archiveErr
	}
	return token, nil
}

// TestATemplateArchivedMidEnrolmentIsNotIssued closes the gap between the two checks.
//
// The early check runs before the certificate is issued, so that a refusal leaves the token usable;
// that is the right place for it and it cannot also be the last word, because redemption — the moment
// this enrolment becomes the one that happened — comes afterwards. An archival landing in between would
// otherwise hand a machine the template the fleet had just retired, while the operator who pressed
// Archive was told it had worked.
//
// What the refusal must leave behind is nothing: no host, no recorded certificate, and a message saying
// the token is spent rather than one the operator has to decode on a retry.
func TestATemplateArchivedMidEnrolmentIsNotIssued(t *testing.T) {
	h := newHarness(t, func(real store.Store) store.Store {
		return archiveOnRedemption{Store: real, name: "standard-server"}
	})
	signature := h.saveSignedTemplate(t, "standard-server", "#cloud-config\nhostname: bootstrapped\n")

	status, _, raw := h.enrollDirect(t, protocol.EnrollRequest{
		Token: h.issueBootstrapToken(t, "standard-server"), Hostname: "web-01",
		RequestedBootstrap: "standard-server",
	})
	if status != http.StatusConflict || !strings.Contains(string(raw), "archived_template") {
		t.Fatalf("a template archived mid-enrolment was not refused: %d %s", status, raw)
	}
	if strings.Contains(string(raw), signature) {
		t.Fatalf("the refusal handed over the signature: %s", raw)
	}
	if !strings.Contains(string(raw), "has been spent") {
		t.Fatalf("the refusal does not say the token is spent: %s", raw)
	}

	hosts, err := h.scoped().ListHosts(context.Background())
	if err != nil {
		t.Fatalf("listing hosts: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("the refused enrolment left a host behind: %+v", hosts)
	}
}
