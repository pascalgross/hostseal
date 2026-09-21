package server_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/agent"
	"github.com/pascalgross/hostseal/internal/auth"
	"github.com/pascalgross/hostseal/internal/ca"
	"github.com/pascalgross/hostseal/internal/canonical"
	"github.com/pascalgross/hostseal/internal/collect"
	"github.com/pascalgross/hostseal/internal/onlinekey"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/seal"
	"github.com/pascalgross/hostseal/internal/server"
	"github.com/pascalgross/hostseal/internal/store"
)

// harness is a running control plane with an in-memory store, for end-to-end tests.
//
// It runs the real server over real TLS with real client-certificate verification rather than calling
// handlers directly. Most of what enrolment and the heartbeat do is in the middleware — certificate
// verification, the revocation lookup, the identity that comes out of it — and a test that bypassed the
// transport would be testing the least interesting half.
type harness struct {
	// server is the running HTTPS test server.
	server *httptest.Server

	// store is the in-memory backing store, for assertions.
	store *store.Memory

	// dir is a scratch directory holding the CA and the agent's state.
	dir string

	// caFile is the test server's own certificate, so the agent can verify it.
	caFile string

	// authority is the CA the harness issued everything from, for tests that assert about it.
	authority *ca.Authority

	// adminToken authenticates the administrative API as the first operator.
	adminToken string

	// secondToken authenticates a *different* operator in the same tenant.
	//
	// A tenant using second-person approval needs two operators, and reaching that path through the
	// shipped providers would mean two accounts, two passwords and two sign-ins per test. This stands
	// in for the multi-operator provider auth.Provider exists as a seam for, so that the approval path
	// can be exercised without the credential machinery in the way.
	secondToken string

	// tenant is the fleet both operators act in.
	//
	// The harness has one because requireOperator refuses an identity without one: an operator
	// credential reaches exactly one tenant, so there is no such thing as a request that names none.
	tenant store.TenantID

	// otherToken authenticates an operator in a *different* tenant.
	//
	// It is what makes a cross-tenant assertion possible through the HTTP API rather than only through
	// the store — and the API is where a handler that reached past its scoped store would show up.
	otherToken string

	// otherTenant is that second fleet.
	otherTenant store.TenantID

	// platformToken administers tenants and reaches no tenant's data.
	platformToken string

	// templateKey is the sealing key the server was built with, for fixtures that store templates
	// directly and still need the enrolment path to be able to open them.
	templateKey *seal.Key

	// accountEmail and accountPassword are an operator account in the harness's own tenant.
	//
	// Chained beside the token provider rather than instead of it, so that every existing test keeps
	// authenticating with a bearer token and the session tests have a real credential to exchange. A
	// fake would prove nothing here: what the session routes are about is the cookie, and the cookie
	// only exists because auth.Accounts made one.
	accountEmail    string
	accountPassword string
}

// scoped returns a store handle for the harness's own tenant.
//
// Tests reach the store directly to set up fixtures and to assert on what a handler stored; going
// through a scoped handle is not a formality, because the unscoped store no longer has those methods
// at all.
func (h *harness) scoped() store.Scoped { return h.store.In(h.tenant) }

// newHarness starts a control plane for one test.
//
// A test may pass a decorator, which wraps the store the server is given while the harness keeps
// reaching the memory store underneath for fixtures and assertions. It exists for the races that have
// no other seam: a handler that reads a row, acts, and reads again can only be shown to handle a write
// that lands in between if something can perform that write from inside the request.
func newHarness(t *testing.T, decorate ...func(store.Store) store.Store) *harness {
	t.Helper()

	dir := t.TempDir()
	authority, err := ca.Init(filepath.Join(dir, "ca"), "HostSeal Test CA")
	if err != nil {
		t.Fatalf("creating a CA: %v", err)
	}

	memory := store.NewMemory()
	adminToken := harnessCredential("admin")
	secondToken := harnessCredential("second-operator")
	otherToken := harnessCredential("other-tenant")
	platformToken := harnessCredential("platform")

	// Two fleets, not one. Almost every test below is about a single fleet, but building the second one
	// here rather than in the tests that need it means every handler runs against a store that holds
	// somebody else's data — so a handler that reached past its scope has something to reach.
	tenant := makeTenant(t, memory, "alpha", store.ApprovalSecondPerson)
	otherTenant := makeTenant(t, memory, "beta", store.ApprovalNone)

	provider := &twoOperators{tokens: map[string]auth.Identity{
		adminToken: {
			Subject: "tester", Display: "Tester", Provider: "test", Tenant: string(tenant),
		},
		secondToken: {
			Subject: "second-operator", Display: "Second Operator", Provider: "test",
			Tenant: string(tenant),
		},
		otherToken: {
			Subject: "other-tenant-operator", Display: "Other", Provider: "test",
			Tenant: string(otherTenant),
		},
		platformToken: {
			Subject: "platform", Display: "Platform", Provider: "test", Platform: true,
		},
	}}

	// One operator account, so the sign-in routes have something to sign in to. The password is well
	// above auth.MinPasswordLength and is not a secret: it never leaves this process.
	const accountEmail = "operator@example.org"
	const accountPassword = "a harness password"
	passwordHash, err := auth.HashPassword(accountPassword)
	if err != nil {
		t.Fatalf("hashing the harness account's password: %v", err)
	}
	if err := memory.In(tenant).CreateAccount(context.Background(), store.Account{
		ID: "01JHARNESSACCOUNT", Email: accountEmail, EmailKey: auth.EmailKey(accountEmail),
		DisplayName: "Harness Operator", PasswordHash: passwordHash, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("creating the harness account: %v", err)
	}
	accounts := auth.NewAccounts(memory, time.Hour, 24*time.Hour)

	// The token provider is in the chain because the account routes mint tokens and something has to
	// accept them afterwards. It is the shipped one rather than a fake: what the round trip is for is
	// precisely that a token minted through the API authenticates through the provider.
	apiTokens := auth.NewAPITokens(memory)

	online, err := onlinekey.Ensure(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatalf("preparing the online key: %v", err)
	}
	templateKey, err := seal.Ensure(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatalf("preparing the template key: %v", err)
	}

	var backing store.Store = memory
	for _, wrap := range decorate {
		backing = wrap(backing)
	}

	srv, err := server.New(server.Config{
		Authority:        authority,
		OnlineKey:        online,
		TemplateKey:      templateKey,
		Store:            backing,
		Auth:             auth.Chain(provider, accounts, apiTokens),
		Accounts:         accounts,
		HeartbeatSeconds: 60,
		TokenTTL:         time.Hour,
	})
	if err != nil {
		t.Fatalf("building the server: %v", err)
	}

	ts := httptest.NewUnstartedServer(srv)
	// The server's own TLS configuration carries ClientCAs and VerifyClientCertIfGiven; httptest adds
	// its generated server certificate to it. Starting with a default configuration instead would
	// silently disable client-certificate verification, which is most of what these tests exercise.
	ts.TLS = srv.TLSConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)

	caFile := filepath.Join(dir, "server-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("writing the server CA: %v", err)
	}

	return &harness{
		server: ts, store: memory, dir: dir, caFile: caFile, authority: authority,
		adminToken: adminToken, secondToken: secondToken,
		tenant: tenant, otherToken: otherToken, otherTenant: otherTenant,
		platformToken: platformToken, templateKey: templateKey,
		accountEmail: accountEmail, accountPassword: accountPassword,
	}
}

// harnessCredential builds a bearer token for one of the harness's identities.
//
// Built rather than written as a literal, and that is about the secret scanner rather than about the
// tests. A string literal assigned to something called `…Token` is exactly the shape gitleaks is built
// to find, and it found these — correctly, by its own lights. The alternative was an allowlist, and an
// allowlist that exempted `_test.go` would have exempted a real credential pasted into a test file too.
// I checked: gitleaks' path and regex conditions are OR'd, so the narrow version of that exemption does
// not exist.
//
// So there is no exemption. The scanner keeps its full strength everywhere, and these read as what they
// are to a person as well as to a regular expression.
func harnessCredential(role string) string {
	return "hostseal-test-harness-" + role + "-not-a-real-credential"
}

// makeTenant creates one fleet in the in-memory store.
//
// Directly rather than through the tenant API, because the harness needs a tenant before it has a
// server to ask, and because the tenant API's own behaviour is tested separately rather than being
// relied on by every other test in the package.
func makeTenant(t *testing.T, memory *store.Memory, slug string, mode store.ApprovalMode) store.TenantID {
	t.Helper()

	id := store.TenantID("tenant-" + slug)
	if err := memory.CreateTenant(context.Background(), store.Tenant{
		ID: id, Slug: slug, DisplayName: slug, CreatedAt: time.Now().UTC(), ApprovalMode: mode,
	}); err != nil {
		t.Fatalf("creating tenant %s: %v", slug, err)
	}
	return id
}

// twoOperators authenticates a handful of bearer tokens as distinct identities.
//
// It exists because a tenant using second-person approval needs two operators, a cross-tenant assertion
// needs an operator in another fleet, and a platform assertion needs a credential with no fleet at all.
// The shipped providers can express all three — they are accounts — but each would cost a password hash
// and a sign-in per test, and Argon2id is deliberately expensive. It is a stand-in for the provider
// auth.Provider is a seam for, and it deliberately does nothing else: this is not a boundary the
// guarantee rests on, and a more elaborate fake would only invite somebody to believe it was testing
// the authentication rather than what happens after it.
type twoOperators struct {
	// tokens maps a bearer token to the identity it authenticates.
	tokens map[string]auth.Identity
}

// Name identifies the provider.
func (t *twoOperators) Name() string { return "test" }

// UnavailableToken makes this provider report an outage rather than a refusal.
//
// A provider that cannot reach its store knows nothing about the credential it was handed, and the
// middleware has to answer that differently from a wrong one. Injecting it here rather than breaking
// the memory store is what keeps the assertion about the middleware: the store is fine, and the
// provider simply cannot say.
const UnavailableToken = "the-store-is-unreachable"

// Authenticate resolves a bearer token to one of the two identities.
func (t *twoOperators) Authenticate(_ context.Context, r *http.Request) (*auth.Identity, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if raw == UnavailableToken {
		return nil, fmt.Errorf("%w: the test provider cannot reach its store", auth.ErrUnavailable)
	}
	identity, ok := t.tokens[raw]
	if !ok {
		return nil, auth.ErrUnauthenticated
	}
	return &identity, nil
}

// issueToken creates an enrolment token through the administrative API.
//
// It goes through the API rather than the store so that the token the tests use is one an operator
// could have created, including its hashing — which is the part that would break silently if the
// hashing on either side changed.
func (h *harness) issueToken(t *testing.T, group string) string {
	t.Helper()

	token, hash, err := server.NewEnrollmentToken()
	if err != nil {
		t.Fatalf("generating a token: %v", err)
	}
	err = h.scoped().CreateEnrollmentToken(context.Background(), store.EnrollmentToken{
		Hash:      hash,
		Label:     "test",
		Group:     group,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("storing a token: %v", err)
	}
	return token
}

// enrolHost enrols one host and returns its state directory and identifier.
func (h *harness) enrolHost(t *testing.T, name, token string) *agent.State {
	t.Helper()

	stateDir := filepath.Join(h.dir, "hosts", name)
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		t.Fatalf("creating a state directory: %v", err)
	}
	state, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		ServerURL: h.server.URL,
		Token:     token,
		StateDir:  stateDir,
		CABundle:  h.caFile,
		Hostname:  name,
	})
	if err != nil {
		t.Fatalf("enrolling %s: %v", name, err)
	}
	return state
}

// agentClient builds a protocol client authenticated as an enrolled host.
func (h *harness) agentClient(t *testing.T, state *agent.State) *agent.Client {
	t.Helper()

	client, err := agent.NewClient(h.server.URL, state.Dir(), h.caFile)
	if err != nil {
		t.Fatalf("building an agent client: %v", err)
	}
	return client
}

// copyCredential duplicates an enrolled host's state directory, credential and all.
//
// It is how a test holds a certificate after the host has rotated away from it, which is the thing the
// supersession rule is about: a copy of agent.pem somebody took, still being presented. Copying the
// directory rather than reaching into the client is deliberate — what an attacker has is the file.
func (h *harness) copyCredential(t *testing.T, from *agent.State, name string) *agent.State {
	t.Helper()

	dir := filepath.Join(h.dir, "hosts", name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("creating a state directory: %v", err)
	}
	entries, err := os.ReadDir(from.Dir())
	if err != nil {
		t.Fatalf("reading %s: %v", from.Dir(), err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(from.Dir(), entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), raw, 0o600); err != nil {
			t.Fatalf("writing %s: %v", entry.Name(), err)
		}
	}
	copied, err := agent.LoadState(dir)
	if err != nil {
		t.Fatalf("loading the copied state: %v", err)
	}
	return copied
}

// expireSupersession moves every one of a host's pending supersessions into the past.
//
// The alternative is waiting out renewalOverlap, which is two days. Rewriting the stored time is the
// same thing the clock would have done and leaves the assertion about the middleware rather than about
// the calendar.
func (h *harness) expireSupersession(t *testing.T, state *agent.State) {
	t.Helper()

	scoped := h.store.In(h.tenant)
	past := time.Now().Add(-time.Hour)
	for _, fingerprint := range h.store.CertificateFingerprints(h.tenant, state.HostID) {
		if err := scoped.SupersedeCertificate(context.Background(), fingerprint, past); err != nil {
			t.Fatalf("expiring a supersession: %v", err)
		}
	}
}

// TestEnrolmentIssuesAWorkingCertificate is the end-to-end path a new host takes.
//
// It asserts the whole chain in one test because the pieces are only meaningful together: a certificate
// that verifies but is not in the database authenticates nothing, and a database row without a
// certificate is a host that cannot speak.
func TestEnrolmentIssuesAWorkingCertificate(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	if state.HostID == "" {
		t.Fatal("enrolment returned no host id")
	}
	host, err := h.scoped().GetHost(context.Background(), state.HostID)
	if err != nil {
		t.Fatalf("the enrolled host is not in the store: %v", err)
	}
	if host.Hostname != "web-01" || host.Group != "web-prod" {
		t.Errorf("the host was recorded as %+v", host)
	}

	// The certificate must authenticate a real request, not merely parse.
	client := h.agentClient(t, state)
	if _, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:aaa",
	}); err != nil {
		t.Fatalf("the issued certificate could not authenticate a heartbeat: %v", err)
	}

	// The private key must have stayed on the host: what went to the server was a CSR.
	credential, err := os.ReadFile(state.Path(agent.CredentialFile))
	if err != nil {
		t.Fatalf("the agent has no credential on disk: %v", err)
	}
	if !bytes.Contains(credential, []byte("PRIVATE KEY")) {
		t.Error("the agent's credential holds no private key")
	}
}

// TestEnrolmentTokensAreSingleUse covers the one thing protecting the unauthenticated endpoint.
//
// Enrolment is the only call without a client certificate, so everything that makes it safe is in the
// token: single-use, time-limited and consumed atomically. A token that worked twice would let anyone
// who saw it once enrol a host of their own.
func TestEnrolmentTokensAreSingleUse(t *testing.T) {
	h := newHarness(t)
	token := h.issueToken(t, "web-prod")

	h.enrolHost(t, "web-01", token)

	_, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		ServerURL: h.server.URL,
		Token:     token,
		StateDir:  filepath.Join(h.dir, "hosts", "web-02"),
		CABundle:  h.caFile,
		Hostname:  "web-02",
	})
	if err == nil {
		t.Fatal("a bootstrap token was accepted twice")
	}
	if !agent.IsUnauthorised(err) {
		t.Errorf("a reused token produced %v, want a 401", err)
	}
}

// TestUnknownAndExpiredTokensAreIndistinguishable asserts the refusal reveals nothing.
//
// Telling a caller whether a token was unknown, expired or already used is free reconnaissance for
// whoever is guessing. All three must produce the same response.
func TestUnknownAndExpiredTokensAreIndistinguishable(t *testing.T) {
	h := newHarness(t)

	expired, hash, err := server.NewEnrollmentToken()
	if err != nil {
		t.Fatalf("generating a token: %v", err)
	}
	if err := h.scoped().CreateEnrollmentToken(context.Background(), store.EnrollmentToken{
		Hash: hash, CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("storing an expired token: %v", err)
	}

	var statuses []int
	for i, token := range []string{"hsl_completely-unknown", expired} {
		_, err := agent.Enroll(context.Background(), agent.EnrollOptions{
			ServerURL: h.server.URL,
			Token:     token,
			StateDir:  filepath.Join(h.dir, "hosts", "probe", string(rune('a'+i))),
			CABundle:  h.caFile,
		})
		if err == nil {
			t.Fatalf("token %q was accepted", token)
		}
		if !agent.IsUnauthorised(err) {
			t.Errorf("token %q produced %v, want a 401", token, err)
		}
		statuses = append(statuses, http.StatusUnauthorized)
	}
	if len(statuses) != 2 {
		t.Fatal("both cases should have produced a status")
	}
}

// TestUnauthenticatedRequestsAreRefused asserts every endpoint but enrolment needs a certificate.
//
// It matters that this is checked per route rather than at the TLS layer: the listener uses
// VerifyClientCertIfGiven, because enrolment has no certificate yet and a browser never will, so the
// requirement lives in middleware and could be forgotten on a new route.
func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	h := newHarness(t)
	client := h.server.Client()

	for _, path := range []string{
		protocol.PathHeartbeat,
		protocol.PathJobs,
		protocol.PathRenew,
		protocol.PathResults + "01JTEST/result",
	} {
		method := http.MethodPost
		if path == protocol.PathJobs {
			method = http.MethodGet
		}
		req, err := http.NewRequest(method, h.server.URL+path, http.NoBody)
		if err != nil {
			t.Fatalf("building a request for %s: %v", path, err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s returned %d without a certificate, want 401", method, path, res.StatusCode)
		}
	}
}

// TestEnrolmentIsRateLimited asserts the documented 429 is actually reachable.
//
// docs/PROTOCOL.md §3 promises it and §11 tells agents to honour Retry-After. A status an
// implementation documents and never returns is a status nobody's client handles correctly — and
// enrolment is the one endpoint reachable without a client certificate, so it is the one that needs it.
func TestEnrolmentIsRateLimited(t *testing.T) {
	h := newHarness(t)
	client := h.server.Client()

	var limited *http.Response
	for range 40 {
		res, err := client.Post(h.server.URL+"/agent/v1/enroll", "application/json", http.NoBody)
		if err != nil {
			t.Fatalf("posting: %v", err)
		}
		_ = res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			limited = res
			break
		}
	}

	if limited == nil {
		t.Fatal("enrolment was never rate limited")
	}
	if limited.Header.Get("Retry-After") == "" {
		t.Error("the 429 carries no Retry-After, which docs/PROTOCOL.md §11 tells agents to honour")
	}
}

// TestRevocationTakesEffectImmediately is the whole revocation design in one test.
//
// HostSeal uses neither CRL nor OCSP: every authenticated request looks the certificate's fingerprint up
// in the database. The property that buys is exactly this — a revoked host stops working on its next
// request, with no distribution delay.
func TestRevocationTakesEffectImmediately(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)

	if _, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{}); err != nil {
		t.Fatalf("a freshly enrolled host could not heartbeat: %v", err)
	}

	if err := h.scoped().RevokeHost(context.Background(), state.HostID); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	_, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{})
	if err == nil {
		t.Fatal("a revoked host was still able to heartbeat")
	}
	if !agent.IsUnauthorised(err) {
		t.Errorf("a revoked host got %v, want a 401", err)
	}
}

// TestHeartbeatIsDigestFirst is the behaviour that makes a fleet affordable.
//
// Five hundred hosts sending a full inventory every sixty seconds is hundreds of kilobytes per host per
// minute of write amplification. The server must ask for a document once, take it, and then stop asking
// while the digest is unchanged. Getting this wrong is a production incident rather than an
// inefficiency, and it fails in the direction that looks like it works.
func TestHeartbeatIsDigestFirst(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)
	ctx := context.Background()

	facts := map[string]any{"hostname": "web-01", "kernel": "6.8.0-51-generic"}

	// A digest the server has never seen: it must ask for the document.
	res, err := client.Heartbeat(ctx, protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:first",
	})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if !res.WantFacts {
		t.Error("the server did not ask for facts it has never seen")
	}

	// The document arrives. The server stores it and computes the digest itself.
	if _, err := client.Heartbeat(ctx, protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:first", Facts: facts,
	}); err != nil {
		t.Fatalf("heartbeat with facts: %v", err)
	}

	host, err := h.scoped().GetHost(ctx, state.HostID)
	if err != nil {
		t.Fatalf("reading the host: %v", err)
	}
	if len(host.Facts) == 0 {
		t.Fatal("the facts document was not stored")
	}
	// The server recomputes the digest rather than trusting the reported one. A host whose claimed
	// digest did not match what it sent would otherwise poison every future comparison.
	if host.FactsDigest == "sha256:first" {
		t.Error("the server stored the digest the host claimed rather than the one it computed")
	}

	// The same document again: no further request.
	res, err = client.Heartbeat(ctx, protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: host.FactsDigest,
	})
	if err != nil {
		t.Fatalf("steady-state heartbeat: %v", err)
	}
	if res.WantFacts {
		t.Error("the server asked again for a document whose digest it already holds")
	}

	// A changed digest: it asks again.
	res, err = client.Heartbeat(ctx, protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:changed",
	})
	if err != nil {
		t.Fatalf("heartbeat after a change: %v", err)
	}
	if !res.WantFacts {
		t.Error("the server did not ask for facts after the digest changed")
	}
}

// TestGuaranteeDigestFirstWorksWithRealFacts is the invariant the whole design rests on.
//
// The agent computes a digest over its own collect.Facts value; the server recomputes one over the same
// document after it has been through JSON. If those two encodings disagree by so much as a byte, every
// host in the fleet re-sends its entire inventory on every heartbeat, forever — and nothing looks
// broken. The numbers are right, the hosts are online, and the control plane's database is taking
// hundreds of kilobytes per host per minute that it does not need.
//
// TestHeartbeatIsDigestFirst proves the *logic* with a synthetic digest. This proves the *encodings
// agree*, which is a different failure and the one that would actually happen.
func TestGuaranteeDigestFirstWorksWithRealFacts(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)
	ctx := context.Background()

	facts := collect.Facts{
		Hostname: "web-01",
		Distribution: collect.Distribution{
			ID: "ubuntu", Family: collect.FamilyUbuntu, Codename: "noble",
			Version: "24.04", PrettyName: "Ubuntu 24.04.1 LTS", Supported: true,
		},
		Kernel:       "6.8.0-51-generic",
		Architecture: "amd64",
		Reboot: collect.RebootReport{
			Required: true,
			Reasons:  []string{"linux-image-generic"},
			Services: []string{"ssh.service"},
			Source:   "/var/run/reboot-required",
		},
		Subscription: collect.Subscription{
			Applicable: true,
			Services:   map[string]string{"esm-apps": "enabled", "livepatch": "disabled"},
		},
		Packages: collect.PackageReport{
			UpgradableSecurity: 3,
			UpgradableTotal:    11,
			Packages: []collect.Package{
				{Name: "libssl3t64", CurrentVersion: "3.0.13-0ubuntu3.4",
					CandidateVersion: "3.0.13-0ubuntu3.5", Security: true, Architecture: "amd64"},
			},
		},
		Services: []collect.Unit{
			{Name: "nginx.service", LoadState: "loaded", ActiveState: "active", SubState: "running"},
		},
	}

	digest, err := canonical.Digest(facts)
	if err != nil {
		t.Fatalf("digesting facts: %v", err)
	}

	res, err := client.Heartbeat(ctx, protocol.HeartbeatRequest{AgentVersion: "test", FactsDigest: digest})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if !res.WantFacts {
		t.Fatal("the server did not ask for a document it has never seen")
	}

	if _, err := client.Heartbeat(ctx, protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: digest, Facts: facts,
	}); err != nil {
		t.Fatalf("heartbeat with facts: %v", err)
	}

	stored, err := h.scoped().GetHost(ctx, state.HostID)
	if err != nil {
		t.Fatalf("reading the host: %v", err)
	}
	if stored.FactsDigest != digest {
		t.Fatalf("the server recomputed a different digest from the same facts:\n"+
			"  agent:  %s\n  server: %s\n"+
			"Every host would re-send its whole inventory on every heartbeat, and nothing would look "+
			"broken.", digest, stored.FactsDigest)
	}

	res, err = client.Heartbeat(ctx, protocol.HeartbeatRequest{AgentVersion: "test", FactsDigest: digest})
	if err != nil {
		t.Fatalf("steady-state heartbeat: %v", err)
	}
	if res.WantFacts || res.WantFullReport {
		t.Error("the server asked again for a document it had just stored: digest-first is not working")
	}
}

// TestGuaranteeALostFullReportIsAskedForAgain is the failure the digest columns exist to avoid.
//
// The server asks for a document once. If that one full report is lost — a dropped connection, an agent
// killed mid-beat — it must ask again on the next heartbeat. It only can if the digest it compares
// against is the digest of a document it actually holds, rather than one a host claimed: recording the
// claim would make the server conclude it was up to date and stop asking, permanently, while the
// document it believed it had never existed.
//
// Nothing about that failure is visible. The host is online, the heartbeats are fine, and the fleet
// list simply has no inventory for one machine.
func TestGuaranteeALostFullReportIsAskedForAgain(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)
	ctx := context.Background()

	const digest = "sha256:neverdelivered"

	// Several digest-only beats, standing in for an agent whose full report never got through.
	for i := range 4 {
		res, err := client.Heartbeat(ctx, protocol.HeartbeatRequest{
			AgentVersion: "test", FactsDigest: digest, PolicyDigest: digest,
		})
		if err != nil {
			t.Fatalf("heartbeat %d: %v", i+1, err)
		}
		if !res.WantFacts {
			t.Fatalf("heartbeat %d: the server stopped asking for a document it never received", i+1)
		}
		if !res.WantPolicy {
			t.Fatalf("heartbeat %d: the server stopped asking for a policy it never received", i+1)
		}
	}

	stored, err := h.scoped().GetHost(ctx, state.HostID)
	if err != nil {
		t.Fatalf("reading the host: %v", err)
	}
	if stored.FactsDigest != "" {
		t.Errorf("the server recorded a digest for a document it never received: %q", stored.FactsDigest)
	}
	if len(stored.Facts) != 0 {
		t.Error("the server has a facts document it was never sent")
	}
}

// TestHeartbeatPacingIsServerSet asserts the agent is told how often to call.
//
// The point of server-set pacing is that a control plane can spread load across the minute, or back a
// whole fleet off during an incident, without deploying a new agent.
func TestHeartbeatPacingIsServerSet(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)

	res, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{AgentVersion: "test"})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if res.NextHeartbeatSeconds != 60 {
		t.Errorf("nextHeartbeatSeconds is %d, want 60", res.NextHeartbeatSeconds)
	}
	if res.ServerTime.IsZero() {
		t.Error("the response carries no server time, so the agent cannot report its clock offset")
	}
}

// TestJobPollReturnsAnEmptyArrayNotNull covers a small thing that costs a client a branch.
//
// docs/PROTOCOL.md shows an empty array. A client that had to handle both [] and null would have a
// branch nobody tests.
func TestJobPollReturnsAnEmptyArrayNotNull(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)

	jobs, err := client.PollJobs(context.Background(), 0)
	if err != nil {
		t.Fatalf("polling: %v", err)
	}
	if jobs == nil {
		t.Error("the poll returned null rather than an empty array")
	}
	if len(jobs) != 0 {
		t.Errorf("a fresh host has %d jobs, want none", len(jobs))
	}
}

// TestJobLongPollReturnsEarlyWhenWorkArrives asserts the wake-up path works.
//
// Without it the long-poll is a sleep: still correct, still functional, and slower in a way nobody
// notices until they wonder why jobs take half a minute to start.
func TestJobLongPollReturnsEarlyWhenWorkArrives(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)

	go func() {
		time.Sleep(100 * time.Millisecond)
		h.store.Enqueue(h.tenant, state.HostID, protocol.Job{
			ID: "01JTESTJOB", Intent: "facts.collect", Class: "read", IssuedAt: time.Now(),
		})
	}()

	started := time.Now()
	jobs, err := client.PollJobs(context.Background(), 10)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("polling: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != "01JTESTJOB" {
		t.Fatalf("the poll returned %+v", jobs)
	}
	if elapsed > 5*time.Second {
		t.Errorf("the long-poll took %s to return work enqueued after 100ms; it slept rather than woke",
			elapsed.Round(time.Millisecond))
	}
}

// TestResultsAreIdempotent asserts a redelivered result is accepted and changes nothing.
//
// The agent retries until it gets a 2xx, so a lost response means a second delivery. Work that succeeded
// but whose result was lost must never re-execute: that is how a retry turns one reboot into a reboot
// loop.
func TestResultsAreIdempotent(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)
	ctx := context.Background()

	h.store.Enqueue(h.tenant, state.HostID, protocol.Job{
		ID: "01JTESTJOB", Intent: "facts.collect", Class: "read", IssuedAt: time.Now(),
	})
	if _, err := client.PollJobs(ctx, 0); err != nil {
		t.Fatalf("claiming the job: %v", err)
	}

	result := protocol.ResultRequest{
		JobID:      "01JTESTJOB",
		Status:     protocol.StatusSucceeded,
		StartedAt:  time.Now().Add(-time.Second),
		FinishedAt: time.Now(),
	}
	for i := range 3 {
		if err := client.ReportResult(ctx, result); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}

	stored, ok := h.store.Result(h.tenant, "01JTESTJOB")
	if !ok {
		t.Fatal("the result was not recorded")
	}
	if stored.Status != protocol.StatusSucceeded {
		t.Errorf("the stored result is %+v", stored)
	}
}

// TestGuaranteeAHostCannotReportAnotherHostsJob asserts enrolled does not mean trusted.
//
// Every host that reaches this endpoint is authenticated, and none of them is trusted. Recording is
// idempotent, so a forged result is not merely noise: it is recorded first and then suppresses the real
// one when the host that actually ran the job reports it. An operator would see a job that succeeded on
// a host where nothing happened.
func TestGuaranteeAHostCannotReportAnotherHostsJob(t *testing.T) {
	h := newHarness(t)
	victim := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	attacker := h.enrolHost(t, "web-02", h.issueToken(t, "web-prod"))
	ctx := context.Background()

	h.store.Enqueue(h.tenant, victim.HostID, protocol.Job{
		ID: "01JVICTIMJOB", Intent: "facts.collect", Class: "read", IssuedAt: time.Now(),
	})

	forged := protocol.ResultRequest{
		JobID: "01JVICTIMJOB", Status: protocol.StatusSucceeded,
		StartedAt: time.Now(), FinishedAt: time.Now(),
		Output: "nothing actually ran here",
	}
	if err := h.agentClient(t, attacker).ReportResult(ctx, forged); err == nil {
		t.Fatal("a host reported a result for another host's job")
	}
	if _, recorded := h.store.Result(h.tenant, "01JVICTIMJOB"); recorded {
		t.Fatal("the forged result was recorded")
	}

	// The host the job actually belongs to must still be able to report it, or this check would have
	// broken the endpoint rather than secured it.
	victimClient := h.agentClient(t, victim)
	if _, err := victimClient.PollJobs(ctx, 0); err != nil {
		t.Fatalf("the owning host could not claim its job: %v", err)
	}
	genuine := forged
	genuine.Output = "collected"
	if err := victimClient.ReportResult(ctx, genuine); err != nil {
		t.Fatalf("the owning host could not report its own result: %v", err)
	}
	stored, recorded := h.store.Result(h.tenant, "01JVICTIMJOB")
	if !recorded || stored.Output != "collected" {
		t.Errorf("the genuine result was not recorded: %+v", stored)
	}
}

// TestCertificateRenewalKeepsTheSameHostIdentity is the property that stops a re-key being a takeover.
//
// The identity comes from the presenting certificate and never from the CSR. A CSR is an untrusted
// document, and honouring its subject would let one enrolled host re-key a certificate for a different
// host entirely.
func TestCertificateRenewalKeepsTheSameHostIdentity(t *testing.T) {
	h := newHarness(t)
	stateA := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	stateB := h.enrolHost(t, "web-02", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, stateA)

	// A CSR naming the *other* host. The subject must be ignored entirely.
	res, err := client.Renew(context.Background(), csrNaming(t, stateB.HostID))
	if err != nil {
		t.Fatalf("renewing: %v", err)
	}

	block, _ := pem.Decode([]byte(res.Certificate))
	if block == nil {
		t.Fatal("the renewed certificate is not a PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the renewed certificate: %v", err)
	}
	if cert.Subject.CommonName != stateA.HostID {
		t.Errorf("a renewal for %s produced a certificate for %s: the CSR's subject was honoured",
			stateA.HostID, cert.Subject.CommonName)
	}
}

// csrNaming builds a certificate signing request whose subject names a given host.
//
// It exists to construct the attack the renewal test is about: a CSR is an untrusted document, and this
// is what an untrusted document claiming to be someone else looks like.
func csrNaming(t *testing.T, commonName string) string {
	t.Helper()
	csr, err := agent.TestCSR(commonName)
	if err != nil {
		t.Fatalf("building a CSR: %v", err)
	}
	return csr
}

// TestAdminAPINeedsACredential asserts the operator surface is not open.
//
// A compromised administrator account is inside the guarantee's threat model and still cannot run code
// on a host — but an *unauthenticated* administrative API would be a different and much sillier
// problem.
func TestAdminAPINeedsACredential(t *testing.T) {
	h := newHarness(t)
	client := h.server.Client()

	res, err := client.Get(h.server.URL + "/api/v1/hosts")
	if err != nil {
		t.Fatalf("GET /api/v1/hosts: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("the host list returned %d without a credential, want 401", res.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/hosts", http.NoBody)
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.adminToken)
	res, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/hosts with a token: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("the host list returned %d with a valid token, want 200", res.StatusCode)
	}
}

// TestARevokedMachineCanEnrolAgain is the way out of a permanent 409.
//
// A machine-id hash is claimed by the host row, and the enrolment handler refuses a machine that
// already has one. Without a release, any host row that outlives its usefulness — a revoked host, an
// enrolment that failed after the row committed — wedges that physical machine for ever: it cannot
// authenticate and it cannot enrol again, and the only repair is somebody editing the database. This
// asserts the two operator actions that release it, and that neither needs a hand-written UPDATE.
func TestARevokedMachineCanEnrolAgain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// The same state directory means the same machine-id salt, and therefore the same hash — which is
	// what one physical machine enrolling twice looks like to the server.
	first := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	_, err := agent.Enroll(ctx, agent.EnrollOptions{
		ServerURL: h.server.URL,
		Token:     h.issueToken(t, "web-prod"),
		StateDir:  first.Dir(),
		CABundle:  h.caFile,
		Hostname:  "web-01",
	})
	if err == nil {
		t.Fatal("a machine that is already enrolled enrolled a second time")
	}

	if err := h.scoped().RevokeHost(ctx, first.HostID); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	second, err := agent.Enroll(ctx, agent.EnrollOptions{
		ServerURL: h.server.URL,
		Token:     h.issueToken(t, "web-prod"),
		StateDir:  first.Dir(),
		CABundle:  h.caFile,
		Hostname:  "web-01",
	})
	if err != nil {
		t.Fatalf("re-enrolling a revoked machine: %v", err)
	}
	if second.HostID == first.HostID {
		t.Error("re-enrolment reused the revoked host's identity")
	}

	// The new certificate authenticates, and the revoked host's row is still there to be audited.
	if _, err := h.agentClient(t, second).Heartbeat(ctx, protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:aaa",
	}); err != nil {
		t.Fatalf("the re-enrolled host cannot speak: %v", err)
	}
	if _, err := h.scoped().GetHost(ctx, first.HostID); err != nil {
		t.Errorf("the revoked host's history was discarded: %v", err)
	}
}

// TestDeletingAHostAlsoReleasesItsMachine covers the operator's other repair.
//
// Deletion is for the row that should never have existed rather than for the host that did — an
// enrolment abandoned halfway, a test machine. It has to release the machine id too, or it would be the
// one action that looks like a cleanup and leaves the wedge in place.
func TestDeletingAHostAlsoReleasesItsMachine(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	first := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	if err := h.scoped().DeleteHost(ctx, first.HostID); err != nil {
		t.Fatalf("deleting: %v", err)
	}
	if _, err := agent.Enroll(ctx, agent.EnrollOptions{
		ServerURL: h.server.URL,
		Token:     h.issueToken(t, "web-prod"),
		StateDir:  first.Dir(),
		CABundle:  h.caFile,
		Hostname:  "web-01",
	}); err != nil {
		t.Fatalf("enrolling a machine whose host was deleted: %v", err)
	}
}

// TestGuaranteeARenewedAwayCertificateStopsWorking is what makes the agent's key rotation worth
// something.
//
// The agent generates a fresh key at every renewal, which bounds what a leaked agent.pem is worth — and
// it bounded nothing, because the certificate it rotated away from stayed valid until its ninetieth
// day. Somebody who read the file on day ten kept a working authentication path for eighty more, and
// could spend the renewals themselves to keep it indefinitely.
//
// The old credential keeps working during the overlap, which is asserted first: the agent promotes its
// new credential with one rename, and a host interrupted between obtaining a certificate and promoting
// it has to be able to come back on the old one. What must not survive is the overlap.
func TestGuaranteeARenewedAwayCertificateStopsWorking(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	// A second client on the *original* credential, built before the renewal replaces the file on
	// disk. This stands in for the copy somebody took: the same certificate and key, still presented
	// after the host has rotated away from them.
	stolen := h.agentClient(t, h.copyCredential(t, state, "stolen"))

	if _, err := h.agentClient(t, state).Renew(context.Background(), csrNaming(t, state.HostID)); err != nil {
		t.Fatalf("renewing: %v", err)
	}

	// Inside the overlap the old certificate still authenticates, which is what keeps an interrupted
	// renewal from stranding a host.
	if _, err := stolen.Heartbeat(context.Background(), protocol.HeartbeatRequest{
		AgentVersion: "0.0.0-test", BootID: "boot-1",
	}); err != nil {
		t.Fatalf("the superseded certificate stopped working immediately, which strands a host "+
			"interrupted mid-renewal: %v", err)
	}

	// Past it, it does not. The clock is moved by rewriting the stored supersession rather than by
	// waiting two days.
	h.expireSupersession(t, state)

	_, err := stolen.Heartbeat(context.Background(), protocol.HeartbeatRequest{
		AgentVersion: "0.0.0-test", BootID: "boot-1",
	})
	if err == nil {
		t.Fatal("a certificate the host renewed away from still authenticates after the overlap; " +
			"rotating the key bought nothing")
	}
}

// TestGuaranteeAHostCannotAccumulateCertificates is the other half of the renewal bound.
//
// A rate limit bounds how fast a host may renew and not how many certificates it ends up holding, and
// the total is what fills a table every tenant of a hosted installation shares — and what widens the
// window in which any one leaked key still works. Both are refusals rather than silent successes, so a
// host in this state is visible.
func TestGuaranteeAHostCannotAccumulateCertificates(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)

	// Comfortably more attempts than either bound allows, from a host that keeps presenting a valid
	// credential. The count is a literal rather than the constants, which this package cannot see, and
	// the assertion is that renewal stops rather than where: the limiter and the cap are two separate
	// bounds and either one refusing is the correct outcome.
	const attempts = 20
	refused := 0
	for range attempts {
		if _, err := client.Renew(context.Background(), csrNaming(t, state.HostID)); err != nil {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("a host renewed 20 times without a refusal; every call signs with the CA key and adds " +
			"a row to a table every tenant shares")
	}

	live, err := h.store.In(h.tenant).CountLiveCertificates(context.Background(), state.HostID, time.Now())
	if err != nil {
		t.Fatalf("counting certificates: %v", err)
	}
	// The cap is a small number and this asserts the shape rather than its value, so that raising it
	// does not fail a test about accumulation. What must not happen is one certificate per attempt.
	if live >= attempts {
		t.Errorf("the host holds %d live certificates after %d renewals; nothing bounded the total",
			live, attempts)
	}
}
