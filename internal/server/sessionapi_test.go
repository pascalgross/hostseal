package server_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"

	"github.com/pascalgross/hostseal/internal/auth"
)

// browser is an HTTP client that keeps cookies, the way an operator's actually does.
//
// A cookie jar rather than a hand-copied Set-Cookie header, because half of what these tests are about
// is whether a browser would send the credential back — and a test that copies the value itself would
// pass against a cookie no browser would ever return.
func (h *harness) browser(t *testing.T) *http.Client {
	t.Helper()

	pool := x509.NewCertPool()
	pem, err := os.ReadFile(h.caFile)
	if err != nil {
		t.Fatalf("reading the server CA: %v", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the server CA is not a certificate")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("building a cookie jar: %v", err)
	}
	return &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
}

// sessionRequest performs one request through a cookie-keeping client.
//
// The header auth.SessionHeader is set on every call, because that is what the application does and
// what a cross-site request cannot do; the one test that is about its absence builds its request by
// hand instead.
func sessionRequest(t *testing.T, client *http.Client, method, url string, body any) (int, []byte) {
	t.Helper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding the request: %v", err)
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(auth.SessionHeader, "1")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	return resp.StatusCode, answer
}

// TestAnOperatorSignsInWithAnAddressAndReachesTheFleet is the route pair, end to end through HTTP.
//
// It is what the interface does: post the credential, get a cookie, and have every subsequent request
// authenticated by it without the application ever holding a token. The fleet listing is the assertion
// rather than whoami, because the fleet listing is behind requireOperator and reaches the scoped store
// — so it proves the session resolved to a tenant and not merely to an identity.
func TestAnOperatorSignsInWithAnAddressAndReachesTheFleet(t *testing.T) {
	h := newHarness(t)
	client := h.browser(t)

	status, body := sessionRequest(t, client, http.MethodPost, h.server.URL+"/api/v1/session",
		map[string]string{"email": h.accountEmail, "password": h.accountPassword})
	if status != http.StatusOK {
		t.Fatalf("signing in returned %d: %s", status, body)
	}

	var identity struct {
		// Principal is what the audit trail will record for this operator.
		Principal string `json:"principal"`
	}
	if err := json.Unmarshal(body, &identity); err != nil {
		t.Fatalf("decoding the sign-in response: %v", err)
	}
	if identity.Principal != "local-account:"+h.accountEmail {
		t.Errorf("signed in as %q, want the account's own principal", identity.Principal)
	}
	if bytes.Contains(body, []byte("password")) {
		t.Error("the sign-in response mentions the password")
	}

	status, body = sessionRequest(t, client, http.MethodGet, h.server.URL+"/api/v1/hosts", nil)
	if status != http.StatusOK {
		t.Fatalf("the fleet listing returned %d for a signed-in operator: %s", status, body)
	}

	// And signing out ends it, which is the half that would otherwise be untested until somebody left.
	if status, body = sessionRequest(t, client, http.MethodDelete, h.server.URL+"/api/v1/session", nil); status != http.StatusNoContent {
		t.Fatalf("signing out returned %d: %s", status, body)
	}
	if status, _ = sessionRequest(t, client, http.MethodGet, h.server.URL+"/api/v1/hosts", nil); status != http.StatusUnauthorized {
		t.Fatalf("the fleet listing returned %d after signing out, want 401", status)
	}
}

// TestAWrongPasswordAndAnUnknownAddressAreTheSameRefusal is the reconnaissance rule at the HTTP layer.
//
// The status, the error code and the message have to be identical, because an endpoint anybody can
// reach that distinguishes them is a way to enumerate who has an account on this control plane.
func TestAWrongPasswordAndAnUnknownAddressAreTheSameRefusal(t *testing.T) {
	h := newHarness(t)

	var answers [][]byte
	for _, credential := range []map[string]string{
		{"email": h.accountEmail, "password": "not the harness password"},
		{"email": "nobody@example.org", "password": "not the harness password"},
	} {
		status, body := sessionRequest(t, h.browser(t), http.MethodPost,
			h.server.URL+"/api/v1/session", credential)
		if status != http.StatusUnauthorized {
			t.Fatalf("signing in with %v returned %d: %s", credential["email"], status, body)
		}
		answers = append(answers, body)
	}
	if !bytes.Equal(answers[0], answers[1]) {
		t.Errorf("a wrong password answers %s and an unknown address answers %s", answers[0], answers[1])
	}
}

// TestASessionCookieWithoutTheHeaderReachesNothing is the cross-site request forgery defence, at the
// layer an attacker would actually reach.
//
// A cross-site form post arrives with the cookie and no custom header — SameSite=Lax already blocks
// most of that, and this is the half that does not depend on the browser having implemented it. The
// request below is built by hand precisely because the helper above always sets the header.
func TestASessionCookieWithoutTheHeaderReachesNothing(t *testing.T) {
	h := newHarness(t)
	client := h.browser(t)

	if status, body := sessionRequest(t, client, http.MethodPost, h.server.URL+"/api/v1/session",
		map[string]string{"email": h.accountEmail, "password": h.accountPassword}); status != http.StatusOK {
		t.Fatalf("signing in returned %d: %s", status, body)
	}

	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/hosts", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("requesting the fleet: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a cookie with no %s header returned %d, want 401", auth.SessionHeader, resp.StatusCode)
	}
}

// TestSigningOutWorksWithoutASession is why the route is not behind requireOperator.
//
// A session that has already expired still has a cookie in the browser and a row in the table. If
// signing out required a working session, the one case where signing out matters most would be the one
// case it refused.
func TestSigningOutWorksWithoutASession(t *testing.T) {
	h := newHarness(t)

	if status, body := sessionRequest(t, h.browser(t), http.MethodDelete,
		h.server.URL+"/api/v1/session", nil); status != http.StatusNoContent {
		t.Fatalf("signing out with no session returned %d: %s", status, body)
	}
}

// TestASignInAttemptIsRateLimited bounds the endpoint that costs this process 64 MiB per attempt.
//
// It is the second route reachable with no credential at all, and unlike enrolment an attempt here is
// cheap for the caller and expensive here — so the limit defends against exhaustion as much as against
// guessing. The loop deliberately exceeds the burst rather than assuming a particular number.
func TestASignInAttemptIsRateLimited(t *testing.T) {
	h := newHarness(t)
	client := h.browser(t)

	var limited bool
	for i := 0; i < 40 && !limited; i++ {
		status, _ := sessionRequest(t, client, http.MethodPost, h.server.URL+"/api/v1/session",
			map[string]string{"email": "nobody@example.org", "password": "not a real password"})
		limited = status == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("forty sign-in attempts from one source were all answered; the endpoint is unbounded")
	}
}

// TestGuaranteeAFormOnAnotherOriginCannotSignThisBrowserIn is login CSRF, which is the quiet one.
//
// The familiar attack forges a request from a signed-in victim. This one is the mirror: it signs the
// victim *in*, as the attacker, and lets them work. Every host they enrol afterwards, every API token
// they mint goes into the attacker's fleet under the attacker's principal — and the attacker reads it at their leisure. Nothing looks wrong to the victim beyond a
// name in a toolbar they have no reason to check.
//
// It is reachable without JavaScript and without CORS. A form with enctype="text/plain" encodes as
// `name=value`, so a field named `{"email":…,"x":"` with the value `"}` posts a body that is valid
// JSON; that content type is CORS-safelisted, so there is no preflight; and a form submission is a
// top-level navigation, so the Set-Cookie in the response is stored. SameSite=Lax governs whether a
// cookie is *sent* cross-site, not whether one may be *set*.
//
// The defence is the header the interface already sends and a cross-origin form cannot.
func TestGuaranteeAFormOnAnotherOriginCannotSignThisBrowserIn(t *testing.T) {
	h := newHarness(t)
	client := h.browser(t)

	// Exactly what a cross-site form produces: no header, a text/plain body that happens to be JSON.
	body := fmt.Sprintf(`{"email":%q,"password":%q,"x":"="}`, h.accountEmail, h.accountPassword)
	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/session", strings.NewReader(body))
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain;charset=UTF-8")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("posting the forged sign-in: %v", err)
	}
	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a cross-origin form signed this browser in: %s", answer)
	}
	// And it set no cookie, which is the half that matters: a refusal that still handed out a session
	// would be the same attack with an error page in front of it.
	for _, cookie := range resp.Cookies() {
		if cookie.Name == auth.SessionCookieName && cookie.Value != "" {
			t.Fatal("a refused sign-in still set a session cookie")
		}
	}
	if status, _ := sessionRequest(t, client, http.MethodGet, h.server.URL+"/api/v1/hosts", nil); status != http.StatusUnauthorized {
		t.Errorf("the browser reached the fleet after a refused sign-in: %d", status)
	}

	// The same credential, sent the way the interface sends it, still works — so the defence is the
	// header rather than anything about the body.
	if status, answer := sessionRequest(t, client, http.MethodPost, h.server.URL+"/api/v1/session",
		map[string]string{"email": h.accountEmail, "password": h.accountPassword}); status != http.StatusOK {
		t.Fatalf("the interface's own sign-in returned %d: %s", status, answer)
	}
}
