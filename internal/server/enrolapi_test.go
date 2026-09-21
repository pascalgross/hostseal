package server_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestTheCACertificateIsServedWithoutACredential is the one unauthenticated route under /api/v1.
//
// It is deliberate rather than an omission, and the reason is what the document is: a CA certificate is
// handed to every enrolling agent before that agent has any credential at all, so withholding it here
// would withhold nothing. What serving it buys is the second step of enrolment being one command on the
// host rather than a browser download and a copy across — and a step that spans two machines is the
// step people improvise around.
//
// What is asserted alongside is that it really is a certificate, and the CA's own. A route that
// answered 200 with an error page would satisfy "no credential needed" and leave every host trusting
// nothing.
func TestTheCACertificateIsServedWithoutACredential(t *testing.T) {
	h := newHarness(t)

	res, err := h.server.Client().Get(h.server.URL + "/api/v1/ca.crt")
	if err != nil {
		t.Fatalf("fetching the CA: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("the CA certificate returned %d without a credential", res.StatusCode)
	}
	if disposition := res.Header.Get("Content-Disposition"); !strings.Contains(disposition, "hostseal-ca.crt") {
		t.Errorf("Content-Disposition is %q; a browser will render it rather than save it", disposition)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading the CA: %v", err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatalf("the response is not a PEM block: %s", body)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the CA: %v", err)
	}
	if !cert.IsCA {
		t.Errorf("the certificate served at /api/v1/ca.crt is not a CA: %s", cert.Subject)
	}
}

// TestTheEnrolmentInstructionsNeedAnOperatorAndNameTheAgentAddress covers the other half.
//
// The agent URL is a statement about this installation's topology rather than a public document, so
// unlike the certificate beside it this route takes a credential. And the address it reports is the
// configured one: the panel that renders it exists because the page used to print a placeholder every
// operator replaced by hand, and deriving the answer from the request would replace that placeholder
// with the interface's own hostname — which, in the deployment this project documents, is the one
// hostname where the agent API answers 403.
func TestTheEnrolmentInstructionsNeedAnOperatorAndNameTheAgentAddress(t *testing.T) {
	h := newHarness(t)

	res, err := h.server.Client().Get(h.server.URL + "/api/v1/enrolment")
	if err != nil {
		t.Fatalf("GET /api/v1/enrolment: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("the enrolment instructions returned %d without a credential, want 401", res.StatusCode)
	}

	status, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/enrolment", nil)
	if status != http.StatusOK {
		t.Fatalf("reading the instructions returned %d: %s", status, body)
	}
	var view struct {
		// AgentURL is what the enrolment command names, and IsAGuess whether anybody configured it.
		AgentURL string `json:"agentUrl"`
		IsAGuess bool   `json:"agentUrlIsAGuess"`

		// CACertificatePath is where the second step reads the certificate from.
		CACertificatePath string `json:"caCertificatePath"`

		// CAFingerprint is what an unverified fetch of that certificate is checked against.
		CAFingerprint string `json:"caFingerprint"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decoding the instructions: %v", err)
	}

	// The harness configures no agent URL, so the answer is the browser's own address and says so.
	// That is the honest state rather than a broken one, and the flag is what lets the interface warn
	// instead of printing a confident wrong command.
	if !view.IsAGuess {
		t.Error("an unconfigured agent address was reported as though somebody had chosen it")
	}
	if view.AgentURL == "" {
		t.Error("no agent address was reported at all, so the instructions name nothing")
	}
	if view.CACertificatePath != "/api/v1/ca.crt" {
		t.Errorf("the instructions point at %q for the CA, which is not where it is served",
			view.CACertificatePath)
	}

	// The digest of the certificate actually served, in the spelling openssl prints, because it exists
	// to be compared against `openssl x509 -fingerprint -sha256` on a host that could not verify the
	// connection it fetched over. A digest of something else, or in another format, is a comparison
	// that fails for the wrong reason — and an operator who has been told to expect a match and gets a
	// mismatch does not install a certificate they should have installed.
	// Computed here rather than called from the server package, so the test is a statement about the
	// format an operator will compare against rather than a second call to the same function.
	sum := sha256.Sum256(h.authority.Certificate().Raw)
	pairs := make([]string, 0, len(sum))
	for _, b := range sum {
		pairs = append(pairs, fmt.Sprintf("%02X", b))
	}
	want := strings.Join(pairs, ":")
	if view.CAFingerprint != want {
		t.Errorf("the instructions publish %q as the CA fingerprint, want %q",
			view.CAFingerprint, want)
	}
	if !strings.Contains(view.CAFingerprint, ":") || strings.ToUpper(view.CAFingerprint) != view.CAFingerprint {
		t.Errorf("the fingerprint is %q, which is not the colon-separated uppercase hex openssl "+
			"prints, so an operator cannot compare it without transforming it first", view.CAFingerprint)
	}
}

// TestTheInstructionsSayWhereEachPlatformGetsTheAgentFrom is the omission this file did not catch.
//
// Debian and Ubuntu hosts have a repository, and the instructions have always named it. Windows hosts
// have none — the agent for them is one archive attached to a release — and for several releases the
// archive was built, checksummed into SHA256SUMS, and then attached to nothing, while the panel went on
// printing apt-get to whoever was holding a Windows Server. Every route to that agent was a Linux one.
//
// Both fields are asserted together because that is the property: an operator on either platform is
// told where their agent comes from. One of them being present is how this went unnoticed.
func TestTheInstructionsSayWhereEachPlatformGetsTheAgentFrom(t *testing.T) {
	h := newHarness(t)

	status, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/enrolment", nil)
	if status != http.StatusOK {
		t.Fatalf("reading the instructions returned %d: %s", status, body)
	}
	var view struct {
		// APTURL is where a Debian or Ubuntu host installs the agent from.
		APTURL string `json:"aptUrl"`

		// WindowsArchiveURL is where a Windows host downloads it from.
		WindowsArchiveURL string `json:"windowsArchiveUrl"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decoding the instructions: %v", err)
	}

	if view.APTURL == "" {
		t.Error("the instructions name no APT repository, so a Debian host is told nothing to install from")
	}
	// The archive's own name rather than the whole URL: what matters is that the link points at the
	// release asset an operator has to unpack, and a test pinned to the host would fail on a mirror
	// instead of on the thing it is about.
	if !strings.HasSuffix(view.WindowsArchiveURL, "hostseal-agent-windows-amd64.zip") {
		t.Errorf("the instructions point a Windows host at %q, which is not the release archive",
			view.WindowsArchiveURL)
	}
}
