package localsign

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/canonical"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/signing"
)

// testOrigin is the one origin the services built below sign for.
const testOrigin = "https://hostseal.example.org"

// stubSigner is a signing.Signer over an in-process key, for tests that are about the service.
//
// Not the file backend and certainly not a token: what these tests exercise is what the service does
// with a signer, so the signer is the part that should be trivial and predictable. It counts its calls
// because several of the properties here are "nothing was signed", and the only honest way to assert
// that is to ask the key.
type stubSigner struct {
	// key is the private half.
	key ed25519.PrivateKey

	// calls counts Sign invocations.
	calls int

	// corrupt makes Sign return a signature that does not verify, standing in for a token that
	// returns a signature in an encoding HostSeal's wire format does not carry.
	corrupt bool
}

// newStubSigner builds a signer over a fresh key.
func newStubSigner(t *testing.T) *stubSigner {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return &stubSigner{key: key}
}

// KeyID returns the identity a host's trusted-signers would have to list.
func (s *stubSigner) KeyID() string { return "ops-test" }

// Algorithm reports the wire algorithm.
func (s *stubSigner) Algorithm() signing.Algorithm { return signing.Ed25519 }

// Public returns the verifying half.
func (s *stubSigner) Public() crypto.PublicKey { return s.key.Public() }

// Backend names how the key is held, for display.
func (s *stubSigner) Backend() string { return "test" }

// Sign signs the payload, or returns nonsense, as the test asked.
func (s *stubSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	s.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.corrupt {
		return []byte("not a signature"), nil
	}
	return ed25519.Sign(s.key, payload), nil
}

// Close releases nothing, because there is nothing to release.
func (s *stubSigner) Close() error { return nil }

// alwaysConfirm answers yes, and records what it was asked.
//
// The recording is the point in more than one test: the operator's prompt is where the body is read,
// so "the service asked about the template that was actually signed" is a property worth holding.
type alwaysConfirm struct {
	// asked is the last request handed to the confirmation.
	asked Request

	// calls counts how many times a human was asked.
	calls int
}

// confirm is the ConfirmFunc.
func (a *alwaysConfirm) confirm(req Request) (bool, error) {
	a.calls++
	a.asked = req
	return true, nil
}

// newTestService builds a service and its HTTP handler.
func newTestService(t *testing.T, signer signing.Signer, confirm ConfirmFunc) http.Handler {
	t.Helper()
	service, err := New(Options{
		Signer:      signer,
		Origins:     []string{testOrigin},
		Confirm:     confirm,
		ConfirmJob:  func(JobConfirmation) (bool, error) { return true, nil },
		SignTimeout: 5 * time.Second,
		Log:         io.Discard,
	})
	if err != nil {
		t.Fatalf("building the service: %v", err)
	}
	return service.Handler()
}

// signRequest posts a template to the signing endpoint with the headers a browser would send.
func signRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, SignTemplatePath, strings.NewReader(body))
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.Host = "127.0.0.1:18515"
	return r
}

// TestTheSignedPayloadIsBuiltHereRatherThanReceived is the property the whole package exists for.
//
// The request carries a name and a body; the signature that comes back has to verify against the
// canonical {name, body} document — the same bytes `hostseal sign-template` signs and the same bytes an
// enrolling agent reconstructs and checks. If this service ever signed something the caller supplied
// instead, a compromised control plane could show one template in the browser and have another signed,
// and every guardrail in docs/SECURITY.md §7 would be standing on a signature over bytes nobody read.
func TestTheSignedPayloadIsBuiltHereRatherThanReceived(t *testing.T) {
	signer := newStubSigner(t)
	confirm := &alwaysConfirm{}
	handler := newTestService(t, signer, confirm.confirm)

	const name = "hostseal-baseline"
	const body = "#cloud-config\npackage_update: true\n"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, signRequest(`{"name":"`+name+`","body":"#cloud-config\npackage_update: true\n"}`))

	if response.Code != http.StatusOK {
		t.Fatalf("signing answered %d: %s", response.Code, response.Body.String())
	}
	var got struct {
		Name            string `json:"name"`
		Signature       string `json:"signature"`
		SignerKeyID     string `json:"signerKeyId"`
		SignerAlgorithm string `json:"signerAlgorithm"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}

	payload, err := canonical.Marshal(protocol.Bootstrap{Name: name, Body: body}.SignedPayload())
	if err != nil {
		t.Fatalf("canonicalising the expected payload: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(got.Signature)
	if err != nil {
		t.Fatalf("the signature is not base64: %v", err)
	}
	key := signing.PublicKey{Algorithm: signing.Ed25519, KeyID: got.SignerKeyID, Key: signer.Public()}
	if !key.Verify(payload, signature) {
		t.Errorf("the signature does not verify over the canonical {name, body} payload.\n" +
			"That is what an enrolling agent checks, so a signature over anything else is one every " +
			"host refuses — or, worse, one made over bytes the operator never saw.")
	}
	if got.SignerKeyID != "ops-test" || got.SignerAlgorithm != string(signing.Ed25519) {
		t.Errorf("the response names %s/%s, the signer is ops-test/ed25519",
			got.SignerKeyID, got.SignerAlgorithm)
	}
	if confirm.asked.Name != name || confirm.asked.Body != body {
		t.Errorf("the human was asked about %q/%q and %q/%q was signed",
			confirm.asked.Name, confirm.asked.Body, name, body)
	}
	if confirm.asked.Origin != testOrigin {
		t.Errorf("the confirmation was asked about origin %q, want %q", confirm.asked.Origin, testOrigin)
	}
}

// TestARequestThatTriesToChooseThePayloadIsRefused covers the other half of the same property.
//
// Ignoring an unknown field would be the ordinary thing for a JSON API to do, and here it would mean a
// caller sending `payload` or `digest` believing it had said what to sign, and a service signing
// something else — or, in the direction that matters, a future version of this service quietly gaining
// the field. Refusing is what makes the absence of that field a statement rather than an omission.
func TestARequestThatTriesToChooseThePayloadIsRefused(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestService(t, signer, (&alwaysConfirm{}).confirm)

	for _, body := range []string{
		`{"name":"a-template","body":"x","payload":"AAAA"}`,
		`{"name":"a-template","body":"x","digest":"AAAA"}`,
		`{"name":"a-template","body":"x","key":"pkcs11:object=other"}`,
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, signRequest(body))
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", body, response.Code)
		}
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times for requests that were refused", signer.calls)
	}
}

// TestNothingIsSignedWithoutAConfirmation is the guardrail that makes this service a signer rather
// than a signing oracle.
//
// Everything else here is defence in depth: the origin allowlist, the loopback bind, the Host check.
// They keep the question from being asked too often. This is the answer.
func TestNothingIsSignedWithoutAConfirmation(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestService(t, signer, func(Request) (bool, error) { return false, nil })

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, signRequest(`{"name":"a-template","body":"x"}`))

	if response.Code != http.StatusForbidden {
		t.Errorf("a declined signature answered %d, want 403: %s", response.Code, response.Body.String())
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times after the operator said no", signer.calls)
	}
}

// TestAConfirmationThatCannotBeAskedIsNotAYes covers the failure between yes and no.
//
// A terminal that has gone away — the signer started from a script, standard input closed — must not
// resolve to "sign it". Anything that is not an explicit yes is a no, which is the same stance
// prompt.Confirm takes one layer down and worth holding here too, because this is the layer that would
// have to be wrong only once.
func TestAConfirmationThatCannotBeAskedIsNotAYes(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestService(t, signer, func(Request) (bool, error) {
		return false, errors.New("no terminal")
	})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, signRequest(`{"name":"a-template","body":"x"}`))

	if response.Code != http.StatusInternalServerError {
		t.Errorf("an unaskable confirmation answered %d, want 500", response.Code)
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times when nobody could be asked", signer.calls)
	}
}

// TestAnOriginThatWasNotNamedIsRefused keeps the allowlist meaningful.
//
// The response must also carry no Access-Control-Allow-Origin, which is the half that is easy to lose:
// a refusal that helpfully echoed the origin back would let the page read the body of the refusal, and
// a service that answers questions about itself to any page is the beginning of a signing oracle.
func TestAnOriginThatWasNotNamedIsRefused(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestService(t, signer, (&alwaysConfirm{}).confirm)

	request := signRequest(`{"name":"a-template","body":"x"}`)
	request.Header.Set("Origin", "https://evil.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Errorf("an unnamed origin answered %d, want 403", response.Code)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("a refused origin was allowed by the CORS header: %q", got)
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times for an origin that was not named", signer.calls)
	}
}

// TestARequestAddressedToAnyNameButLoopbackIsRefused is the DNS-rebinding defence.
//
// It is the one attack the origin allowlist cannot see: a page at https://attacker.example whose name
// resolves, after a moment, to 127.0.0.1 arrives here from an origin that is genuinely its own. What it
// cannot do is make the browser address the request to 127.0.0.1, because the browser sends the name
// the page asked for — so the Host header is the thing that tells them apart.
func TestARequestAddressedToAnyNameButLoopbackIsRefused(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestService(t, signer, (&alwaysConfirm{}).confirm)

	request := signRequest(`{"name":"a-template","body":"x"}`)
	request.Host = "rebound.attacker.example:18515"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Errorf("a rebound name answered %d, want 403: %s", response.Code, response.Body.String())
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times for a request addressed to another name", signer.calls)
	}
}

// TestThePreflightAnswersThePrivateNetworkQuestion covers the header that is invisible until it is
// missing.
//
// A page served over HTTPS reaching 127.0.0.1 is a Private Network Access request, and Chrome asks for
// it by name. Answer only the ordinary CORS headers and the preflight passes every check a person
// inspects and is refused anyway — which is a long afternoon for whoever debugs it, on a machine that
// is not this one.
func TestThePreflightAnswersThePrivateNetworkQuestion(t *testing.T) {
	handler := newTestService(t, newStubSigner(t), (&alwaysConfirm{}).confirm)

	request := httptest.NewRequest(http.MethodOptions, SignTemplatePath, nil)
	request.Header.Set("Origin", testOrigin)
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Private-Network", "true")
	request.Host = "127.0.0.1:18515"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("the preflight answered %d, want 204", response.Code)
	}
	for header, want := range map[string]string{
		"Access-Control-Allow-Origin":          testOrigin,
		"Access-Control-Allow-Private-Network": "true",
		"Access-Control-Allow-Headers":         "Content-Type",
	} {
		if got := response.Header().Get(header); got != want {
			t.Errorf("%s is %q, want %q", header, got, want)
		}
	}
	if got := response.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("credentials are allowed (%q). This service has no session and no token: what "+
			"authorises a signature is a person at this machine, and a credential the browser could "+
			"send would only be a second thing to steal.", got)
	}
}

// TestASecondRequestIsRefusedWhileSomebodyIsBeingAsked keeps two prompts off one terminal.
//
// Queueing would be worse than refusing: the operator would be reading one template and answering
// another, with nothing on screen to say which. A refusal the browser can explain is the honest
// outcome, and it is a 409 rather than a 503 because the remedy is "finish the one you are looking at".
func TestASecondRequestIsRefusedWhileSomebodyIsBeingAsked(t *testing.T) {
	signer := newStubSigner(t)
	asked := make(chan struct{})
	release := make(chan struct{})
	handler := newTestService(t, signer, func(Request) (bool, error) {
		close(asked)
		<-release
		return true, nil
	})

	done := make(chan int, 1)
	go func() {
		first := httptest.NewRecorder()
		handler.ServeHTTP(first, signRequest(`{"name":"a-template","body":"x"}`))
		done <- first.Code
	}()
	<-asked

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, signRequest(`{"name":"b-template","body":"y"}`))
	if second.Code != http.StatusConflict {
		t.Errorf("the second request answered %d, want 409", second.Code)
	}

	close(release)
	if code := <-done; code != http.StatusOK {
		t.Errorf("the first request answered %d, want 200", code)
	}
	if signer.calls != 1 {
		t.Errorf("the key was used %d times, want once", signer.calls)
	}
}

// TestASignatureThatDoesNotVerifyIsNotReturned puts the backend self-check on this path too.
//
// It is the failure every remote key store walks into: a token returns ECDSA as a raw r‖s pair where
// the wire format is DER, and nothing goes wrong until every host in the fleet reports a signature from
// no trusted signer, days later. Checking here turns that into an error in a browser, now, while the
// person who could fix it is still looking.
func TestASignatureThatDoesNotVerifyIsNotReturned(t *testing.T) {
	signer := newStubSigner(t)
	signer.corrupt = true
	handler := newTestService(t, signer, (&alwaysConfirm{}).confirm)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, signRequest(`{"name":"a-template","body":"x"}`))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("a signature that does not verify answered %d, want 500", response.Code)
	}
	if strings.Contains(response.Body.String(), "signature") &&
		!strings.Contains(response.Body.String(), "verify") {
		t.Errorf("the refusal does not say what is wrong: %s", response.Body.String())
	}
}

// TestSomethingOtherThanJSONIsRefused keeps every cross-origin request behind a preflight.
//
// The content type is not a formality here. A form post carries one of three types a browser will send
// without asking permission first, so requiring application/json is what makes the allowlist above run
// before a request rather than after it.
func TestSomethingOtherThanJSONIsRefused(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestService(t, signer, (&alwaysConfirm{}).confirm)

	request := signRequest(`{"name":"a-template","body":"x"}`)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a form-encoded request answered %d, want 415", response.Code)
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times for a request that never passed a preflight", signer.calls)
	}
}

// TestAJSONContentTypeWithParametersIsAccepted covers the other side of that check.
//
// `application/json; charset=utf-8` is what several HTTP clients send and it is the same media type. A
// check that refused it would be a check that works in a browser and fails in a script, which is the
// kind of difference that gets a header requirement removed altogether.
func TestAJSONContentTypeWithParametersIsAccepted(t *testing.T) {
	handler := newTestService(t, newStubSigner(t), (&alwaysConfirm{}).confirm)

	request := signRequest(`{"name":"a-template","body":"x"}`)
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Errorf("a charset parameter was refused: %d %s", response.Code, response.Body.String())
	}
}

// TestATemplateNameTheControlPlaneWouldRefuseIsRefusedHere spends no token touch on a doomed save.
//
// The name is half of what the signature covers, so a name the control plane will not store is a
// signature that can never be used — and the operator would find that out from a 400 after confirming
// and touching their token, which is the moment least likely to be forgiven.
func TestATemplateNameTheControlPlaneWouldRefuseIsRefusedHere(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestService(t, signer, (&alwaysConfirm{}).confirm)

	for _, name := range []string{"", "Not Lower Case", "trailing-space ", strings.Repeat("a", 65)} {
		encoded, err := json.Marshal(map[string]string{"name": name, "body": "x"})
		if err != nil {
			t.Fatalf("encoding the request: %v", err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, signRequest(string(encoded)))
		if response.Code != http.StatusBadRequest {
			t.Errorf("the name %q answered %d, want 400", name, response.Code)
		}
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times for names that cannot be stored", signer.calls)
	}
}

// TestStatusNamesTheKeyAndTheLineAHostNeeds is what the web interface reads before it offers to sign.
//
// The trusted-signers line is in it because that is the half of this arrangement no tooling can do for
// anybody: a template signed by a key no host trusts is refused at every enrolment, and nothing in the
// control plane can fix it. Putting the line where the operator already is saves the step that
// otherwise gets skipped.
func TestStatusNamesTheKeyAndTheLineAHostNeeds(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestService(t, signer, (&alwaysConfirm{}).confirm)

	request := httptest.NewRequest(http.MethodGet, StatusPath, nil)
	request.Header.Set("Origin", testOrigin)
	request.Host = "127.0.0.1:18515"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status answered %d: %s", response.Code, response.Body.String())
	}
	var got statusResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding the status: %v", err)
	}
	if got.Signer != "hostseal" {
		t.Errorf("the marker is %q; a page has to be able to tell this apart from whatever else "+
			"might be listening on the port", got.Signer)
	}
	if got.KeyID != signer.KeyID() || got.Algorithm != string(signing.Ed25519) {
		t.Errorf("status reports %s/%s, want %s/ed25519", got.KeyID, got.Algorithm, signer.KeyID())
	}
	want, err := signing.TrustedSignerLine(signer)
	if err != nil {
		t.Fatalf("rendering the expected line: %v", err)
	}
	if got.TrustedSignerLine != want {
		t.Errorf("status carries the line %q, want %q", got.TrustedSignerLine, want)
	}
}

// TestTheServiceStopsWhenNothingAsksForAnything covers the idle exit.
//
// The reason it exists is worth restating where it is tested: this process holds a logged-in token
// session, and one nobody is using is a signing oracle with a prompt in front of it. Stopping is the
// honest end state, and ErrIdle is how the command knows to say so rather than looking like a crash.
func TestTheServiceStopsWhenNothingAsksForAnything(t *testing.T) {
	service, err := New(Options{
		Signer:     newStubSigner(t),
		Origins:    []string{testOrigin},
		Confirm:    (&alwaysConfirm{}).confirm,
		ConfirmJob: func(JobConfirmation) (bool, error) { return true, nil },
		Log:        io.Discard,
	})
	if err != nil {
		t.Fatalf("building the service: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stopped := make(chan error, 1)
	go func() { stopped <- service.Serve(ctx, "127.0.0.1:0", 50*time.Millisecond) }()

	if _, err := service.Address(ctx); err != nil {
		t.Fatalf("the service never bound: %v", err)
	}
	select {
	case err := <-stopped:
		if !errors.Is(err, ErrIdle) {
			t.Errorf("the service stopped with %v, want ErrIdle", err)
		}
	case <-ctx.Done():
		t.Error("the service did not stop when nothing asked it for anything")
	}
}

// TestTheServiceRefusesToListenWhereOthersCanReachIt keeps the bind check on the path that binds.
//
// ValidateAddr is tested on its own beside the origin parsing; this asserts that Serve calls it, which
// is the half that could quietly stop being true. A signer on 0.0.0.0 works perfectly for its operator
// and is a signing service for everybody else on the network.
func TestTheServiceRefusesToListenWhereOthersCanReachIt(t *testing.T) {
	service, err := New(Options{
		Signer:     newStubSigner(t),
		Origins:    []string{testOrigin},
		Confirm:    (&alwaysConfirm{}).confirm,
		ConfirmJob: func(JobConfirmation) (bool, error) { return true, nil },
		Log:        io.Discard,
	})
	if err != nil {
		t.Fatalf("building the service: %v", err)
	}
	if err := service.Serve(context.Background(), "0.0.0.0:0", time.Second); err == nil {
		t.Error("Serve accepted 0.0.0.0")
	}
}

// TestAServiceCannotBeBuiltWithoutTheThingsThatMakeItSafe pins the constructor's refusals.
//
// Each of these is a way of ending up with a signing service that works and is wrong: no confirmation
// is a signing oracle, no origin is one any page can reach, and a wildcard origin is the same thing
// spelled deliberately.
func TestAServiceCannotBeBuiltWithoutTheThingsThatMakeItSafe(t *testing.T) {
	signer := newStubSigner(t)
	confirm := (&alwaysConfirm{}).confirm

	confirmJob := func(JobConfirmation) (bool, error) { return true, nil }

	for name, opts := range map[string]Options{
		"no signer": {Origins: []string{testOrigin}, Confirm: confirm, ConfirmJob: confirmJob},
		"no template confirmation": {
			Signer: signer, Origins: []string{testOrigin}, ConfirmJob: confirmJob,
		},
		"no job confirmation": {Signer: signer, Origins: []string{testOrigin}, Confirm: confirm},
		"no origin":           {Signer: signer, Confirm: confirm, ConfirmJob: confirmJob},
		"wildcard origin": {
			Signer: signer, Confirm: confirm, ConfirmJob: confirmJob, Origins: []string{"*"},
		},
	} {
		if _, err := New(opts); err == nil {
			t.Errorf("a service was built with %s", name)
		}
	}
}

// jobRequest posts a job to the signing endpoint with the headers a browser would send.
func jobRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, SignJobPath, strings.NewReader(body))
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.Host = "127.0.0.1:18515"
	return r
}

// newTestJobService builds a service whose job confirmation is the one the test supplies.
func newTestJobService(t *testing.T, signer signing.Signer, confirm ConfirmJobFunc) http.Handler {
	t.Helper()
	service, err := New(Options{
		Signer:      signer,
		Origins:     []string{testOrigin},
		Confirm:     (&alwaysConfirm{}).confirm,
		ConfirmJob:  confirm,
		SignTimeout: 5 * time.Second,
		Log:         io.Discard,
	})
	if err != nil {
		t.Fatalf("building the service: %v", err)
	}
	return service.Handler()
}

// TestASignedJobIsAssembledHereAndNotReceived is the job half of the property this package exists for.
//
// The browser says which host, which catalogue member and which parameters. Everything a signature
// actually binds beyond that — the job's identifier, its nonce, and both edges of its validity window
// — is chosen on this side of the socket by internal/signjob, and the signature has to verify over the
// canonical document those values make. A caller that could choose the nonce could replay a signature
// a host had already spent; a caller that could choose the window could ask for a reboot that stays
// valid for a year.
func TestASignedJobIsAssembledHereAndNotReceived(t *testing.T) {
	signer := newStubSigner(t)
	const host = "01JTESTHOST0000000000000000"
	var asked JobConfirmation
	handler := newTestJobService(t, signer, func(req JobConfirmation) (bool, error) {
		asked = req
		return true, nil
	})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, jobRequest(
		`{"hostId":"`+host+`","intent":"host.reboot","params":{"delaySeconds":60}}`))

	if response.Code != http.StatusOK {
		t.Fatalf("signing answered %d: %s", response.Code, response.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	for _, field := range []string{"id", "nonce", "notBefore", "notAfter", "signature"} {
		if value, ok := got[field].(string); !ok || value == "" {
			t.Errorf("the signed job carries no %s; the browser cannot supply one, so this signer has "+
				"to", field)
		}
	}

	// Rebuilt from the response the way the control plane rebuilds it, and verified against the key.
	notBefore, err := time.Parse(time.RFC3339, got["notBefore"].(string))
	if err != nil {
		t.Fatalf("notBefore is not RFC3339: %v", err)
	}
	notAfter, err := time.Parse(time.RFC3339, got["notAfter"].(string))
	if err != nil {
		t.Fatalf("notAfter is not RFC3339: %v", err)
	}
	job := protocol.Job{
		ID:        got["id"].(string),
		Intent:    got["intent"].(string),
		Params:    got["params"].(map[string]any),
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Nonce:     got["nonce"].(string),
	}
	payload, err := canonical.Marshal(job.SignedPayload(host))
	if err != nil {
		t.Fatalf("canonicalising the expected payload: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(got["signature"].(string))
	if err != nil {
		t.Fatalf("the signature is not base64: %v", err)
	}
	key := signing.PublicKey{Algorithm: signing.Ed25519, KeyID: signer.KeyID(), Key: signer.Public()}
	if !key.Verify(payload, signature) {
		t.Errorf("the signature does not verify over the job document the response carries.\n" +
			"A host reconstructs exactly this payload and checks it against its own trusted-signers, " +
			"so a signature over anything else is one every host refuses.")
	}

	if asked.Job.ID != job.ID || asked.HostID != host {
		t.Errorf("the human was asked about job %q on %q and %q on %q was signed",
			asked.Job.ID, asked.HostID, job.ID, host)
	}
	if asked.Spec.Name.String() != "host.reboot" {
		t.Errorf("the confirmation was given the catalogue entry %q", asked.Spec.Name)
	}
	if asked.Params == nil || !strings.Contains(asked.Params.Describe(), "reboot") {
		t.Errorf("the confirmation cannot describe the operation: %v", asked.Params)
	}
}

// TestAJobRequestCannotChooseWhatBindsTheSignature is the refusing half.
//
// Each of these fields is one a browser might plausibly send and must never be honoured. Refusing is
// what makes their absence a statement: a service that ignored them would sign something the caller
// believed it had specified, which is the failure mode this whole path is built to avoid.
func TestAJobRequestCannotChooseWhatBindsTheSignature(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestJobService(t, signer, func(JobConfirmation) (bool, error) { return true, nil })

	const host = "01JTESTHOST0000000000000000"
	for _, body := range []string{
		`{"hostId":"` + host + `","intent":"host.reboot","params":{},"nonce":"replayed"}`,
		`{"hostId":"` + host + `","intent":"host.reboot","params":{},"id":"chosen"}`,
		`{"hostId":"` + host + `","intent":"host.reboot","params":{},"notAfter":"2099-01-01T00:00:00Z"}`,
		`{"hostId":"` + host + `","intent":"host.reboot","params":{},"payload":"AAAA"}`,
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, jobRequest(body))
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", body, response.Code)
		}
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times for requests that were refused", signer.calls)
	}
}

// TestAnIntentThatNeedsNoOfflineSignatureIsRefused keeps a token touch for the tier that needs one.
//
// Nothing breaks if a read intent is signed — a host takes the class from its own catalogue, never
// from the wire — but the signature buys nothing, and a tool that accepted it would teach operators to
// reach for a token where a client certificate is already the whole authorisation. The refusal names
// the tier, because "why does this need my YubiKey" is the question behind the mistake.
func TestAnIntentThatNeedsNoOfflineSignatureIsRefused(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestJobService(t, signer, func(JobConfirmation) (bool, error) { return true, nil })

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, jobRequest(
		`{"hostId":"01JTESTHOST0000000000000000","intent":"services.list","params":{}}`))

	if response.Code != http.StatusBadRequest {
		t.Errorf("a read intent answered %d, want 400: %s", response.Code, response.Body.String())
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times for an intent that needs no signature", signer.calls)
	}
}

// TestAWindowBeyondTheCeilingIsRefused bounds the one field a caller can make dangerous.
//
// A validity window is the blast radius of a signature: a signed reboot valid for a year is one that
// reaches a host which was switched off for eleven months of it. The ceiling is here rather than only
// in the browser because the browser is the thing that might be lying.
func TestAWindowBeyondTheCeilingIsRefused(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestJobService(t, signer, func(JobConfirmation) (bool, error) { return true, nil })

	for _, seconds := range []int{-1, int(MaxJobValidity.Seconds()) + 1, 365 * 24 * 3600} {
		body := fmt.Sprintf(
			`{"hostId":"01JTESTHOST0000000000000000","intent":"host.reboot","params":{},`+
				`"validForSeconds":%d}`, seconds)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, jobRequest(body))
		if response.Code != http.StatusBadRequest {
			t.Errorf("validForSeconds=%d answered %d, want 400", seconds, response.Code)
		}
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times for a window that was refused", signer.calls)
	}
}

// TestNoJobIsSignedWithoutAConfirmation is the job half of the guardrail that matters most.
func TestNoJobIsSignedWithoutAConfirmation(t *testing.T) {
	signer := newStubSigner(t)
	handler := newTestJobService(t, signer, func(JobConfirmation) (bool, error) { return false, nil })

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, jobRequest(
		`{"hostId":"01JTESTHOST0000000000000000","intent":"host.reboot","params":{}}`))

	if response.Code != http.StatusForbidden {
		t.Errorf("a declined job answered %d, want 403", response.Code)
	}
	if signer.calls != 0 {
		t.Errorf("the key was used %d times after the operator said no", signer.calls)
	}
}

// TestTheBrowserAndTheSignerAgreeAboutWhereItListens keeps one number in two languages honest.
//
// The address and the three paths are a contract between a Go program on an operator's machine and a
// TypeScript file that ships inside the control plane's binary, with nothing between them that a
// compiler can check. They are not negotiated: the page has to find the signer without the control
// plane holding any configuration about anybody's laptop, which is why the default is a constant in
// both places rather than a setting in either.
//
// Changing one and not the other produces a web interface whose signing buttons fail with "no signer
// answered" on a machine where a signer is plainly running — a false negative with no symptom
// anywhere near its cause. So it is asserted here, where both halves are readable at once.
func TestTheBrowserAndTheSignerAgreeAboutWhereItListens(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repoRoot(t), "web", "src", "app", "core",
		"local-signer.service.ts"))
	if err != nil {
		t.Fatalf("reading the browser's half of this contract: %v", err)
	}
	service := string(source)

	if !strings.Contains(service, "'http://"+DefaultAddr+"'") {
		t.Errorf("the web application does not name http://%s. It cannot discover the address, so the "+
			"two constants have to be the same one written twice.", DefaultAddr)
	}
	for _, path := range []string{StatusPath, SignTemplatePath, SignJobPath} {
		if !strings.Contains(service, path) {
			t.Errorf("the web application does not call %s", path)
		}
	}
}

// repoRoot walks up from the working directory to the module root.
//
// From the working directory rather than runtime.Caller, for the reason cmd/hostseal's documentation
// test gives: under -trimpath — which every binary this project ships is built with — a caller's file
// name is module-relative and a walk upwards from it finds no go.mod at all.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot determine the working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to the filesystem root without finding go.mod")
		}
		dir = parent
	}
}
