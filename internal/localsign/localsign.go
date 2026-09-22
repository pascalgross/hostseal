// Package localsign is the signing service that runs on an operator's own machine and that the web
// interface asks for a signature.
//
// It exists for one shape of operator: a person whose workstation is a Windows laptop, whose signing
// key is on a YubiKey, and whose fleet is Ubuntu. Before it, signing a destructive job meant
// `hostseal sign` in a terminal, copying a JSON document out of it and pasting that document into the
// web interface by hand. Nothing was wrong with that and nothing about it has been taken away — this is
// the same act with the copying removed.
//
// What it must not become is the thing HostSeal does not have. So the arrangement is stated here, in
// the package that would be the place to weaken it:
//
//   - The private key never leaves the token, and never reaches the browser or the control plane. This
//     process holds a PKCS#11 session; what crosses to the browser is a detached signature, a key id
//     and an algorithm name.
//   - **The payload is built here, never received.** A request carries a host, an intent and its
//     parameters — what the job is about — and this package assembles and canonicalises the signed
//     job itself. A service that signed a digest handed to it by a web page would let a compromised
//     control plane display one operation in the browser and have a different one signed, which is
//     precisely the property `hostseal sign` was built to refuse (docs/PROTOCOL.md §8). That is why
//     there is no `payload` field and why an unknown field is a refusal rather than something ignored.
//   - **The terminal is the display that counts.** Every signature is confirmed by a human, on the
//     machine holding the token, against the decoded job printed there. A browser showing one thing
//     and the terminal another is a disagreement the operator can see and refuse — which is the whole
//     value of the confirmation being here rather than in the page that asked.
//   - The control plane learns nothing new. It stores the signature it is given, exactly as it does
//     for one produced by `hostseal sign`, and it still cannot mint one. A host still verifies against
//     its own /etc/hostseal/trusted-signers, and this changes nothing about that.
//
// The listener is loopback-only and its callers are named: a browser origin has to be on a list the
// operator typed, and the Host header has to be a loopback literal, which is what keeps a page that
// resolved its own hostname to 127.0.0.1 from reaching a signing service. Neither is the real control
// — the confirmation is — but a service that could be asked for a signature by any page on the
// internet would be asking its operator to be the only thing standing between a fleet and a mistake,
// several times an hour, which is how confirmations stop being read.
package localsign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pascalgross/hostseal/internal/buildinfo"
	"github.com/pascalgross/hostseal/internal/canonical"
	"github.com/pascalgross/hostseal/internal/intent"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/signing"
	"github.com/pascalgross/hostseal/internal/signjob"
)

// DefaultAddr is where the service listens unless an operator says otherwise.
//
// Loopback, and a port nobody else wants: 18515 is 0x4853, the two bytes "HS". The browser has to know
// the number without being told, because the whole point is that a page can find the signer without
// the control plane holding any configuration about an operator's laptop — so it is a constant here,
// the same constant in the web application, and documented in both.
const DefaultAddr = "127.0.0.1:18515"

// StatusPath answers "is a signer running, and whose key is in it".
const StatusPath = "/v1/signer"

// SignJobPath takes a host, an intent and its parameters and returns a signed job request.
const SignJobPath = "/v1/sign-job"

// MaxJobValidity bounds how long a signature made through this service stays valid.
//
// The window is the blast radius of a signature: a signed reboot that is still valid next week is one
// that reaches a host which was switched off all of it. `hostseal sign` takes --valid-for from a
// person who is looking at the consequence; a request arriving over a socket gets a ceiling as well,
// because the number is the one field of a job that a caller can make dangerous without making it
// look wrong.
const MaxJobValidity = 24 * time.Hour

// MaxRequestBytes bounds a request body before it is in memory.
//
// A job request is a host id, an intent name and a small parameter object, so this is generous by
// orders of magnitude; it is a bound on what an allowlisted page can make this process hold in memory
// before the decoder has looked at a byte, not a statement about what a request should be.
const MaxRequestBytes = 256 << 10

// DefaultSignTimeout bounds one call into the signing backend, after the confirmation.
//
// Longer than the thirty seconds `hostseal sign` allows, because the two bound different moments. That
// deadline starts when an operator who is already at their terminal says yes; this one starts when
// somebody in a browser asked, the terminal has just been answered, and the token that has to be
// touched may be in a drawer. A minute of grace costs nothing — nothing is signed until the token
// answers — and a deadline that expired while the operator was fetching the key would read as a broken
// signer rather than as a number chosen here.
const DefaultSignTimeout = 2 * time.Minute

// DefaultIdleTimeout is how long the service waits for work before shutting down.
//
// It exists because this process holds a logged-in token session, and a session nobody is using is a
// signing oracle with a confirmation in front of it rather than nothing at all. Exiting is the honest
// end state: the operator started it for a task, the task is over, and starting it again is one
// command. Half an hour is long enough to cover deciding on the next job between two signatures.
const DefaultIdleTimeout = 30 * time.Minute

// ErrIdle reports that the service shut down because nothing asked it for anything.
//
// A named error rather than a silent return, so the command can print why it stopped: a tool that
// vanished from a terminal without a sentence is one an operator assumes crashed.
var ErrIdle = errors.New("localsign: no request within the idle timeout")

// JobConfirmation is what the operator is asked to confirm.
//
// The origin travels with the job because it is half of the question. "Sign this job" and "sign this
// job, asked for by https://hostseal.example.org" are different questions, and the second is the one
// somebody can answer wrongly and notice.
//
// It carries the assembled job rather than the request, because the identifier, the nonce and the
// window are the signer's own and are part of what the person is authorising. The decoded parameters
// and the catalogue entry travel with it so that the confirmation can describe the operation in the
// catalogue's own words — "restart nginx.service on 01J…" rather than a JSON object — which is the
// difference between a prompt that is read and one that is answered.
type JobConfirmation struct {
	// Origin is the browser origin that asked, exactly as it arrived.
	Origin string

	// HostID is the host the signature binds this job to.
	HostID string

	// Job is the assembled job, as the signature will cover it.
	Job protocol.Job

	// Spec is the catalogue entry, for its class and summary.
	Spec intent.Spec

	// Params are the decoded parameters, which know how to describe themselves.
	Params intent.Params

	// Payload is the exact byte string the signature will cover, so the confirmation can show it.
	Payload []byte
}

// ConfirmJobFunc asks a human on this machine whether to sign a job, and reports their answer.
//
// It is a function rather than a terminal prompt written into this package for two reasons. The
// property worth testing is that nothing is signed without a yes, and a package that read a terminal
// could only be tested by pretending to be one. And the confirmation is where the operator reads the
// job: how that is rendered belongs to the command that already renders it for `hostseal sign`, so
// that the two cannot drift into showing different things.
type ConfirmJobFunc func(JobConfirmation) (bool, error)

// Options configures a service.
type Options struct {
	// Signer holds the key. Opened once, by the command, before the listener exists — so an operator
	// learns that their token is unreachable at the terminal rather than through a browser.
	Signer signing.Signer

	// Origins are the browser origins allowed to ask. Required, and never a wildcard.
	Origins []string

	// ConfirmJob asks the human about a job. Required: a service that could be constructed without
	// one would be one signature away from a signing oracle.
	ConfirmJob ConfirmJobFunc

	// SignTimeout bounds one backend call, defaulted to DefaultSignTimeout.
	SignTimeout time.Duration

	// Log is where the audit line for each request goes, usually the operator's terminal.
	//
	// Plain sentences rather than structured fields, because the reader is a person watching a
	// terminal during a task they are doing right now, and this is the only record either the browser
	// or this process keeps of what was asked.
	Log io.Writer
}

// Service is the loopback HTTP service.
type Service struct {
	// signer holds the key.
	signer signing.Signer

	// origins is the allowlist, as an exact-match set: an origin is a string comparison by
	// specification, and anything cleverer here is a way of accidentally allowing a substring.
	origins map[string]bool

	// confirmJob asks the human about a job.
	confirmJob ConfirmJobFunc

	// signTimeout bounds one backend call.
	signTimeout time.Duration

	// log is where the audit lines go.
	log io.Writer

	// inFlight admits one signing request at a time.
	//
	// A buffered channel rather than a mutex, because the wanted behaviour on contention is to refuse
	// rather than to queue: two confirmations cannot share one terminal, and a second request that
	// waited would be answered by whichever prompt the operator happened to be reading. A refusal the
	// browser can explain is the honest outcome.
	inFlight chan struct{}

	// activity is poked by every request, so the idle timer can be reset without a lock.
	activity chan struct{}

	// ready is closed once the listener is up, and carries the address it bound.
	//
	// It exists for tests that let the kernel choose a port: without it a test would have to guess
	// when the service is listening, which is the shape of a flake.
	ready struct {
		// once guards the close, so a second Serve on one Service cannot panic.
		once sync.Once

		// addr is the bound address.
		addr string

		// done is closed when addr is set.
		done chan struct{}
	}
}

// New validates the options and builds a service.
//
// Everything that can be wrong about the configuration is wrong here, before a listener exists: an
// operator who mistyped an origin should be told by the command they just ran, not by a browser
// refusing to talk to something that is already running and looks fine.
func New(opts Options) (*Service, error) {
	if opts.Signer == nil {
		return nil, errors.New("localsign: a signer is required")
	}
	if opts.ConfirmJob == nil {
		return nil, errors.New("localsign: a confirmation function is required; " +
			"a signing service nobody has to answer to is a signing oracle")
	}
	if len(opts.Origins) == 0 {
		return nil, errors.New("localsign: at least one --origin is required. It is the address of " +
			"the HostSeal web interface you will sign from; without it any page in the browser could " +
			"ask this service for a signature")
	}
	origins := map[string]bool{}
	for _, origin := range opts.Origins {
		normalised, err := ValidateOrigin(origin)
		if err != nil {
			return nil, err
		}
		origins[normalised] = true
	}
	timeout := opts.SignTimeout
	if timeout <= 0 {
		timeout = DefaultSignTimeout
	}
	log := opts.Log
	if log == nil {
		log = io.Discard
	}
	s := &Service{
		signer:      opts.Signer,
		origins:     origins,
		confirmJob:  opts.ConfirmJob,
		signTimeout: timeout,
		log:         log,
		inFlight:    make(chan struct{}, 1),
		activity:    make(chan struct{}, 1),
	}
	s.ready.done = make(chan struct{})
	return s, nil
}

// Handler returns the routes, wrapped in the checks every one of them needs.
//
// Exported so a test can drive the service over httptest rather than over a real loopback port. What
// it returns is exactly what Serve serves; a handler assembled differently for tests would be a test
// of something this package does not ship.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+StatusPath, s.handleStatus)
	mux.HandleFunc("OPTIONS "+StatusPath, s.handlePreflight)
	mux.HandleFunc("POST "+SignJobPath, s.handleSignJob)
	mux.HandleFunc("OPTIONS "+SignJobPath, s.handlePreflight)
	return s.guard(mux)
}

// Serve listens on addr until the context is cancelled or nothing asks for anything.
//
// The address is checked before it is bound rather than after: a signer listening on 0.0.0.0 is a
// signing service for everybody who can reach the machine, and the operator who typed it would have no
// symptom at all until somebody else's browser found it.
func (s *Service) Serve(ctx context.Context, addr string, idle time.Duration) error {
	if err := ValidateAddr(addr); err != nil {
		return err
	}
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}

	// Through a ListenConfig with the caller's context rather than net.Listen, so that a cancelled
	// context stops the bind as well as the serving — and so that the one place this package opens a
	// socket is the one place a reviewer looks for it.
	var config net.ListenConfig
	listener, err := config.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("localsign: cannot listen on %s: %w", addr, err)
	}
	s.ready.once.Do(func() {
		s.ready.addr = listener.Addr().String()
		close(s.ready.done)
	})

	server := &http.Server{
		Handler: s.Handler(),
		// The browser holds a connection open across a confirmation and a token touch, so no write
		// deadline can be set here without timing out the very request this exists to serve. The
		// header deadline is what a stuck client costs, and is short.
		ReadHeaderTimeout: 10 * time.Second,
	}

	// The two ways this ends besides a failed Serve: the caller cancelled, or nothing asked for
	// anything for long enough. Shutdown rather than Close in both, so a signature already being made
	// is allowed to finish and reach the browser that asked for it — a token touch is not a thing to
	// throw away on a timer.
	watchCtx, stopWatching := context.WithCancel(ctx)
	defer stopWatching()
	idled := make(chan struct{})
	go s.watchForIdleness(watchCtx, idle, idled)

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()

	var reason error
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		reason = ctx.Err()
	case <-idled:
		reason = ErrIdle
	}

	shutdownCtx, done := context.WithTimeout(context.Background(), s.signTimeout)
	defer done()
	_ = server.Shutdown(shutdownCtx)
	<-serveErr
	return reason
}

// watchForIdleness closes idled when nothing has asked for anything for the whole timeout.
//
// A goroutine with a timer rather than a deadline on the listener, because what is being measured is
// requests and not connections: a browser holds a connection open across a confirmation and a token
// touch, and an idle *connection* is exactly what a signer that is working looks like.
func (s *Service) watchForIdleness(ctx context.Context, idle time.Duration, idled chan<- struct{}) {
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.activity:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(idle)
		case <-timer.C:
			close(idled)
			return
		}
	}
}

// Address reports where the service bound, blocking until it has.
//
// For the command, which prints it, and for tests, which have to know which port the kernel chose.
func (s *Service) Address(ctx context.Context) (string, error) {
	select {
	case <-s.ready.done:
		return s.ready.addr, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// guard applies what every route needs, before any route runs.
//
// Three checks, in the order a request fails them. The Host header comes first because a failure there
// is not a mistake anybody makes honestly: a browser sends the name the page asked for, so a Host that
// is not a loopback literal means a name somewhere resolved to 127.0.0.1 — DNS rebinding, and the one
// attack that would otherwise walk straight past an origin allowlist by having a real origin of its
// own. Then the origin, then the activity poke, which happens only for requests that got this far so
// that a hostile page cannot keep the service alive indefinitely.
func (s *Service) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every response varies by origin, including the refusals: a cache that kept one origin's
		// answer for another would make this allowlist meaningless. no-store because a signature is a
		// credential, and a cached copy of one is a copy nobody is watching.
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		if !loopbackHost(r.Host) {
			writeError(w, http.StatusForbidden, "not_loopback",
				"this signer answers only on a loopback address. The request arrived addressed to "+
					r.Host+", which means a name somewhere resolved to 127.0.0.1 — ask for "+
					"http://127.0.0.1 directly.")
			return
		}

		origin := r.Header.Get("Origin")
		if !s.origins[origin] {
			// No Access-Control-Allow-Origin on this path, deliberately: the browser will report it
			// as a CORS failure, which is what it is, and the body is for whoever reads the terminal
			// or curls it directly.
			writeError(w, http.StatusForbidden, "origin_refused",
				"this signer signs for "+s.originList()+" and this request came from "+
					describeOrigin(origin)+". Restart it with --origin naming the address of the "+
					"HostSeal web interface you are signing from.")
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)

		select {
		case s.activity <- struct{}{}:
		default:
			// The watcher has a poke pending already; one is as good as two.
		}
		next.ServeHTTP(w, r)
	})
}

// handlePreflight answers the browser's permission question.
//
// Private Network Access is the half that is easy to miss: a page served over HTTPS reaching
// 127.0.0.1 is a request from a public origin into the local network, and Chrome asks for it by name
// with its own request header. Answering only the ordinary CORS headers produces a preflight that
// passes every visible check and is refused anyway, which is a bad afternoon for whoever debugs it.
func (s *Service) handlePreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")
	if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
	}
	// Credentials are deliberately not allowed. This service has no session, no cookie and no bearer
	// token: what authorises a signature is a person answering a prompt on the machine holding the
	// key, and a credential the browser could send would only be a second thing to steal.
	w.WriteHeader(http.StatusNoContent)
}

// statusResponse is what the web interface reads to decide whether signing is possible at all.
type statusResponse struct {
	// Signer is a fixed marker, so a page can tell a HostSeal signer from whatever else might be
	// listening on a port in this range.
	Signer string `json:"signer"`

	// Version is this build, for a bug report that says which one.
	Version string `json:"version"`

	// KeyID is the identity a host's trusted-signers must list.
	KeyID string `json:"keyId"`

	// Algorithm is "ed25519" or "ecdsa-p256".
	Algorithm string `json:"algorithm"`

	// Backend names how the key is held — "pkcs11" for a token — for display beside the key id.
	Backend string `json:"backend"`

	// TrustedSignerLine is the line to paste into a host's /etc/hostseal/trusted-signers.
	//
	// A public key, and the one thing an operator needs that neither the browser nor the control plane
	// can produce: a job signed by a key no host trusts is a job every host refuses, and the remedy
	// is this line on the hosts that key may act on.
	TrustedSignerLine string `json:"trustedSignerLine"`
}

// handleStatus reports which key this signer holds.
//
// Public information only — a key id, an algorithm, a public key — because it answers before any
// confirmation has happened and therefore to any page on the allowlist.
func (s *Service) handleStatus(w http.ResponseWriter, _ *http.Request) {
	line, err := signing.TrustedSignerLine(s.signer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal",
			"the key this signer holds cannot be written as a trusted-signers line: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{
		Signer:            "hostseal",
		Version:           buildinfo.String(),
		KeyID:             s.signer.KeyID(),
		Algorithm:         string(s.signer.Algorithm()),
		Backend:           s.signer.Backend(),
		TrustedSignerLine: line,
	})
}

// signJobRequest is the body of POST /v1/sign-job.
//
// Three fields that describe an operation, and one that bounds it. Everything else a signed job
// carries — its identifier, its nonce, the two edges of its validity window — is chosen by
// internal/signjob on this side of the socket. A caller that could choose a nonce could replay a
// signature; a caller that could choose a window could ask for one valid for a year; and a caller
// that could hand over a payload could have something signed that nobody ever read.
type signJobRequest struct {
	// HostID is the host to act on. The signature covers it, so it binds this job to one machine.
	HostID string `json:"hostId"`

	// Intent is the catalogue member, such as service.restart.
	Intent string `json:"intent"`

	// Params is the parameter object, passed to the catalogue's own decoder verbatim.
	//
	// Raw rather than a map, so that the bytes the decoder sees are the bytes that arrived: decoding
	// into map[string]any turns every number into a float64, and a signature is the wrong place to
	// discover that 60 has become 60.0.
	Params json.RawMessage `json:"params,omitempty"`

	// ValidForSeconds bounds how long the signature stays valid, zero for the default.
	ValidForSeconds int `json:"validForSeconds,omitempty"`
}

// handleSignJob confirms with a human and signs one destructive job.
//
// It is `hostseal sign` reached over a socket, and the ordering is the same one that command argues
// for: the job is assembled here, its parameters are decoded against this binary's own compiled-in
// catalogue, a human reads what it means on this machine, and only then is anything signed. The
// browser supplies what operation to perform on which host; it does not supply what is signed.
//
// Read and routine intents are refused rather than signed. Nothing would break if they were — a host
// checks the class from its own catalogue, not from the signature — but a signature over a read
// intent is a token touch spent on something already authorised by the client certificate, and a tool
// that accepted it would teach operators to reach for a token where none is needed.
func (s *Service) handleSignJob(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !isJSON(ct) {
		writeError(w, http.StatusUnsupportedMediaType, "not_json",
			"this endpoint takes application/json")
		return
	}

	var req signJobRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed",
			"this request is not a {\"hostId\": ..., \"intent\": ..., \"params\": ...} object: "+
				err.Error()+". The job id, the nonce and the validity window are chosen by this signer "+
				"and cannot be supplied: a caller that chose a nonce could replay a signature.")
		return
	}
	if req.HostID == "" || req.Intent == "" {
		writeError(w, http.StatusBadRequest, "malformed", "hostId and intent are both required")
		return
	}
	validFor := time.Duration(req.ValidForSeconds) * time.Second
	if validFor < 0 || validFor > MaxJobValidity {
		writeError(w, http.StatusBadRequest, "malformed",
			fmt.Sprintf("validForSeconds must be between 0 and %d; the window is how long this "+
				"signature can still reach a host that was switched off", int(MaxJobValidity.Seconds())))
		return
	}

	// Assembled before the confirmation and before anything is signed, so that a mistyped unit name
	// is an error in the browser rather than a token touch spent on a job no host will accept.
	job, spec, params, err := signjob.Draft(signjob.Request{
		HostID:    req.HostID,
		Intent:    req.Intent,
		RawParams: req.Params,
		ValidFor:  validFor,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	payload, err := canonical.Marshal(job.SignedPayload(req.HostID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal",
			"this job cannot be canonicalised: "+err.Error())
		return
	}

	select {
	case s.inFlight <- struct{}{}:
		defer func() { <-s.inFlight }()
	default:
		writeError(w, http.StatusConflict, "busy",
			"this signer is already waiting for somebody to confirm a signature at its terminal. "+
				"Answer that one first; two prompts cannot share one terminal.")
		return
	}

	confirmed, err := s.confirmJob(JobConfirmation{
		Origin:  r.Header.Get("Origin"),
		HostID:  req.HostID,
		Job:     job,
		Spec:    spec,
		Params:  params,
		Payload: payload,
	})
	if err != nil {
		s.logf("Could not ask: %v. Nothing was signed.\n", err)
		writeError(w, http.StatusInternalServerError, "no_confirmation",
			"this signer could not ask anybody on this machine whether to sign: "+err.Error())
		return
	}
	if !confirmed {
		s.logf("Declined at this terminal. Nothing was signed.\n")
		writeError(w, http.StatusForbidden, "declined",
			"the signature was declined at the signer's own terminal.")
		return
	}

	signCtx, done := context.WithTimeout(r.Context(), s.signTimeout)
	defer done()
	signature, err := s.signer.Sign(signCtx, payload)
	if err != nil {
		s.logf("Signing failed: %v\n", err)
		writeError(w, http.StatusInternalServerError, "sign_failed", "signing failed: "+err.Error())
		return
	}
	if err := signing.SelfCheck(s.signer, payload, signature); err != nil {
		s.logf("%v\n", err)
		writeError(w, http.StatusInternalServerError, "self_check", err.Error())
		return
	}

	s.logf("Signed %s on %s with %s (%s). The control plane will queue it; the host acts "+
		"on it only if %s is in its own %s, and only within its own policy.\n",
		job.Intent, req.HostID, s.signer.KeyID(), s.signer.Algorithm(),
		s.signer.KeyID(), signing.TrustedSignersPath)

	// The document POST /api/v1/jobs takes, exactly as `hostseal sign` prints it. The browser forwards
	// it rather than rebuilding it: every field here either is covered by the signature or names the
	// key that made it, and a client that assembled its own would eventually leave one out.
	writeJSON(w, http.StatusOK, signjob.Document(job, req.HostID, signature, s.signer))
}

// logf writes one line of the terminal audit trail.
//
// Its error is dropped, deliberately and in one place rather than at each call site: this is a line on
// an operator's terminal, and a signer that failed a signature because it could not write its own log
// would be trading the thing that matters for the thing that does not. Where the log goes is the
// command's choice — os.Stderr in practice, io.Discard in tests.
func (s *Service) logf(format string, args ...any) { _, _ = fmt.Fprintf(s.log, format, args...) }

// originList renders the allowlist for an error message, in a stable order.
func (s *Service) originList() string {
	list := make([]string, 0, len(s.origins))
	for origin := range s.origins {
		list = append(list, origin)
	}
	sort.Strings(list)
	return strings.Join(list, ", ")
}

// isJSON reports whether a Content-Type header names JSON.
//
// The parameters are ignored — `application/json; charset=utf-8` is what several HTTP clients send and
// it is the same media type — and the comparison is case-insensitive, as the specification says media
// types are.
func isJSON(header string) bool {
	media, _, _ := strings.Cut(header, ";")
	return strings.EqualFold(strings.TrimSpace(media), "application/json")
}

// writeJSON writes a response body.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError writes a refusal in the shape the control plane uses.
//
// The same shape deliberately: the browser has one function that turns an HTTP failure into a sentence
// for an operator, and a second shape here would mean a second one — or, more likely, a signer whose
// refusals render as "the control plane returned 403".
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, protocol.ErrorBody{Error: code, Message: message})
}
