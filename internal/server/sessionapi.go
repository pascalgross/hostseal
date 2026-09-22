package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/pascalgross/hostseal/internal/auth"
)

// MaxSessionRequestBytes bounds a sign-in request body.
//
// An address and a password. This is generous by two orders of magnitude and exists so the body is
// bounded before it is in memory, like every other body this server reads — which matters more here
// than elsewhere, because this is one of the two routes reachable without a credential.
const MaxSessionRequestBytes = 4 << 10

// The bounds on sign-in attempts, per source address.
//
// The second endpoint in this server that anybody may reach without a credential, and the only one
// where an attempt is cheap for the caller and expensive here: verifying a password is an Argon2id
// derivation that allocates 64 MiB, so an unbounded sign-in route is a memory exhaustion primitive
// before it is a password-guessing one. That is why this limit exists even though the enrolment
// comment argues limits are mostly about load rather than success — here it is about both.
//
// Ten attempts and one back every six seconds: a person who has forgotten which of two passwords they
// used will not notice, and a script will.
const (
	// signInBurst is how many attempts a source may make at once.
	signInBurst = 10

	// signInRefill is how long one attempt takes to come back.
	signInRefill = 6 * time.Second
)

// handleSignIn exchanges an address and a password for a session cookie.
//
// Unauthenticated by construction — it is where a credential comes from — which is why it is rate
// limited, why the body is bounded, and why every failure is one answer. A wrong address, a wrong
// password and an account that has been deleted are indistinguishable from here, and deliberately cost
// the same: internal/auth verifies against a decoy hash when the address is unknown, so the response
// time does not sort the addresses that exist from the ones that do not.
//
// The response carries the identity rather than the token, because the token is in an HttpOnly cookie
// the browser will send back on its own. There is nothing here for a script to store, which is the
// point: a script mints an API token from the account page and uses that instead.
//
// It requires auth.SessionHeader even though it authenticates nobody, and that is the least obvious
// line in this file. Everywhere else the header stops a cross-site request from *using* a cookie; here
// it stops one from *causing* a cookie. A cross-site HTML form cannot set a header and cannot send
// JSON — but it can send `enctype="text/plain"`, whose encoding is `name=value`, and a field named
// `{"email":"a@b","password":"p","x":"` with the value `"}` produces a body that is valid JSON. That
// content type is CORS-safelisted, so there is no preflight, and a form submission is a top-level
// navigation, so the response is first-party and the Set-Cookie below is stored. SameSite=Lax does not
// help: it governs whether a cookie is sent, not whether one may be set.
//
// The result is login CSRF, which is quieter than it sounds and worse: the victim is signed in as the
// *attacker*, and every host they enrol and token they mint afterwards lands in the attacker's
// fleet, under the attacker's principal, for the attacker to read later.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		// No accounts provider configured. It is 404 rather than 501 because the route genuinely does
		// not exist on this installation, and a client that got 501 would keep offering the form.
		writeError(w, http.StatusNotFound, "not_found", "this control plane has no account sign-in")
		return
	}
	if r.Header.Get(auth.SessionHeader) == "" {
		// Before the rate limiter on purpose: a cross-site attempt is made by somebody else's browser,
		// and spending their bucket would let an attacker lock a victim out of signing in for real.
		writeError(w, http.StatusBadRequest, "missing_header",
			"a sign-in must carry the "+auth.SessionHeader+" header; this control plane's interface "+
				"sends it, and a page on another origin cannot")
		return
	}
	if !s.signInLimiter.allow(auth.RequestSource(r), time.Now()) {
		w.Header().Set("Retry-After", strconv.Itoa(int(s.signInLimiter.retryAfter().Seconds())))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many sign-in attempts")
		return
	}

	var req struct {
		// Email is the address the operator signs in with.
		Email string `json:"email"`

		// Password is what they typed. It is never logged, never stored and never echoed.
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, MaxSessionRequestBytes, &req); err != nil {
		writeDecodeError(w, err, "the request body holds more than one value; send one sign-in")
		return
	}

	// A credential in the response, and a redirect chain in front of a browser: no cache may keep it.
	noStore(w)

	identity, err := s.accounts.SignIn(r.Context(), w, r, req.Email, req.Password)
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		// One refusal for every wrong credential. The log line carries the address, because an operator
		// locked out of their own control plane is the commonest reason anybody reads it — and never
		// the password.
		slog.Info("sign-in refused", "email", auth.NormaliseEmail(req.Email), "source", auth.RequestSource(r))
		w.Header().Set("WWW-Authenticate", `Bearer realm="hostseal"`)
		writeError(w, http.StatusUnauthorized, "unauthenticated",
			"that address and password do not match an account on this control plane")
		return
	case err != nil:
		// Not a refusal: the credential may well have been right and the database was not reachable.
		// Answering 401 here would tell somebody their password was wrong during an outage, and they
		// would spend the outage typing it again.
		slog.Error("could not complete a sign-in", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not complete the sign-in")
		return
	}

	slog.Info("operator signed in", "operator", identity.Principal(), "tenant", identity.Tenant)
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":   identity.Subject,
		"display":   identity.Display,
		"provider":  identity.Provider,
		"principal": identity.Principal(),
	})
}

// handleSignOut ends the session a request carries.
//
// It is not behind requireOperator, and that is deliberate rather than an oversight: a session that has
// already expired still has a cookie in the browser and a row in the table, and refusing to sign such a
// caller out would leave both in place. Signing out is the one operation that must work for a
// credential that no longer authenticates.
func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		writeError(w, http.StatusNotFound, "not_found", "this control plane has no account sign-in")
		return
	}
	if err := s.accounts.SignOut(r.Context(), w, r); err != nil {
		slog.Error("could not end a session", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not end the session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
