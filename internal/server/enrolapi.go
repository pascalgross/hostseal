package server

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// CACertificatePath is where the agent CA certificate is downloadable.
//
// Named as a constant because the interface builds a link to it and a test asserts the same path: two
// spellings of one route is a download button that answers 404 on the day somebody renames it.
const CACertificatePath = "/api/v1/ca.crt"

// handleCACertificate serves the agent CA certificate, to anybody who asks.
//
// It is the one unauthenticated route under /api/v1, and that is a decision rather than an oversight.
// The certificate is a public document — it is handed to every enrolling agent in the enrolment
// response, before that agent has any credential at all, and its whole purpose is to be distributed to
// machines that do not yet exist. Withholding it here would not withhold it.
//
// What it buys is the second step of enrolment being a single command on the host rather than a
// download in a browser and a copy over scp. That is the difference between an operator following the
// instructions and an operator improvising, and improvising is where a host ends up trusting the
// system roots instead.
//
// Nothing else about the control plane leaks through it. A CA certificate names the authority and its
// validity window; it says nothing about which hosts exist, which tenants do, or what any of them run.
func (s *Server) handleCACertificate(w http.ResponseWriter, _ *http.Request) {
	pem := s.cfg.Authority.CertificatePEM()

	// application/x-pem-file, and a filename that matches where the instructions install it. A browser
	// that guessed text/plain would show it in a tab, and the operator would then be copying a document
	// out of a viewport rather than saving the bytes.
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="hostseal-ca.crt"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(pem); err != nil {
		// Logged and not answered: the header is already written, so there is nothing left to say to
		// the client. A truncated download is visible as a certificate that does not parse.
		slog.Error("could not write the CA certificate", "error", err)
	}
}

// enrolmentView is what the interface needs to render the three enrolment steps.
//
// It is one response rather than three, because the steps are one document: an operator following them
// out of order, or with an agent URL from one control plane and a CA from another, is exactly the
// failure the page exists to prevent.
type enrolmentView struct {
	// AgentURL is the base URL to pass to `hostseal enroll --server`.
	AgentURL string `json:"agentUrl"`

	// AgentURLIsAGuess reports that nobody configured the address and this is the browser's own.
	//
	// The interface says so rather than hiding it. The documented Traefik deployment serves this page
	// on a hostname that refuses the agent API by design, so a guess is wrong there in a way that is
	// invisible until an agent has been installed and cannot enrol.
	AgentURLIsAGuess bool `json:"agentUrlIsAGuess"`

	// CACertificatePath is where the CA certificate can be fetched.
	CACertificatePath string `json:"caCertificatePath"`

	// CAFingerprint is the SHA-256 of the CA certificate, as openssl prints it.
	//
	// It is here because of the one bootstrap problem this page cannot otherwise solve. On a control
	// plane serving its own certificate, `curl` cannot verify the connection it would fetch that
	// certificate over — the file being fetched is what would establish the trust — so the only
	// remaining options are to copy the file by hand or to fetch it unverified. Fetching it unverified
	// is safe exactly when there is an independent channel to check the result against, and this
	// session is one: the operator is already authenticated here.
	//
	// Colon-separated uppercase hex rather than the bare hex used for certificate lookup elsewhere,
	// because this value exists to be compared by eye or by shell against `openssl x509 -fingerprint
	// -sha256`, and a format that does not match what openssl prints is one the operator has to
	// transform before they can compare it — which is where a comparison stops happening.
	CAFingerprint string `json:"caFingerprint"`

	// APTURL is the repository the agent package is installed from.
	APTURL string `json:"aptUrl"`

	// WindowsArchiveURL is where the Windows agent is downloaded from.
	//
	// A second field rather than a second spelling of the first, because the two platforms are not
	// served the same way and pretending otherwise is how the Windows agent went undocumented. Debian
	// and Ubuntu hosts subscribe to a signed repository and get upgrades from it; Windows has no such
	// channel here, so what a host fetches is one archive from one release and an upgrade is that same
	// fetch again.
	WindowsArchiveURL string `json:"windowsArchiveUrl"`
}

// APTRepositoryURL is where the agent package comes from.
//
// A constant rather than configuration: it is written into
// /etc/apt/sources.list.d/hostseal.sources on every host that ever installs the agent and can never be
// migrated afterwards, which is the same reason release.yml refuses to publish without it being set.
// An installation serving its own mirror edits the commands it copies; nothing about this page is the
// place to make that a setting.
const APTRepositoryURL = "https://hostseal.io/apt"

// WindowsArchiveURL is where the Windows agent's release archive is fetched from.
//
// `releases/latest/download/…` rather than a URL naming a version, so the interface does not have to
// know which release is current and cannot print a link to an older one after the next tag. It is the
// closest thing Windows has here to what `apt-get install` does for Debian and Ubuntu, and it is
// deliberately much less: no signed repository, no unattended upgrade, and an operator who must come
// back for the next one.
//
// A constant beside APTRepositoryURL, for the same reason and with the same consequence: it is the
// address an administrator downloads an agent from, so an installation serving its own copy edits the
// command rather than a setting. What it must not be is absent — the archive is built by every release
// and was, for several of them, attached to none of them, which is the failure this names.
const WindowsArchiveURL = "https://github.com/pascalgross/hostseal/releases/latest/download/" +
	"hostseal-agent-windows-amd64.zip"

// handleEnrolmentInstructions returns what an operator needs to enrol a host.
//
// Behind requireOperator, unlike the CA download beside it, because the agent URL is a statement about
// this installation's topology rather than a public document — and because the page that renders it is
// behind a credential anyway.
func (s *Server) handleEnrolmentInstructions(w http.ResponseWriter, r *http.Request, _ operator) {
	view := enrolmentView{
		AgentURL:          strings.TrimRight(s.cfg.AgentURL, "/"),
		CACertificatePath: CACertificatePath,
		CAFingerprint:     opensslFingerprint(s.cfg.Authority.Certificate()),
		APTURL:            APTRepositoryURL,
		WindowsArchiveURL: WindowsArchiveURL,
	}
	if view.AgentURL == "" {
		// The browser's own address, marked as the guess it is. It is right for the ordinary
		// single-hostname deployment and wrong for the two-hostname one, and the interface has no way
		// to tell which it is in — so it says so instead of choosing.
		view.AgentURL = "https://" + r.Host
		view.AgentURLIsAGuess = true
	}
	writeJSON(w, http.StatusOK, view)
}

// opensslFingerprint renders a certificate's SHA-256 the way `openssl x509 -fingerprint -sha256` does.
//
// Deliberately not server.Fingerprint, which produces the bare lowercase hex the certificate table is
// keyed on. That value is for machines comparing it to itself; this one is for a person comparing it to
// the output of a command on another screen, and two spellings of the same digest are a comparison that
// looks like a mismatch.
func opensslFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	pairs := make([]string, 0, len(sum))
	for _, b := range sum {
		pairs = append(pairs, fmt.Sprintf("%02X", b))
	}
	return strings.Join(pairs, ":")
}
