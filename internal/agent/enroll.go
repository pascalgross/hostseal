package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/pascalgross/hostseal/internal/buildinfo"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/signing"
)

// EnrollOptions are the inputs to enrolling a host.
type EnrollOptions struct {
	// ServerURL is the control plane to enrol with.
	ServerURL string

	// Token is the single-use bootstrap token.
	Token string

	// StateDir is where the agent keeps its key, certificate and state.
	StateDir string

	// CABundle is a path to the control plane's CA, for a private server certificate.
	CABundle string

	// SignersFile is a local trusted-signers file to install before anything is fetched.
	//
	// The trust anchor is established from a local, administrator-chosen file, never from the control
	// plane: a destructive job is verified against a key the server never supplied, and the file is
	// installed here so that a freshly enrolled host has one before its first heartbeat.
	SignersFile string

	// PolicyFile is a local policy.toml to install.
	PolicyFile string

	// Hostname overrides the reported hostname, for testing.
	Hostname string
}

// Enroll registers this host with a control plane and writes its credentials.
//
// The private key is generated here and never leaves the host: only a certificate signing request is
// sent. The certificate that comes back is written atomically alongside it, so that an interrupted
// enrolment leaves a host that is not enrolled rather than one that is half enrolled.
func Enroll(ctx context.Context, opts EnrollOptions) (*State, error) {
	if opts.ServerURL == "" || opts.Token == "" {
		return nil, errors.New("agent: a server URL and a token are required")
	}
	if err := os.MkdirAll(opts.StateDir, 0o750); err != nil {
		return nil, fmt.Errorf("agent: creating %s: %w", opts.StateDir, err)
	}

	// The trust anchor and the policy are installed first, from local files the administrator chose,
	// before anything is fetched. Ordering is the point: a trust anchor the same server supplied would
	// be a trust anchor that verifies nothing.
	if opts.SignersFile != "" {
		if err := installLocalFile(opts.SignersFile, signing.TrustedSignersPath); err != nil {
			return nil, err
		}
	}
	if opts.PolicyFile != "" {
		if err := installLocalFile(opts.PolicyFile, "/etc/hostseal/policy.toml"); err != nil {
			return nil, err
		}
	}

	key, csrPEM, err := generateKeyAndCSR()
	if err != nil {
		return nil, err
	}

	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	machineID, err := MachineIDHash(opts.StateDir)
	if err != nil {
		// Not fatal. A container or a minimal image may have no machine-id, and refusing to enrol it
		// would exclude exactly the hosts most likely to be forgotten. Duplicate detection is weaker
		// without it, which is worth a warning and not worth a refusal.
		slog.Warn("could not hash the machine id; duplicate detection will be weaker", "error", err)
	}

	client, err := NewUnauthenticatedClient(opts.ServerURL, opts.CABundle)
	if err != nil {
		return nil, err
	}

	res, err := client.Enroll(ctx, protocol.EnrollRequest{
		Token:         opts.Token,
		CSR:           string(csrPEM),
		Hostname:      hostname,
		MachineIDHash: machineID,
		AgentVersion:  buildinfo.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("agent: enrolling: %w", err)
	}
	if res.HostID == "" || res.Certificate == "" {
		return nil, errors.New("agent: the control plane returned an incomplete enrolment response")
	}
	// Checked rather than assumed, because this value is written into the state file, into log lines
	// and into every result this host reports: an id the control plane chose is content in documents
	// something else parses, and one carrying a newline or a control character would be adding lines
	// to those documents rather than filling in one field. See protocol.ValidHostID.
	if !protocol.ValidHostID(res.HostID) {
		return nil, fmt.Errorf("agent: the control plane assigned the host id %q, which is not %s; "+
			"refusing to enrol", res.HostID, protocol.HostIDShape)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("agent: encoding the private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := WriteCredential(opts.StateDir, []byte(res.Certificate), keyPEM); err != nil {
		return nil, err
	}
	if res.CABundle != "" {
		if err := WriteFileAtomic(filepath.Join(opts.StateDir, CABundleFile), []byte(res.CABundle), 0o644); err != nil {
			return nil, err
		}
	}
	// Cached now as well as on every heartbeat, so that a host enrolled and immediately handed a
	// routine job can verify it without waiting for a beat. A failure here is logged rather than
	// fatal: enrolment has already succeeded on the server, the host has a working credential, and
	// the next heartbeat will supply the key again. Failing the whole enrolment over the key that
	// governs one intent would be the wrong trade.
	if err := StoreOnlineKey(opts.StateDir, res.OnlineKey); err != nil {
		slog.Warn("could not cache the control plane's online key at enrolment; "+
			"routine jobs are refused until a heartbeat supplies it", "error", err)
	}

	state := &State{ServerURL: trimSlash(opts.ServerURL), HostID: res.HostID, EnrolledAt: time.Now()}
	if err := state.Save(opts.StateDir); err != nil {
		return nil, err
	}

	// Last, once everything the agent will read is on disk: `hostseal enroll` runs as root and the
	// agent does not, so the credential and the state have to be handed to the service account before
	// they are of any use to it.
	if err := AdoptStateDir(opts.StateDir); err != nil {
		return nil, enrolledButUnreadable(res.HostID, opts.StateDir, err)
	}

	slog.Info("enrolled", "host", res.HostID, "server", state.ServerURL, "hostname", hostname)
	return state, nil
}

// generateKeyAndCSR creates the host's key pair and a certificate signing request.
//
// ECDSA P-256 for the same reason the CA uses it: the agent's connection may pass through a proxy or a
// load balancer, and the whole reason the transport is ordinary HTTPS is that it survives those.
//
// The CSR's subject is deliberately minimal. The control plane overwrites it with the host id it
// assigns, because a CSR is an untrusted document and honouring its subject would let a host enrol
// under any name it liked.
func generateKeyAndCSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: generating a key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "hostseal-agent"},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: creating a certificate request: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// installLocalFile copies an administrator-chosen file into place before anything is fetched.
//
// It refuses to overwrite an existing file. Silently replacing a host's trust anchor or its policy
// during a re-enrolment would undo decisions somebody made deliberately, and the recovery is noticing
// that a host started accepting things it used not to.
func installLocalFile(source, destination string) error {
	body, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("agent: reading %s: %w", source, err)
	}
	if existing, err := os.ReadFile(destination); err == nil && len(existing) > 0 {
		if string(existing) == string(body) {
			return nil
		}
		return fmt.Errorf("agent: %s already exists and differs from %s; refusing to replace it. "+
			"Edit it in place if the change is intended", destination, source)
	}
	// 0755, not 0750. /etc/hostseal holds root-owned, world-readable configuration that the
	// unprivileged hostseal user must be able to read: the agent reads policy.toml and trusted-signers
	// on every cycle, and a directory it cannot traverse would make the host refuse everything.
	//nolint:gosec // G301: deliberate, and the files inside are individually 0644 root:root.
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("agent: creating %s: %w", filepath.Dir(destination), err)
	}
	slog.Info("installing local file", "source", source, "destination", destination)
	return WriteFileAtomic(destination, body, 0o644)
}

// enrolledButUnreadable reports an enrolment the service account cannot use.
//
// The enrolment worked, the credential is on disk, and the only problem is which user owns it.
// Telling somebody to start over here would spend a second token to reproduce the same files.
//
// It names the command, because the alternative is the failure this whole function exists to prevent:
// an agent that starts, cannot read its own credential, reports "not enrolled", and leaves an operator
// looking at a control plane that shows the host and a host that sends nothing.
func enrolledButUnreadable(hostID, stateDir string, err error) error {
	return fmt.Errorf("%w\n\nThis host enrolled as %s and the credential is on disk, but it is owned "+
		"by the wrong user, so the agent will report \"not enrolled\" and send nothing. Do not enrol "+
		"again — that spends another token for the same files. Fix the ownership instead:\n\n"+
		"    sudo chown -R hostseal:hostseal %s\n    sudo systemctl restart hostseal-agent",
		err, hostID, stateDir)
}
