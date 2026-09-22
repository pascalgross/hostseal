package agent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pascalgross/hostseal/internal/canonical"
)

// File names inside the agent's state directory.
const (
	// StateFile records what the agent learned at enrolment.
	StateFile = "agent.json"

	// CABundleFile is the control plane's CA chain, for verifying agent certificates on renewal.
	CABundleFile = "ca.crt"

	// SaltFile holds the per-host salt used to hash /etc/machine-id.
	//
	// It is generated at package installation and never leaves the machine. Without it, the same
	// machine-id hashed by two different fleets would produce the same value, and anybody who saw both
	// could correlate them.
	SaltFile = "machine-id-salt"

	// PendingResultsDir holds job results that have not been delivered yet.
	PendingResultsDir = "pending-results"
)

// State is what the agent knows about its enrolment.
//
// It is deliberately small: the server URL, the host id, and nothing that could be reconstructed. Any
// state that matters and can be lost — job results — lives in its own spool directory with its own
// durability rules, rather than here.
type State struct {
	// ServerURL is the control plane's base URL.
	ServerURL string `json:"serverUrl"`

	// HostID is the identifier the control plane assigned at enrolment.
	HostID string `json:"hostId"`

	// EnrolledAt is when enrolment completed.
	EnrolledAt time.Time `json:"enrolledAt"`

	// dir is where this state was loaded from, and where its siblings live.
	dir string
}

// LoadState reads the agent's enrolment state from a directory.
func LoadState(dir string) (*State, error) {
	raw, err := os.ReadFile(filepath.Join(dir, StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("agent: this host is not enrolled; run `hostseal enroll`: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("agent: reading enrolment state: %w", err)
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("agent: enrolment state is unreadable: %w", err)
	}
	s.dir = dir
	if s.ServerURL == "" || s.HostID == "" {
		return nil, errors.New("agent: enrolment state is incomplete")
	}
	return &s, nil
}

// Save writes the enrolment state atomically.
func (s *State) Save(dir string) error {
	s.dir = dir
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encoding enrolment state: %w", err)
	}
	return WriteFileAtomic(filepath.Join(dir, StateFile), raw, 0o600)
}

// Dir returns the state directory this state was loaded from.
func (s *State) Dir() string { return s.dir }

// Path returns a path inside the state directory.
func (s *State) Path(name string) string { return filepath.Join(s.dir, name) }

// WriteFileAtomic writes a file through a temporary file in the same directory and renames it.
//
// An interrupted write must never be able to leave a truncated file where a valid one used to be. For
// the certificate and key that would mean a host that cannot authenticate and cannot renew, recoverable
// only by re-enrolling it by hand — which for a fleet member in a datacentre nobody visits is a real
// cost. The directory is fsynced as well as the file, because a rename is not durable until its parent
// is.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".hostseal-*")
	if err != nil {
		return fmt.Errorf("agent: creating a temporary file in %s: %w", dir, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: setting permissions on %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: writing %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: syncing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agent: closing %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("agent: renaming into place at %s: %w", path, err)
	}
	return SyncDir(dir)
}

// MachineIDHash returns the salted hash of /etc/machine-id.
//
// The raw value is documented by systemd as confidential and is never transmitted. If no salt exists
// yet — a source build rather than a package install — one is generated and stored, so that the hash is
// stable across restarts. A hash that changed on every start would enrol the same machine repeatedly.
func MachineIDHash(dir string) (string, error) {
	id, err := machineIdentity()
	if err != nil {
		return "", err
	}
	salt, err := loadOrCreateSalt(filepath.Join(dir, SaltFile))
	if err != nil {
		return "", err
	}
	return canonical.SaltedDigest(salt, []byte(strings.TrimSpace(id))), nil
}

// loadOrCreateSalt reads the per-host salt, creating it if absent.
func loadOrCreateSalt(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil && len(raw) > 0:
		return raw, nil
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("agent: reading the machine-id salt: %w", err)
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("agent: generating a machine-id salt: %w", err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(salt))
	if err := WriteFileAtomic(path, encoded, 0o600); err != nil {
		return nil, err
	}
	return encoded, nil
}

// ownership is the numeric owner of a state directory, as the kernel reports it.
//
// It exists so that AdoptStateDir can be written once for every platform while the one call that is
// genuinely Linux-only — reading a uid and gid out of a stat structure — lives behind a build tag. The
// fields are int rather than uint32 because os.Lchown takes int, and converting once here is better
// than converting at the call site inside a loop.
type ownership struct {
	uid, gid int
}

// AdoptStateDir gives the state directory's contents to whoever owns the directory.
//
// It exists because enrolment and the agent are two different users. `hostseal enroll` is run with sudo,
// as the documentation and the interface both instruct, and everything it writes — the credential, the
// CA bundle, the cached online key, agent.json at 0600 — therefore lands owned by root. The service
// runs as the unprivileged account the package created, with User=hostseal and no capabilities, so it
// opens agent.json, gets EACCES, and reports "not enrolled" on a host that enrolled successfully
// seconds earlier.
//
// That failure is the worst shape this project has: everything looks right. The control plane shows the
// host, because the enrolment request did succeed and the row exists. The unit is active, because an
// unenrolled agent idles rather than exiting. Only the absence of facts says anything is wrong, and it
// says it in the place an operator is least likely to read it as a permissions problem on their own
// machine.
//
// The directory's own owner is the target rather than a compiled-in "hostseal", because that is what the
// package established with `install -d -o hostseal -g hostseal` and it stays right for an installation
// that runs the agent as something else. Where the owner already matches — an unpackaged install where
// both are root, or a test in a temporary directory — every chown is a no-op, so this costs nothing and
// needs no guard for the ordinary case.
//
// Errors are returned rather than logged. A credential the service cannot read is not a partial success
// worth continuing past: enrolment consumed a single-use token, and the operator has to know now, while
// they are still at the terminal, rather than by reading journal lines an hour later.
func AdoptStateDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("agent: reading the state directory %s: %w", dir, err)
	}
	owner, ok := directoryOwner(info)
	if !ok {
		// Not Linux, which the agent is not built for. Nothing to do rather than a failure, because a
		// state directory with no uid behind it is not a state directory anybody can be locked out of.
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("agent: reading the state directory %s: %w", dir, err)
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		// Lchown rather than Chown: a symlink in here should have its own ownership changed, never the
		// thing it points at, which is how a writable state directory would otherwise become a way to
		// chown a file elsewhere on the system.
		if err := os.Lchown(path, owner.uid, owner.gid); err != nil {
			return fmt.Errorf("agent: giving %s to uid %d: %w", path, owner.uid, err)
		}
	}
	return nil
}
