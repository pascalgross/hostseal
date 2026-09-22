package signing

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/pascalgross/hostseal/internal/canonical"
)

// TrustedSignersPath is where the trust anchor lives on a managed host.
//
// It is a constant, and the file is root-owned, config|noreplace, and empty by default. The default
// emptiness is the important part: a freshly installed agent executes nothing destructive until an
// administrator deliberately places a key here.
//
// The keys are not shipped in the package on purpose. If they were, the trust chain would run
// APT signing key -> package -> job signing key, quietly promoting whoever controls APT signing to
// ultimate authority over every host — and in a hosted deployment it would hand the provider a route
// around the customer's own control plane.
const TrustedSignersPath = "/etc/hostseal/trusted-signers"

// SignerSet is a parsed trusted-signers file.
//
// It is immutable once parsed and carries no method that adds a key, because there is no code path by
// which HostSeal should ever add one: the file is edited by an administrator and read by the agent, and
// anything else is the control plane reaching into the trust anchor.
type SignerSet struct {
	// keys are the parsed entries, in file order.
	keys []PublicKey

	// source records where the set came from, for error messages and the audit log.
	source string
}

// ErrNoTrustedSigners reports that the file exists but lists no keys.
//
// It is distinguished from a read error because it is the normal state of a fresh install rather than a
// fault, and the two want opposite responses: a fresh install should log calmly and refuse destructive
// work, while an unreadable file should log loudly and refuse destructive work.
var ErrNoTrustedSigners = errors.New("signing: no trusted signers configured")

// LoadTrustedSigners reads and parses the host's trust anchor.
//
// A missing file is treated exactly like an empty one, because the two mean the same thing to the agent
// and distinguishing them would only create a case where a host that had lost its anchor behaved
// differently from one that never had it.
func LoadTrustedSigners() (*SignerSet, error) { return LoadSignersFrom(TrustedSignersPath) }

// LoadSignersFrom reads and parses a trusted-signers file at an explicit path.
//
// It exists so that tests, `hostseal enroll --signers` and the control plane's own copy all go through
// the same parser as the agent, rather than through a second implementation that agrees today.
func LoadSignersFrom(path string) (*SignerSet, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return &SignerSet{source: path + " (absent)"}, nil
	}
	if err != nil {
		return &SignerSet{source: path}, fmt.Errorf("signing: opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return ParseSigners(f, path)
}

// ParseSigners parses a trusted-signers stream.
//
// The format is deliberately close to authorized_keys, because that is the file every administrator
// already knows how to edit safely:
//
//	<algorithm>  <base64 public key>  <key-id>  [backend]
//
// Blank lines and lines beginning with # are ignored. A malformed line is an error rather than a
// skipped line: silently ignoring a key an administrator believed they had installed would mean a host
// that refuses every job for a reason nobody can see, and the failure would be discovered during the
// incident the job was meant to fix.
func ParseSigners(r io.Reader, source string) (*SignerSet, error) {
	set := &SignerSet{source: source}
	seen := map[string]int{}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 3 {
			return nil, fmt.Errorf("signing: %s:%d: expected \"<algorithm> <base64 key> <key-id>\", "+
				"got %d field(s)", source, line, len(fields))
		}
		if len(fields) > 4 {
			return nil, fmt.Errorf("signing: %s:%d: too many fields; a key-id may not contain spaces",
				source, line)
		}

		alg := Algorithm(fields[0])
		key, err := ParsePublicKey(alg, fields[1])
		if err != nil {
			return nil, fmt.Errorf("signing: %s:%d: %w", source, line, err)
		}

		entry := PublicKey{Algorithm: alg, KeyID: fields[2], Key: key, Encoded: fields[1]}
		if len(fields) == 4 {
			entry.Backend = fields[3]
		}

		if first, dup := seen[entry.KeyID]; dup {
			return nil, fmt.Errorf("signing: %s:%d: key-id %q is already used on line %d; "+
				"the audit log identifies signers by this field, so it must be unique",
				source, line, entry.KeyID, first)
		}
		seen[entry.KeyID] = line
		set.keys = append(set.keys, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("signing: reading %s: %w", source, err)
	}
	return set, nil
}

// Empty reports whether the set contains no keys.
//
// The agent checks this before doing anything destructive. Without keys present it refuses rather
// than falling back to trusting the server, which is the whole reason the anchor is established from
// a local file the administrator chose.
func (s *SignerSet) Empty() bool { return s == nil || len(s.keys) == 0 }

// Len returns the number of trusted keys.
func (s *SignerSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.keys)
}

// Source describes where the set was loaded from, for logs and the audit trail.
func (s *SignerSet) Source() string {
	if s == nil {
		return "none"
	}
	return s.source
}

// Keys returns the trusted keys in file order.
//
// It returns a copy so that a caller displaying the set in the UI cannot reorder or mutate the anchor
// by accident. The set is small enough that the copy costs nothing worth thinking about.
func (s *SignerSet) Keys() []PublicKey {
	if s == nil {
		return nil
	}
	out := make([]PublicKey, len(s.keys))
	copy(out, s.keys)
	return out
}

// Verify finds the trusted key that produced a signature over the canonical payload.
//
// Every key is tried, and a failure returns one error naming none of them. Telling a caller which key
// nearly matched is information they cannot act on and an attacker can.
//
// An empty set always fails. That is the behaviour a fresh install depends on: no key, no destructive
// work, no exceptions, and no fallback to trusting whoever sent the job.
func (s *SignerSet) Verify(payload, sig []byte) (PublicKey, error) {
	if s.Empty() {
		return PublicKey{}, fmt.Errorf("%w (%s)", ErrNoTrustedSigners, s.Source())
	}
	for _, k := range s.keys {
		if k.Verify(payload, sig) {
			return k, nil
		}
	}
	return PublicKey{}, fmt.Errorf("%w (%d key(s) from %s)", ErrNoTrustedSigner, len(s.keys), s.Source())
}

// Digest returns a stable digest of the trusted key set.
//
// The agent reports it in every heartbeat so that the control plane and the operator can see, without
// any host sending its trust anchor anywhere, that two machines which should have the same signers do.
// A fleet where one host quietly has an extra key is exactly the thing this makes visible.
//
// Key ids and encodings are both included, and the input is sorted so the digest does not depend on the
// order somebody happened to write the lines in.
func (s *SignerSet) Digest() (string, error) {
	entries := make([]string, 0, s.Len())
	for _, k := range s.Keys() {
		entries = append(entries, string(k.Algorithm)+" "+k.Encoded+" "+k.KeyID)
	}
	sort.Strings(entries)
	return canonical.Digest(entries)
}
