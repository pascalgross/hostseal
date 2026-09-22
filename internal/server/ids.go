package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pascalgross/hostseal/internal/id"
)

// NewID returns a lexically sortable, random identifier.
//
// A thin re-export of internal/id, kept because every call site in this package says server.NewID and
// because the shape belongs to the whole product rather than to the control plane: `hostseal sign`
// generates job identifiers on an operator's laptop from the same function.
func NewID() (string, error) { return id.New() }

// NewEnrollmentToken returns a bootstrap token and the hash to store.
//
// Only the hash is ever persisted, so a database dump does not let its holder enrol hosts. The token is
// shown to the operator once, at creation, and is not recoverable afterwards — which is worth saying in
// the UI, because the alternative is somebody storing it somewhere convenient in case they need it
// again.
func NewEnrollmentToken() (token, hash string, err error) {
	raw := make([]byte, enrollmentTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("server: generating an enrolment token: %w", err)
	}
	token = enrollmentTokenPrefix + strings.ToLower(id.Encoding.EncodeToString(raw))
	return token, HashToken(token), nil
}

// enrollmentTokenBytes is how much randomness a token carries.
//
// 256 bits, which is what makes the unsalted, unstretched hash in HashToken the right choice rather
// than a shortcut.
const enrollmentTokenBytes = 32

// enrollmentTokenPrefix marks a HostSeal enrolment token in a log or a paste.
//
// Secret scanners key on prefixes, and a token that looks like any other opaque string is one nobody's
// tooling can recognise when it turns up somewhere it should not be.
const enrollmentTokenPrefix = "hsl_"

// HashToken returns the stored form of a bootstrap token.
//
// SHA-256 with no salt and no stretching is correct here and would not be for a password: the token is
// 256 bits of uniform randomness, so there is no dictionary to attack and a work factor would only slow
// down the enrolment path.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}
