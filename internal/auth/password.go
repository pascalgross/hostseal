package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// MinPasswordLength is the shortest password this control plane will store.
//
// Twelve rather than eight. The usual argument for a low floor is that complexity rules produce worse
// passwords than length does, which is true and is why there are no complexity rules here — but it is
// an argument for asking for length, not for accepting less of it. This is a credential to a fleet
// management console, chosen once by a small number of people, and the cost of the higher floor is one
// sentence in an error message.
const MinPasswordLength = 12

// MaxConcurrentDerivations bounds how many Argon2id derivations may be resident at once.
//
// Four, which at argonMemory is 256 MiB — an amount a control plane can hold without being pushed into
// swap or reaped by the kernel, and enough that four people signing in at the same instant do not wait
// on each other. Everything past it waits rather than being refused: parking a goroutine costs about
// four kilobytes and running the derivation costs sixty-four megabytes, so waiting is strictly the
// cheaper failure, and the caller in front of it is already rate limited.
//
// It exists because the alternative is a memory bound that depends on how many requests happen to
// arrive together. That is not a bound, and the route it protects is reachable by an operator with the
// least privilege the system has: changing your own password verifies the current one, and nothing
// about being signed in stops you doing it in a loop.
const MaxConcurrentDerivations = 4

// derivations admits MaxConcurrentDerivations callers to the memory-hard function at a time.
//
// A buffered channel rather than a semaphore type, because it is four lines and this package has no
// other use for the dependency. Acquire and release are always paired by a defer at the two call sites
// below; there is deliberately no third.
var derivations = make(chan struct{}, MaxConcurrentDerivations)

// deriveKey runs Argon2id with this build's parameters, under the concurrency bound.
//
// Every derivation in this package goes through it, which is the point: a second call to argon2.IDKey
// that took the parameters but not the bound would restore exactly the property the bound removes, and
// would look correct.
func deriveKey(password string, salt []byte, time32, memory uint32, threads uint8, length uint32) []byte {
	derivations <- struct{}{}
	defer func() { <-derivations }()
	return argon2.IDKey([]byte(password), salt, time32, memory, threads, length)
}

// MaxPasswordLength bounds what is accepted, so a long input cannot become a long computation.
//
// Argon2's cost comes from its parameters rather than from the password's length, so this is not a
// defence against a slow hash; it exists because every other input this server reads is bounded before
// it is in memory and a password should not be the exception. It is generous: a six-word passphrase is
// nowhere near it.
//
// Bytes, deliberately, where the minimum below counts characters. The two units are not an
// inconsistency — they measure different things. This one bounds what is copied and hashed, which is
// bytes; the minimum measures what a person chose, which is characters. A password of 256 four-byte
// characters is a megabyte-adjacent input by no useful definition and 64 characters by every one, so
// the ceiling in bytes is the honest bound for what it is protecting.
const MaxPasswordLength = 256

// The Argon2id cost parameters, which are RFC 9106's SECOND RECOMMENDED option.
//
// Named constants rather than configuration: there is one right answer for a given year and a knob
// would only create installations with the wrong one. They are
// written into every hash this build produces (see HashPassword's encoding), so raising them later
// applies to new and changed passwords without invalidating anybody's existing one — which is the
// property that makes it possible to raise them at all.
//
// The memory figure is the one to watch when changing them: it is allocated per hash in flight, so it
// multiplies by however many derivations are running at once. What bounds that product is
// MaxConcurrentDerivations below, and the two numbers should be changed together — a rate limit does
// not bound it, which is what this comment used to claim. A token bucket meters attempts over time and
// says nothing about how many are resident simultaneously: ten requests arriving in the same
// millisecond all pass a burst of ten.
const (
	// argonTime is the number of passes over memory.
	argonTime = 3

	// argonMemory is the memory cost in KiB — 64 MiB.
	argonMemory = 64 * 1024

	// argonThreads is the number of lanes.
	argonThreads = 4

	// argonSaltLength is how much salt each hash carries, in bytes.
	argonSaltLength = 16

	// argonKeyLength is the length of the derived key, in bytes.
	argonKeyLength = 32
)

// Ceilings on the parameters read back out of a stored hash.
//
// The parameters travel with the hash so they can be raised, which means they arrive from the database
// rather than from this file — and a row with m=16777216 would ask this process to allocate sixteen
// gigabytes at a sign-in attempt. Encrypted-at-rest or not, a value that reaches a resource decision
// has to be bounded on the way in. These are far above anything this build writes and far below
// anything that would take the process down.
const (
	// maxArgonTime is the largest pass count a stored hash may ask for.
	maxArgonTime = 16

	// maxArgonMemory is the largest memory cost a stored hash may ask for, in KiB — 1 GiB.
	maxArgonMemory = 1024 * 1024

	// maxArgonThreads is the largest lane count a stored hash may ask for.
	maxArgonThreads = 16

	// maxArgonKeyLength is the longest derived key a stored hash may carry, in bytes.
	maxArgonKeyLength = 64
)

// ErrPasswordTooShort reports a password below MinPasswordLength.
//
// It is a sentinel because it is the one password failure a caller should report differently: telling
// somebody choosing a password that it is too short is help, where telling somebody signing in which
// half of their guess was wrong is reconnaissance. Verification never returns it.
var ErrPasswordTooShort = fmt.Errorf("auth: a password must be at least %d characters", MinPasswordLength)

// ErrPasswordTooLong reports a password above MaxPasswordLength.
var ErrPasswordTooLong = fmt.Errorf("auth: a password may be at most %d characters", MaxPasswordLength)

// errMalformedHash reports a stored password hash this build cannot read.
//
// Deliberately not exported and deliberately not distinguished from a wrong password by anything the
// caller can see: a row whose hash is unreadable is a row nobody can sign in as, and which of the two
// happened is not something an unauthenticated caller is entitled to learn.
var errMalformedHash = errors.New("auth: the stored password hash is not readable by this build")

// HashPassword returns the stored form of a password.
//
// Argon2id rather than SHA-256, which is what internal/server.HashToken uses for enrolment tokens and
// is correct there for a reason that does not hold here: a token is 256 bits of uniform randomness, so
// there is no dictionary to attack. A password is chosen by a person, so the whole defence is making
// each guess expensive, and a memory-hard function is what makes it expensive on the hardware an
// attacker would actually use.
//
// The encoding is the PHC string format — $argon2id$v=19$m=…,t=…,p=…$salt$hash, base64 without padding
// — because it carries the parameters and the salt with the digest. That is what lets the cost be
// raised later without a migration and without locking anybody out: a hash written under the old
// parameters keeps verifying under them.
func HashPassword(password string) (string, error) {
	// Characters, not bytes, because that is what ErrPasswordTooShort promises and what the interface
	// asks for. `len` on a string counts UTF-8 bytes: under it, three four-byte emoji are "twelve
	// characters" and satisfy the only length rule this control plane has. The ceiling stays in bytes —
	// see MaxPasswordLength for why the two units are different on purpose.
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return "", ErrPasswordTooShort
	}
	if len(password) > MaxPasswordLength {
		return "", ErrPasswordTooLong
	}

	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generating a password salt: %w", err)
	}
	key := deriveKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLength)
	return encodePHC(argonMemory, argonTime, argonThreads, salt, key), nil
}

// encodePHC renders one derivation as the string that is stored.
//
// Its own function because parsePasswordHash reads exactly this shape, and the two going out of step is
// the failure that would look like every password on the installation being wrong at once. Written
// here, next to its reader, rather than inline in HashPassword where a reviewer would have to hold both
// in mind at once.
func encodePHC(memory, time32 uint32, threads uint8, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time32, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// VerifyPassword reports whether a password matches a stored hash.
//
// It returns false rather than an error for every failure, including a hash this build cannot parse.
// The caller is a sign-in path, and the one thing it must not do is answer differently depending on
// which part of the credential was wrong — the same rule ErrUnauthenticated exists for one layer up.
//
// The comparison is constant time over two derived keys of the same length, which is the case that
// makes subtle.ConstantTimeCompare meaningful: it leaks length, and here the length is fixed by the
// stored parameters rather than by the secret.
func VerifyPassword(encoded, password string) bool {
	memory, time32, threads, salt, want, err := parsePasswordHash(encoded)
	if err != nil {
		return false
	}
	if len(password) > MaxPasswordLength {
		// Refused before the derivation rather than after it, so that a caller cannot ask this process
		// to hash a megabyte by putting one in a sign-in form.
		return false
	}
	// The conversion is bounded by parsePasswordHash, which refuses a key longer than
	// maxArgonKeyLength — 64 bytes. gosec cannot see that across the call, and a length check here
	// would be a second copy of a rule that is already enforced where the value comes from.
	//nolint:gosec // len(want) <= maxArgonKeyLength (64), enforced by parsePasswordHash.
	got := deriveKey(password, salt, time32, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NeedsRehash reports whether a stored hash was written with weaker parameters than this build uses.
//
// It exists so that raising the cost is something an installation grows into rather than something it
// has to be migrated through: the sign-in path knows the password at exactly the moment it can rewrite
// the hash, and that is the only moment it ever will.
func NeedsRehash(encoded string) bool {
	memory, time32, threads, _, want, err := parsePasswordHash(encoded)
	if err != nil {
		// Unreadable is not "weaker" — it is a hash nobody can sign in as, so rewriting it is not this
		// function's decision to invite.
		return false
	}
	return memory < argonMemory || time32 < argonTime || uint32(threads) < argonThreads ||
		len(want) < argonKeyLength
}

// parsePasswordHash splits a PHC string into the parameters and material it carries.
//
// Every bound is checked here rather than at the call sites, because the values come from a database
// row and reach a memory allocation: this is the one place that has to be suspicious of them, and two
// callers each remembering to be would eventually be one.
func parsePasswordHash(encoded string) (memory, time32 uint32, threads uint8, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	// A leading empty field, then: algorithm, version, parameters, salt, key.
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errMalformedHash
	}

	var version int
	if _, scanErr := fmt.Sscanf(parts[2], "v=%d", &version); scanErr != nil || version != argon2.Version {
		return 0, 0, 0, nil, nil, errMalformedHash
	}

	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return 0, 0, 0, nil, nil, errMalformedHash
	}
	memory, err = parseParam(params[0], "m=", maxArgonMemory)
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}
	time32, err = parseParam(params[1], "t=", maxArgonTime)
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}
	lanes, err := parseParam(params[2], "p=", maxArgonThreads)
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}
	// parseParam has already refused anything above maxArgonThreads, which is 16, so this narrowing
	// cannot lose a bit. It is a narrowing at all only because argon2.IDKey takes the lane count as a
	// uint8 while the other two costs are uint32.
	//nolint:gosec // lanes <= maxArgonThreads (16), enforced by parseParam on the line above.
	threads = uint8(lanes)

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > maxArgonKeyLength {
		return 0, 0, 0, nil, nil, errMalformedHash
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > maxArgonKeyLength {
		return 0, 0, 0, nil, nil, errMalformedHash
	}
	return memory, time32, threads, salt, key, nil
}

// parseParam reads one "name=number" field of a PHC parameter list, refusing a value above a ceiling.
//
// Zero is refused along with everything above the ceiling: argon2.IDKey panics on a zero lane count,
// and a stored row is not somewhere a panic should be reachable from.
func parseParam(field, prefix string, ceiling uint64) (uint32, error) {
	digits, found := strings.CutPrefix(field, prefix)
	if !found {
		return 0, errMalformedHash
	}
	value, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || value == 0 || value > ceiling {
		return 0, errMalformedHash
	}
	return uint32(value), nil
}
