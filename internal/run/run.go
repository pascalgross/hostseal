// Package run is the only place in HostSeal that starts an external process.
//
// It exists so that "no code path leads from a network message to a shell" is enforced at run time and
// not only asserted by a source-level test. Every external program HostSeal may execute is a member of a
// closed allowlist in this file, given as an absolute path; Command refuses anything else before
// reaching exec, so a future caller cannot introduce a new program without editing this list and having
// a reviewer see it in the diff.
//
// The static check in internal/intent's guarantee suite still applies everywhere else: outside this
// package, the program argument of any exec call must be a compile-time constant absolute path that is
// not an interpreter. This package is the single exemption, and it earns it by replacing a compile-time
// property with a stronger run-time one.
//
// Three other things happen here once, rather than being remembered at each call site: the environment
// is replaced rather than inherited, so nothing the caller controls — PATH, LD_PRELOAD,
// DEBIAN_FRONTEND — can change what the program does; every invocation has a deadline, because an apt
// operation that blocks on a conffile prompt would otherwise hang the agent forever; and output is
// bounded, because a program that prints without limit must not be able to exhaust a managed host's
// memory.
package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Program is one of the fixed set of external programs HostSeal may execute.
//
// It is a distinct type so that a string arriving from anywhere else cannot be passed where a program
// is expected. Combined with the allowlist below, that means the set of processes this software can
// start is visible in one screen of code.
type Program string

// The complete set of programs HostSeal may execute.
//
// Each is an absolute path: resolving a program through PATH would let whoever controls the environment
// choose it, which is the same weakness as accepting the name over the network with extra steps. None
// is an interpreter, and the guarantee suite asserts that.
const (
	// AptGet reads package state and applies updates.
	//
	// It is apt-get and never apt. apt 3.0, which shipped in Ubuntu 25.04, reorganised apt's output
	// into colourised columns, and 26.04 ships apt 3.1; apt-get keeps the machine-oriented format that
	// has been stable for two decades. A refactor to the "nicer" command breaks update detection on the
	// newest release while still passing on the oldest, which is the worst possible way to find out.
	AptGet Program = "/usr/bin/apt-get"

	// UnattendedUpgrade applies updates with the distribution's own origin filtering.
	//
	// HostSeal wraps it rather than reimplementing origin filtering, because unattended-upgrades already
	// gets that right on both distribution families and a second implementation would be wrong on
	// exactly the release nobody tested.
	UnattendedUpgrade Program = "/usr/bin/unattended-upgrade"

	// Needrestart answers which running services still hold replaced libraries.
	//
	// That question is more actionable than reboot-required and is the one most update dashboards
	// skip. On Debian it is also the reliable source for whether a reboot is needed at all, since
	// /var/run/reboot-required is an Ubuntu update-notifier convention rather than a standard.
	Needrestart Program = "/usr/sbin/needrestart"

	// Pro reports Ubuntu Pro and Livepatch subscription state. It does not exist on Debian.
	Pro Program = "/usr/bin/pro"

	// Shutdown reboots the host. Reached only from the reboot-host root helper, after policy.
	Shutdown Program = "/usr/sbin/shutdown"

	// UpdateScan reports the updates pending on a Windows host. It does not exist on Linux.
	//
	// It is HostSeal's own binary, shipped in the same package as the agent, and it is here for the same
	// reason apt-get is: the agent asks a program the question rather than reading the platform's update
	// state itself. On Windows that separation carries more weight than convenience. Enumerating updates
	// means loading wuapi.dll, and docs/SECURITY.md §3 refuses a runtime code loader in the agent — the
	// process holding the host's mTLS private key — without qualification. Starting a short-lived
	// unprivileged process that loads it instead is what keeps that refusal literally true.
	//
	// The path is under Program Files rather than beside the state directory because it must be a
	// location the agent's own service account cannot write. An agent that could rewrite the program it
	// then executes would have turned this allowlist into a formality.
	UpdateScan Program = `C:\Program Files\HostSeal\hostseal-update-scan.exe`
)

// allowed is the run-time allowlist.
//
// It is checked on every call, so adding a program means editing this map. A caller that assembles a
// path from anywhere else — configuration, a job parameter, a response — fails here rather than
// executing.
//
// It holds only programs shipped code actually calls, and TestGuaranteeEveryAllowlistedProgramHasACaller
// keeps it that way. /usr/bin/systemctl was here for a while with no caller at all — unit state is read
// over D-Bus and so are start, stop and restart — and an entry like that is not inert: it is a
// flag-rich program made runnable in advance, so that the day somebody adds the first call site, the
// review that should have decided whether it may run at all has already silently happened.
var allowed = map[Program]bool{
	AptGet:            true,
	UnattendedUpgrade: true,
	Needrestart:       true,
	Pro:               true,
	Shutdown:          true,
	UpdateScan:        true,
}

// ErrNotAllowed reports an attempt to execute a program outside the allowlist.
var ErrNotAllowed = errors.New("run: program is not in the allowlist")

// WaitDelay bounds how long Wait lingers after the program itself has gone.
//
// It exists because of one specific shape, and that shape is the whole reason updates are the slowest
// thing this package runs: apt-get spawns dpkg, and dpkg inherits the pipes this package reads the
// output from. When a deadline fires, exec.CommandContext signals the *direct* child only. Without a
// wait delay, Wait then blocks on a pipe the surviving dpkg still holds — for as long as the
// transaction takes — so the helper hangs well past its own timeout and the agent is left waiting on a
// helper that has, as far as it knows, simply stopped answering.
//
// The surviving dpkg is deliberately left alone. Killing the process group would return the pipes
// sooner and leave the package system half-configured on somebody's server, which is a much worse
// outcome than an orphan that finishes its transaction, releases /var/lib/dpkg/lock and exits. The job
// is reported as timed out either way; this only decides whether the host is also broken.
const WaitDelay = 10 * time.Second

// DefaultTimeout bounds an invocation that does not ask for its own.
//
// Two minutes is generous for everything except applying updates, which passes its own. The point is
// that no invocation is unbounded: an apt operation blocked on a conffile prompt waits for input that
// will never come, and an agent that waited with it would stop reporting on the host.
const DefaultTimeout = 2 * time.Minute

// MaxOutputBytes bounds what is captured from a program's stdout and stderr, each.
//
// A program that prints without limit must not be able to exhaust a managed host's memory. Job output
// is separately truncated to its last 64 KiB before being reported; this is the earlier, cruder bound
// that keeps the agent itself alive.
const MaxOutputBytes = 8 << 20

// Result is the outcome of one invocation.
type Result struct {
	// Stdout is the captured standard output, bounded by MaxOutputBytes.
	Stdout []byte

	// Stderr is the captured standard error, bounded by MaxOutputBytes.
	Stderr []byte

	// ExitCode is the process exit status, or -1 if it did not run or was killed by a signal.
	ExitCode int

	// Duration is how long the process ran.
	Duration time.Duration
}

// Options adjust one invocation.
//
// The zero value is the safe default: a clean environment, the default timeout, and no input. Anything
// a caller adds is visible at the call site rather than buried in a constructor.
type Options struct {
	// Timeout overrides DefaultTimeout.
	Timeout time.Duration

	// Env replaces the process environment entirely. It is never merged with the agent's own.
	//
	// Callers that need DEBIAN_FRONTEND=noninteractive pass it here. Note that it alone is not enough
	// for a full upgrade: without -o Dpkg::Options::=--force-confdef and --force-confold, a changed
	// conffile stops the run dead waiting for input that never arrives.
	Env []string

	// Dir is the working directory. Empty means the root directory, not the caller's.
	Dir string
}

// Command runs an allowlisted program with a fixed argument slice and returns its output.
//
// The arguments are passed as a slice to execve. Nothing is concatenated, nothing is quoted, and no
// shell is involved at any point — which is why a unit name that reached here would be an argument
// rather than a command, even before the catalogue's validator refused it.
func Command(ctx context.Context, p Program, args ...string) (*Result, error) {
	return CommandWith(ctx, Options{}, p, args...)
}

// CommandWith runs an allowlisted program with explicit options.
func CommandWith(ctx context.Context, opts Options, p Program, args ...string) (*Result, error) {
	if !allowed[p] {
		return nil, fmt.Errorf("%w: %q", ErrNotAllowed, p)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The program is the allowlisted constant, never a value derived from the arguments. The static
	// check in the guarantee suite exempts this one call site precisely because the allowlist above
	// makes the run-time property stronger than the compile-time one it replaces.
	//nolint:gosec // G204 flags a subprocess whose program is a variable. That is exactly what this
	// package is: the single audited chokepoint. The program has already been checked against the
	// closed allowlist above, and TestGuaranteeOnlyAllowlistedProgramsCanRun proves the check holds.
	// Suppressing it here rather than repo-wide is deliberate: everywhere else, G204 should still fire.
	cmd := exec.CommandContext(ctx, string(p), args...)

	// A replaced environment rather than an inherited one. PATH is set because a few Debian tools
	// shell out internally and an empty PATH breaks them; it names only system directories.
	cmd.Env = opts.Env
	if cmd.Env == nil {
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C.UTF-8"}
	}
	cmd.Dir = opts.Dir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{buf: &stdout, limit: MaxOutputBytes}
	cmd.Stderr = &limitedWriter{buf: &stderr, limit: MaxOutputBytes}

	// See WaitDelay. Without this, a timed-out apt run leaves this call blocked on a pipe held by a
	// dpkg that outlived its parent, and the timeout above stops meaning anything at all.
	cmd.WaitDelay = WaitDelay

	started := time.Now()
	err := cmd.Run()
	res := &Result{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: cmd.ProcessState.ExitCode(),
		Duration: time.Since(started),
	}
	if err != nil {
		if ctx.Err() != nil {
			return res, fmt.Errorf("run: %s timed out after %s: %w", p, timeout, ctx.Err())
		}
		return res, fmt.Errorf("run: %s: %w", p, err)
	}
	return res, nil
}

// Allowlist returns the programs HostSeal may execute, for tests and for `hostseal-agent doctor`.
//
// It exists so the set can be asserted and displayed rather than only read. An operator auditing what
// HostSeal can start on their host should be able to ask the binary.
func Allowlist() []Program {
	out := make([]Program, 0, len(allowed))
	for p := range allowed {
		out = append(out, p)
	}
	return out
}

// limitedWriter discards everything past a byte limit.
//
// It reports success on the discarded writes rather than an error, because a program that prints too
// much has not failed and killing it would turn a verbose upgrade into a failed one.
type limitedWriter struct {
	// buf receives the bytes that fit.
	buf *bytes.Buffer

	// limit is the maximum number of bytes to retain.
	limit int
}

// Write appends up to the remaining limit and reports the full length as written.
func (w *limitedWriter) Write(p []byte) (int, error) {
	if remaining := w.limit - w.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			w.buf.Write(p[:remaining])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}
