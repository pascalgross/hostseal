// Package autostart registers `hostseal signer` to start when its operator logs in.
//
// It exists because the signer is a foreground program somebody has to remember to start, and the one
// moment they remember is the moment the web interface has already told them no signer answered. That
// is a small annoyance with a bad failure mode: the fix an operator reaches for, when a tool is
// tedious to start, is to leave it running for ever on a machine that also reads mail.
//
// What is registered is a **logon entry in the operator's own interactive session**, and the shape is
// the whole argument of this package.
//
// It is not a service, and adding one would not be an improvement to argue about later. The
// confirmation at the signer's terminal is the control that authorises a signature — docs/SECURITY.md
// §2.3 — and it is read from standard input, where end of input is a no. A Windows service runs in
// session 0 with no console attached, so a signer installed as one would decline every request it ever
// received; the only way to make it useful again is a flag that signs without asking, which is the
// signing oracle the design refuses. A logon entry runs the same program in the same session as the
// person, with the same prompt on the same screen.
//
// It is not a scheduled task either, for a duller reason: registering one means either schtasks.exe or
// the Task Scheduler COM API. The first is a process start, and in this repository those go through
// internal/run's allowlist, which is the list that bounds a compromised agent — widening it so that an
// operator's convenience can reach a new program is the wrong direction for that list to grow. The
// second is COM in a binary that has none.
//
// Nothing here weakens the idle exit. What is registered is the same command line with the same
// --idle, so an auto-started signer still shuts down when the task is over, and the exposure
// docs/SECURITY.md §9 names stays the length of a working session rather than the length of an uptime.
package autostart

import (
	"errors"
	"strings"
)

// ErrUnsupported reports that this platform has no logon entry to register.
//
// A named error rather than a silent success, because "installed" and "did nothing" have to be
// distinguishable by the command that prints a result to a person.
var ErrUnsupported = errors.New("autostart: no logon entry on this platform")

// Entry is a registration, as something to show an operator.
//
// Both fields are for printing rather than for parsing. Where it is registered is what somebody needs
// in order to check or remove it without this tool, and the command line is what will actually run —
// which is the part worth reading before trusting it to run unattended at every logon.
type Entry struct {
	// Where names the place holding the registration, in whatever terms that platform uses.
	Where string

	// Command is the command line exactly as it will be executed.
	Command string
}

// CommandLine renders a program and its arguments the way Windows will parse them back.
//
// It lives in the portable file, with portable tests, for the reason internal/signing/backend/pkcs11's
// ABI tables do: it is a rule about a platform this project cannot run its tests on, so the next best
// thing is a rule that is exercised on the platform it can. Getting it wrong is not a crash — it is a
// signer that starts at logon with a PKCS#11 module path cut in half at the first space, reports that
// it cannot open the token, and looks like a broken YubiKey.
func CommandLine(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, escapeArg(exe))
	for _, arg := range args {
		parts = append(parts, escapeArg(arg))
	}
	return strings.Join(parts, " ")
}

// escapeArg quotes one argument for CommandLineToArgvW.
//
// The rules are the documented ones and not a simplification of them: a run of backslashes is literal
// unless a quote follows it, in which case the run is doubled and the quote escaped. A PKCS#11
// reference is exactly the string that finds the difference — it carries spaces, a Windows path full of
// backslashes, and ends in one often enough that the trailing case is not theoretical.
func escapeArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if !strings.ContainsAny(arg, " \t\"") {
		return arg
	}

	var b strings.Builder
	b.WriteByte('"')
	backslashes := 0
	for i := 0; i < len(arg); i++ {
		switch c := arg[i]; c {
		case '\\':
			backslashes++
			b.WriteByte(c)
		case '"':
			// The run that precedes a quote is doubled, so that the quote arrives as data rather
			// than as the end of the argument.
			b.WriteString(strings.Repeat(`\`, backslashes))
			backslashes = 0
			b.WriteString(`\"`)
		default:
			backslashes = 0
			b.WriteByte(c)
		}
	}
	// And the run that precedes the closing quote, for the same reason.
	b.WriteString(strings.Repeat(`\`, backslashes))
	b.WriteByte('"')
	return b.String()
}
