package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pascalgross/hostseal/internal/autostart"
	"github.com/pascalgross/hostseal/internal/localsign"
	"github.com/pascalgross/hostseal/internal/prompt"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/signing"
)

// originList collects a repeatable --origin flag.
//
// Repeatable rather than comma-separated because an origin is a URL and a list of URLs separated by
// commas is a thing somebody eventually writes with a space in it. Its own type because flag has no
// list kind, and this is the shape the standard library documents for one.
type originList []string

// String renders the flag's current value, for the default in the help text.
func (o *originList) String() string { return strings.Join(*o, ", ") }

// Set appends one occurrence of the flag.
func (o *originList) Set(value string) error {
	*o = append(*o, value)
	return nil
}

// signerFlags are the pointers `hostseal signer` reads its options through.
//
// A struct rather than six returned values, because the set has to be built in one place and read in
// two: the command runs from it, and --install writes it back out as the command line for the next
// logon.
type signerFlags struct {
	// key is the signing key reference, a file path or a backend URI.
	key *string

	// addr is the loopback address to listen on.
	addr *string

	// idle is how long the signer waits for work before shutting down.
	idle *time.Duration

	// origins are the web interfaces allowed to ask this signer for a signature.
	origins *originList

	// install registers the command at logon instead of running it.
	install *bool

	// uninstall removes that registration instead of running anything.
	uninstall *bool
}

// newSignerFlags defines the options of `hostseal signer`.
//
// It exists because --install has to reproduce this command line rather than approximate it. Two
// definitions of these flags — one to parse them and one to write them back out — is precisely the
// drift that produces a logon entry which runs something slightly different from what the operator
// tested, months later, with nothing to point at. One definition means a test can parse what
// signerArgs produced and compare, which is a compiler-checkable version of that promise.
func newSignerFlags() (*flag.FlagSet, signerFlags) {
	fs := flag.NewFlagSet("signer", flag.ExitOnError)
	var origins originList
	flags := signerFlags{
		key: fs.String("key", "",
			"the signing key: a path from `hostseal key generate`, or a backend reference such as\n"+
				"pkcs11:token=ops;object=ops-yubikey-1?module-path=<your PKCS#11 module>"),
		addr: fs.String("addr", localsign.DefaultAddr,
			"loopback address to listen on; a non-loopback address is refused"),
		idle: fs.Duration("idle", localsign.DefaultIdleTimeout,
			"exit after this long with no request, so a logged-in token session does not sit open"),
		origins: &origins,
		install: fs.Bool("install", false,
			"register this command to start at logon, in this account's own session, and exit\n"+
				"without signing anything or opening the token"),
		uninstall: fs.Bool("uninstall", false,
			"remove that registration and exit; safe to run whether or not there is one"),
	}
	fs.Var(&origins, "origin",
		"a HostSeal web interface allowed to ask for signatures, for example\n"+
			"https://hostseal.example.org; repeat for more than one")
	return fs, flags
}

// signerCommand implements `hostseal signer`.
//
// It is `hostseal sign` and `hostseal sign-template` with the copying taken out, and it is
// deliberately not more than that. An operator on a Windows workstation with a YubiKey can sign a
// bootstrap template — or a reboot — from the web interface: the browser says what it wants signed, a
// human here reads what that means and answers a prompt, the token is touched, and a detached
// signature goes back. The key never leaves the token, and the control plane still holds nothing it
// could mint a signature with.
//
// Three things about the shape are worth stating where somebody would change them.
//
// The key reference is a flag on this command line and never something the browser sends. A `--key`
// chosen by a web page would be a web page choosing which shared library this process loads, which is
// a remote code execution with extra steps.
//
// The signed payload is built by internal/localsign out of the name and the body, never received. A
// service that signed a digest supplied by a page would let a compromised control plane show one
// template in the browser and have another signed — the exact property `hostseal sign` exists to
// refuse.
//
// And the confirmation is here, on the machine holding the token, showing the body in full. The
// browser's rendering is not what is authorised; this one is. An operator who is shown something here
// that they did not ask for in the browser has just caught a compromised control plane, and says no.
//
// --install and --uninstall register and remove a logon entry that runs this same command in the
// operator's own session — internal/autostart says why it is a logon entry and not a service, and why
// that is a refusal rather than a feature nobody has got round to. Neither flag opens the token: what
// they write and remove is a command line.
func signerCommand(argv []string) int {
	fs, flags := newSignerFlags()
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	keyPath, addr, idle := flags.key, flags.addr, flags.idle
	origins := *flags.origins
	install, uninstall := flags.install, flags.uninstall

	if *install && *uninstall {
		fmt.Fprintln(os.Stderr, "hostseal: --install and --uninstall ask for opposite things")
		return 2
	}
	// Before the flags below are required, because removing a registration needs none of them: an
	// operator clearing a workstation should not have to reconstruct the key reference they are
	// getting rid of.
	if *uninstall {
		return uninstallAutostart()
	}
	if *keyPath == "" || len(origins) == 0 {
		fmt.Fprintln(os.Stderr, "hostseal: --key and at least one --origin are required")
		fmt.Fprintln(os.Stderr,
			"\n  hostseal signer --key <reference> --origin https://hostseal.example.org\n\n"+
				"The origin is the address you open the HostSeal web interface at. Without it any\n"+
				"page in your browser could ask this service for a signature.")
		return 2
	}

	// Checked before the token is opened, so that a mistyped origin costs an error message rather
	// than a PIN entry and a puzzled look at a browser that cannot reach the signer.
	if err := localsign.ValidateAddr(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 2
	}

	// After the flags have been checked and before the token is opened. What is registered is a
	// command line, so the value of checking it is at this end — and asking for a PIN in order to
	// write a registry value would teach an operator that --install and signing are the same act.
	if *install {
		return installAutostart(*keyPath, *addr, *idle, origins)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Opened here, before anything is listening: a token that is not plugged in, a wrong PIN or a
	// module path that does not exist are all things to learn at this terminal, from the command just
	// typed, rather than through a browser reporting that signing failed.
	signer, err := openWithTimeout(ctx, *keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}
	defer func() { _ = signer.Close() }()

	service, err := localsign.New(localsign.Options{
		Signer:  signer,
		Origins: origins,
		Confirm: func(req localsign.Request) (bool, error) {
			return confirmBrowserTemplate(req, signer)
		},
		ConfirmJob: func(req localsign.JobConfirmation) (bool, error) {
			return confirmBrowserJob(req, signer)
		},
		Log: os.Stderr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 2
	}

	fmt.Fprint(os.Stderr, describeSigner(signer, *addr, origins, *idle))

	switch err := service.Serve(ctx, *addr, *idle); {
	case err == nil, errors.Is(err, context.Canceled):
		fmt.Fprintln(os.Stderr, "\nhostseal: signer stopped.")
		return 0
	case errors.Is(err, localsign.ErrIdle):
		fmt.Fprintf(os.Stderr, "\nhostseal: nothing asked for a signature in %s, so the signer has "+
			"stopped and the token session is closed. Start it again when you need it.\n", *idle)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}
}

// describeSigner renders the banner the operator reads once, when the signer starts.
//
// It carries the trusted-signers line because that is the half of this arrangement the tooling cannot
// do for anybody: a template signed by a key no host trusts is refused at every enrolment, and the
// remedy is this line, pasted by an administrator onto the hosts that key may act on. It has to be a
// deliberate edit — see `hostseal key generate`, which says the same thing for the same reason.
//
// It returns the text rather than printing it so that a test can assert what an operator is told,
// which is the same reason describeJob and describeTemplate do.
func describeSigner(signer signing.Signer, addr string, origins []string, idle time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  Signing key  %s (%s, %s)\n", signer.KeyID(), signer.Backend(), signer.Algorithm())
	fmt.Fprintf(&b, "  Listening    http://%s — loopback only, nothing else can reach it\n", addr)
	fmt.Fprintf(&b, "  Signing for  %s\n", strings.Join(origins, ", "))
	fmt.Fprintf(&b, "  Idle exit    after %s with no request\n", idle)

	if line, err := signing.TrustedSignerLine(signer); err == nil {
		fmt.Fprintf(&b, "\n  A host applies a template signed by this key only if this line is in its\n"+
			"  own %s:\n\n    %s\n", signing.TrustedSignersPath, line)
	}

	fmt.Fprintf(&b, "\n  Every signature is confirmed here — a template shown in full, a job decoded\n"+
		"  against this build's own catalogue. The browser never sees the key, and this machine\n"+
		"  never sends it anywhere. Ctrl-C to stop.\n\n")
	return b.String()
}

// confirmBrowserJob shows what a browser has asked to have signed, and asks.
//
// It reuses describeJob, which is what `hostseal sign` prints: the operation decoded against this
// binary's own catalogue, the host it is bound to, the window, and the payload verbatim. That reuse is
// the point rather than a convenience — the browser's rendering of a reboot is not what is being
// authorised, this is, and two renderings that could disagree would be two chances to authorise
// something nobody read.
func confirmBrowserJob(req localsign.JobConfirmation, signer signing.Signer) (bool, error) {
	fmt.Fprintf(os.Stderr, "\n  Asked for by %s\n", req.Origin)
	fmt.Fprint(os.Stderr, describeJob(req.Job, req.Spec, req.Params, req.HostID, signer, req.Payload))
	return prompt.Confirm("Sign this? [y/N] ")
}

// confirmBrowserTemplate shows what a browser has asked to have signed, and asks.
//
// It reuses describeTemplate, which is what `hostseal sign-template` prints, so the two cannot drift
// into showing an operator different things about the same act. What it adds is the origin: "sign this
// template" and "sign this template, because https://hostseal.example.org asked" are different
// questions, and only the second one can be answered wrongly on purpose.
func confirmBrowserTemplate(req localsign.Request, signer signing.Signer) (bool, error) {
	bootstrap := protocol.Bootstrap{Name: req.Name, Body: req.Body}
	fmt.Fprintf(os.Stderr, "\n  Asked for by %s\n", req.Origin)
	fmt.Fprint(os.Stderr, describeTemplate(bootstrap, signer))
	return prompt.Confirm("Sign this template? [y/N] ")
}

// signerArgs rebuilds the command line that --install registers.
//
// From the parsed flags rather than from argv, because what should run at the next logon is the command
// the operator described and not the one they typed: theirs carried --install, and a registration that
// re-registered itself at every logon would be a loop with a PIN prompt in it.
//
// --addr and --idle appear only when they differ from the defaults, so that the registered line is the
// line the operator wrote. Writing today's defaults into it would pin them: somebody who never chose an
// idle timeout would carry this version's across an upgrade that changed it, with nothing in the
// registration to say where the number came from.
func signerArgs(keyPath, addr string, idle time.Duration, origins []string) []string {
	args := []string{"signer", "--key", keyPath}
	for _, origin := range origins {
		args = append(args, "--origin", origin)
	}
	if addr != localsign.DefaultAddr {
		args = append(args, "--addr", addr)
	}
	if idle != localsign.DefaultIdleTimeout {
		args = append(args, "--idle", idle.String())
	}
	return args
}

// installAutostart registers this signer to start at the operator's next logon.
//
// It opens no token and signs nothing, which is the point of doing it here rather than at the end of a
// session: an operator can set this up once, from the command they already know works, without the act
// of registering it looking like the act of signing.
func installAutostart(keyPath, addr string, idle time.Duration, origins []string) int {
	// Before anything is written, because nothing else on this path would ever check them. The
	// running signer validates its origins in localsign.New, at a moment --install never reaches —
	// so an address pasted out of a browser's bar, with the path still on it, would register happily
	// and then fail at every logon, after the PIN prompt, with the registration looking correct
	// everywhere an operator would think to look.
	checked, err := normalisedOrigins(origins)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 2
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: this program cannot find its own path: %v\n", err)
		return 1
	}

	// Read before it is overwritten. An operator who forgot about an earlier registration — a token
	// they no longer carry, a control plane that has moved — is told what they just replaced, which is
	// the one moment they were going to notice.
	previous, hadPrevious, err := autostart.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}

	entry, err := autostart.Install(exe, signerArgs(keyPath, addr, idle, checked))
	if errors.Is(err, autostart.ErrUnsupported) {
		fmt.Fprint(os.Stderr, describeNoAutostart())
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}

	fmt.Fprint(os.Stderr, describeAutostart(entry, previous, hadPrevious, exe, idle))
	return 0
}

// normalisedOrigins checks the origins --install is about to register, and returns what a browser
// sends.
//
// The normalised form rather than the typed one, because that is what the signer will compare against
// and the registration should say what will happen rather than what was typed — an origin with a
// trailing slash works either way, and one that reads differently in the registry from how it is
// matched is a difference somebody has to know about in order to not be misled by it.
//
// It is the same localsign.ValidateOrigin the service runs, deliberately: two notions of a valid
// origin would eventually disagree, and the one that disagreed silently would be this one.
func normalisedOrigins(origins []string) ([]string, error) {
	checked := make([]string, 0, len(origins))
	for _, origin := range origins {
		valid, err := localsign.ValidateOrigin(origin)
		if err != nil {
			return nil, err
		}
		checked = append(checked, valid)
	}
	return checked, nil
}

// uninstallAutostart removes the logon registration.
//
// Removing one that is not there is a success rather than an error: the state somebody asked for is
// "no signer starts at logon", and they are in it either way. An error would make a second run, or a
// run on the machine where they never installed one, look like a failure to clean up.
func uninstallAutostart() int {
	removed, err := autostart.Uninstall()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}
	if removed {
		fmt.Fprintln(os.Stderr, "hostseal: the signer will no longer start at logon. "+
			"Nothing else was changed:\nthe binary, your key and your token are untouched.")
		return 0
	}
	fmt.Fprintln(os.Stderr, "hostseal: nothing was registered to start at logon, so there was "+
		"nothing to remove.")
	return 0
}

// describeAutostart renders what an operator is told after a registration is written.
//
// Text returned rather than printed, like describeSigner and describeJob, so that a test can assert
// what somebody is told. Three of these sentences are load-bearing rather than friendly: that the token
// was not opened and the command should be run once without --install, because the alternative is
// discovering a wrong module path at the next logon; that the idle exit still applies, because an
// operator who installs this is entitled to know it did not turn the signer into something that runs
// all day; and that it is not a service, because that is the next thing somebody asks for.
func describeAutostart(
	entry autostart.Entry, previous autostart.Entry, hadPrevious bool, exe string, idle time.Duration,
) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  Registered   %s\n", entry.Where)
	fmt.Fprintf(&b, "  Runs         %s\n", entry.Command)

	if hadPrevious && previous.Command != entry.Command {
		fmt.Fprintf(&b, "\n  This replaced an earlier registration, which ran:\n\n    %s\n",
			previous.Command)
	}

	if looksTemporary(exe) {
		fmt.Fprintf(&b, "\n  Note that %s is in a temporary directory. A registration pointing at a\n"+
			"  file that has been cleaned up starts nothing, and says nothing when it does not: move\n"+
			"  the binary somewhere permanent and run --install again.\n", exe)
	}

	fmt.Fprintf(&b, "\n  It starts in your own session, in a window of its own, and asks for the\n"+
		"  token's PIN there. It is not a service and will not become one: every signature is\n"+
		"  confirmed at that window, and a service has none.\n")
	fmt.Fprintf(&b, "\n  The idle exit is unchanged. A signer nothing has asked for anything in %s\n"+
		"  still stops, and the next one starts at your next logon.\n", idle)
	fmt.Fprintf(&b, "\n  Nothing was signed and your token was not opened. Run the same command\n"+
		"  without --install once, so that a wrong module path or a missing token is something you\n"+
		"  find now rather than at a logon.\n")
	fmt.Fprintf(&b, "\n  To undo:     hostseal signer --uninstall\n\n")
	return b.String()
}

// describeNoAutostart says why there is nothing to register on this platform.
//
// It names the mechanism and the reason rather than reporting that the flag is unsupported, because
// "unsupported" invites somebody to add a systemd user unit — which would start a signer with no
// terminal, and a signer with no terminal declines every signature it is asked for.
func describeNoAutostart() string {
	return "hostseal: there is no logon entry to register on this platform.\n\n" +
		"  The mechanisms here are a systemd user unit and a desktop autostart entry. The first has\n" +
		"  no terminal, and every signature is confirmed at one — end of input is a no, so a signer\n" +
		"  started that way would decline everything it was ever asked. The second starts a terminal\n" +
		"  emulator this tool would have to guess the name of.\n\n" +
		"  Start the signer when you need it. It exits on its own when the task is over.\n"
}

// looksTemporary reports whether a path is under this user's temporary directory.
//
// The case it exists for is the obvious way to arrive at this command on Windows: unpack the archive
// into %TEMP%, run the signer from there to try it, and register that path. It works until the
// directory is cleaned up, after which the logon entry silently starts nothing at all — and a signer
// that is not running looks, from the browser, exactly like a signer that was never installed.
func looksTemporary(exe string) bool {
	tmp, err := filepath.Abs(os.TempDir())
	if err != nil {
		return false
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(tmp, abs)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
