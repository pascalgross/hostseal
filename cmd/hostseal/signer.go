package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
func signerCommand(argv []string) int {
	fs := flag.NewFlagSet("signer", flag.ExitOnError)
	keyPath := fs.String("key", "",
		"the signing key: a path from `hostseal key generate`, or a backend reference such as\n"+
			"pkcs11:token=ops;object=ops-yubikey-1?module-path=<your PKCS#11 module>")
	addr := fs.String("addr", localsign.DefaultAddr,
		"loopback address to listen on; a non-loopback address is refused")
	idle := fs.Duration("idle", localsign.DefaultIdleTimeout,
		"exit after this long with no request, so a logged-in token session does not sit open")
	var origins originList
	fs.Var(&origins, "origin",
		"a HostSeal web interface allowed to ask for signatures, for example\n"+
			"https://hostseal.example.org; repeat for more than one")
	if err := fs.Parse(argv); err != nil {
		return 2
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
