package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/autostart"
	"github.com/pascalgross/hostseal/internal/localsign"
	"github.com/pascalgross/hostseal/internal/signing"
	"github.com/pascalgross/hostseal/internal/signing/backend/file"
)

// TestTheSignerBannerNamesTheKeyAndTheLineAHostNeeds pins what an operator is told at the one moment
// they are looking.
//
// The trusted-signers line is the half of this arrangement that no tooling can do for anybody: the
// file is edited by hand, on each host, by an administrator who has decided that key may reboot that
// machine. A signer that started up without printing it would leave the commonest failure — a
// perfectly good signature that every host refuses — with no remedy anywhere on screen.
//
// The origins are in it for the opposite reason: they are the thing an operator gets wrong and can
// see they got wrong, because a signer told about the wrong address refuses every request from the
// browser with nothing visibly different about either.
func TestTheSignerBannerNamesTheKeyAndTheLineAHostNeeds(t *testing.T) {
	signer, err := file.Generate(t.TempDir()+"/ops.key", "ops-test", signing.Ed25519, []byte("pw"))
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	defer func() { _ = signer.Close() }()

	banner := describeSigner(signer, localsign.DefaultAddr,
		[]string{"https://hostseal.example.org"}, 30*time.Minute)

	line, err := signing.TrustedSignerLine(signer)
	if err != nil {
		t.Fatalf("rendering the trusted-signers line: %v", err)
	}
	for _, want := range []string{
		"ops-test",
		line,
		signing.TrustedSignersPath,
		localsign.DefaultAddr,
		"https://hostseal.example.org",
		"loopback only",
		"30m0s",
	} {
		if !strings.Contains(banner, want) {
			t.Errorf("the signer's banner does not mention %q:\n%s", want, banner)
		}
	}
}

// TestTheSignerRefusesToStartWithoutTheThingsThatMakeItSafe covers the flag handling that runs before
// a token is ever opened.
//
// Both refusals are about the same failure: a signer that is running and wrong. Without --origin it
// would answer any page in the browser; on a non-loopback address it would answer anybody who can
// reach the machine. Neither has a symptom on the machine that caused it, which is why they are
// refusals at the moment of typing rather than warnings in a log — and why they happen before the
// PIN prompt, so the cost of a typo is a sentence rather than a token interaction.
func TestTheSignerRefusesToStartWithoutTheThingsThatMakeItSafe(t *testing.T) {
	for name, argv := range map[string][]string{
		"no origin":            {"--key", "/nonexistent.key"},
		"no key":               {"--origin", "https://hostseal.example.org"},
		"a public address":     {"--key", "/nonexistent.key", "--origin", "https://h.example", "--addr", "0.0.0.0:18515"},
		"a hostname to listen": {"--key", "/nonexistent.key", "--origin", "https://h.example", "--addr", "localhost:18515"},
	} {
		if code := signerCommand(argv); code != 2 {
			t.Errorf("%s exited %d, want 2 — the usage code, before anything is opened", name, code)
		}
	}
}

// TestTheOriginFlagRepeats keeps the "more than one HostSeal" case working.
//
// An operator with a staging control plane and a production one signs from both, and a comma-separated
// list is the shape somebody eventually writes with a space in it.
func TestTheOriginFlagRepeats(t *testing.T) {
	var origins originList
	for _, value := range []string{"https://a.example", "https://b.example"} {
		if err := origins.Set(value); err != nil {
			t.Fatalf("setting --origin: %v", err)
		}
	}
	if len(origins) != 2 || origins[0] != "https://a.example" || origins[1] != "https://b.example" {
		t.Errorf("--origin collected %v", origins)
	}
	if got := origins.String(); got != "https://a.example, https://b.example" {
		t.Errorf("the flag renders as %q", got)
	}
}

// TestInstallWouldRegisterTheCommandTheSignerItselfWouldRun is the promise --install rests on.
//
// What gets registered is composed from the parsed flags rather than copied from argv, so "the logon
// entry runs what you just described" is an intention until something checks it. This parses the
// registered arguments back through the same flag set the command uses, which is the only version of
// that check a compiler can help with — and the failure it prevents is a silent one, appearing at a
// logon weeks later as a signer that listens on the wrong address or for the wrong origin.
func TestInstallWouldRegisterTheCommandTheSignerItselfWouldRun(t *testing.T) {
	const key = "pkcs11:token=ops;object=ops-yubikey-1?module-path=/usr/lib/opensc-pkcs11.so"
	origins := originList{"https://hostseal.example.org", "https://staging.example.org"}

	args := signerArgs(key, "127.0.0.1:19999", 90*time.Minute, origins)
	if len(args) == 0 || args[0] != "signer" {
		t.Fatalf("the registered command does not start with the subcommand: %q", args)
	}

	fs, flags := newSignerFlags()
	if err := fs.Parse(args[1:]); err != nil {
		t.Fatalf("the signer cannot parse what --install registered (%q): %v", args, err)
	}
	if *flags.key != key {
		t.Errorf("the registered key is %q, want %q", *flags.key, key)
	}
	if *flags.addr != "127.0.0.1:19999" {
		t.Errorf("the registered address is %q", *flags.addr)
	}
	if *flags.idle != 90*time.Minute {
		t.Errorf("the registered idle timeout is %s", *flags.idle)
	}
	if got := []string(*flags.origins); len(got) != 2 ||
		got[0] != origins[0] || got[1] != origins[1] {
		t.Errorf("the registered origins are %q, want %q", got, origins)
	}
	// The flag that produced the registration is not in it: a logon entry that re-registered itself
	// at every logon would be a loop, and one with a PIN prompt in it.
	for _, arg := range args {
		if arg == "--install" || arg == "--uninstall" {
			t.Errorf("the registered command carries %s: %q", arg, args)
		}
	}
}

// TestInstallLeavesTheDefaultsOutOfTheRegisteredCommand keeps a default from being pinned by accident.
//
// An operator who never chose an idle timeout has no opinion about it, and writing today's number into
// their logon entry would give them one — silently, and for as long as the registration lives, across
// upgrades that change what the default means.
func TestInstallLeavesTheDefaultsOutOfTheRegisteredCommand(t *testing.T) {
	args := signerArgs("/keys/ops.key", localsign.DefaultAddr, localsign.DefaultIdleTimeout,
		originList{"https://hostseal.example.org"})
	for _, unwanted := range []string{"--addr", "--idle"} {
		for _, arg := range args {
			if arg == unwanted {
				t.Errorf("%s was registered although it is the default: %q", unwanted, args)
			}
		}
	}
}

// TestInstallAndUninstallTogetherAreRefused covers the one contradiction these flags can express.
//
// Picking one silently would be a coin toss between "a signer starts at every logon" and "none does",
// decided by the order two ifs happen to be in.
func TestInstallAndUninstallTogetherAreRefused(t *testing.T) {
	if code := signerCommand([]string{"--install", "--uninstall", "--key", "/k", "--origin",
		"https://h.example"}); code != 2 {
		t.Errorf("--install --uninstall exited %d, want 2", code)
	}
}

// TestUninstallNeedsNoKeyOrOrigin covers the state somebody is in when they run it.
//
// They are clearing a workstation, or they have lost the token. Requiring them to retype the key
// reference they are getting rid of would be a flag check standing between a person and the thing they
// asked for, and the answer would be to edit the registry by hand instead.
func TestUninstallNeedsNoKeyOrOrigin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this would remove a real logon entry belonging to whoever is running the tests")
	}
	if code := signerCommand([]string{"--uninstall"}); code != 0 {
		t.Errorf("--uninstall alone exited %d, want 0", code)
	}
}

// TestTheInstallNoticeSaysWhatItDidNotDo pins the three sentences that are not decoration.
//
// The token was not opened, so a wrong module path is still undiscovered; the idle exit still applies,
// so this did not turn the signer into something that runs all day; and it is not a service, because
// that is the next thing somebody asks for and the answer has a reason. An operator who reads none of
// these still has a working signer — one who reads them cannot be surprised by it later.
func TestTheInstallNoticeSaysWhatItDidNotDo(t *testing.T) {
	entry := autostart.Entry{
		Where:   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\HostSeal signer`,
		Command: `C:\HostSeal\hostseal.exe signer --key ops --origin https://hostseal.example.org`,
	}
	previous := autostart.Entry{Where: entry.Where, Command: `C:\Old\hostseal.exe signer --key old`}

	notice := describeAutostart(entry, previous, true, `C:\HostSeal\hostseal.exe`, 30*time.Minute)
	for _, want := range []string{
		entry.Where,
		entry.Command,
		previous.Command,
		"not a service",
		"token was not opened",
		"30m0s",
		"hostseal signer --uninstall",
	} {
		if !strings.Contains(notice, want) {
			t.Errorf("the notice does not mention %q:\n%s", want, notice)
		}
	}
}

// TestTheInstallNoticeWarnsAboutATemporaryDirectory covers the way this goes wrong quietly.
//
// Unpacking the archive into %TEMP%, trying the signer from there and registering that path leaves a
// logon entry that works until the directory is cleaned up — after which it starts nothing and says
// nothing, and the browser reports exactly what it reports when no signer was ever installed.
func TestTheInstallNoticeWarnsAboutATemporaryDirectory(t *testing.T) {
	exe := filepath.Join(os.TempDir(), "hostseal-unpacked", "hostseal")
	notice := describeAutostart(autostart.Entry{Where: "somewhere", Command: "a command"},
		autostart.Entry{}, false, exe, 30*time.Minute)
	if !strings.Contains(notice, "temporary directory") {
		t.Errorf("a binary under %s was registered without a warning:\n%s", os.TempDir(), notice)
	}

	elsewhere := describeAutostart(autostart.Entry{Where: "somewhere", Command: "a command"},
		autostart.Entry{}, false, filepath.Join("/opt", "hostseal", "hostseal"), 30*time.Minute)
	if strings.Contains(elsewhere, "temporary directory") {
		t.Errorf("a permanent path was warned about:\n%s", elsewhere)
	}
}

// TestInstallRefusesAnOriginTheRunningSignerWouldRefuse covers the check --install would otherwise
// skip.
//
// The service validates its origins in localsign.New, which is a moment --install never reaches. An
// address pasted out of a browser's bar still carries its path, and registering that produces a logon
// entry that opens the token, asks for the PIN and then exits — every morning, with the registration
// reading correctly in the registry and the command reading correctly on screen. The exit code is
// checked rather than only the refusal, because 2 is the usage code every other pre-flight check here
// returns and 1 is what an unregistrable platform returns: they say different things to a script.
func TestInstallRefusesAnOriginTheRunningSignerWouldRefuse(t *testing.T) {
	for name, origin := range map[string]string{
		"a path":      "https://hostseal.example.org/jobs",
		"a wildcard":  "*",
		"plain http":  "http://hostseal.example.org",
		"no host":     "https://",
		"not a URL":   "hostseal.example.org",
		"a query too": "https://hostseal.example.org/?tenant=ops",
	} {
		code := signerCommand([]string{"--install", "--key", "/nonexistent.key", "--origin", origin})
		if code != 2 {
			t.Errorf("--install with %s (%q) exited %d, want 2 — refused before anything is written",
				name, origin, code)
		}
	}
}

// TestInstallRegistersTheOriginTheBrowserWillSend covers the normalising half of that check.
//
// What is registered should be what the signer will compare against, not what was typed. A trailing
// slash and a default port are both things an operator copies out of an address bar and neither is
// part of an Origin header, so a registration holding them would read as one thing in the registry and
// match as another.
func TestInstallRegistersTheOriginTheBrowserWillSend(t *testing.T) {
	checked, err := normalisedOrigins([]string{
		"https://hostseal.example.org/",
		"https://staging.example.org:443",
		"http://localhost:4200",
	})
	if err != nil {
		t.Fatalf("normalising origins: %v", err)
	}
	want := []string{
		"https://hostseal.example.org",
		"https://staging.example.org",
		"http://localhost:4200",
	}
	for i, origin := range want {
		if checked[i] != origin {
			t.Errorf("origin %d normalised to %q, want %q", i, checked[i], origin)
		}
	}
}
