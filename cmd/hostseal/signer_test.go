package main

import (
	"strings"
	"testing"
	"time"

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
