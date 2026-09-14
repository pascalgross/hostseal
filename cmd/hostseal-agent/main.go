//go:build linux || windows

// Command hostseal-agent is the HostSeal agent that runs on a managed host.
//
// It connects outbound to a control plane and never listens. There is no server-to-agent direction in
// the protocol at all: every byte moves on a connection this process opened, which is why a managed
// host needs no inbound firewall rule and why putting the fleet behind a VPN buys nothing. See
// docs/PROTOCOL.md.
//
// The agent holds no privilege. On Linux it runs as the hostseal user with an empty capability bounding
// set under the hardened unit in packaging/hostseal-agent.service; the three helpers in
// /usr/libexec/hostseal are the only privileged operations that exist, and each re-enforces the
// root-owned policy itself. This binary changes nothing by itself: every privileged operation happens in
// one of those helpers, reached over the unix sockets in /run/hostseal and never through sudo — with the
// agent's sandbox in force, execve drops the setuid bit, so sudo cannot become root at all.
// `hostseal-agent doctor` checks that boundary from this process's own account.
//
// The build constraint above names the two platforms an agent exists for, and the two builds are not the
// same product. A Windows agent executes the read tier and nothing else, because the mechanism that
// keeps a host sovereign over privileged work is a fresh, socket-activated root helper re-reading the
// host's own policy — and Windows has nothing of that shape, so a privileged operation there would rest
// on the agent process alone. That is enforced in code rather than remembered: internal/agent's
// hostProfile is a const in a build-tagged file, the acceptance path refuses anything outside it, and
// TestGuaranteeTheWindowsProfileHoldsOnlyReadIntents fails if a privileged member is ever added to it.
// docs/SECURITY.md §12 is the argument in full.
//
// A build for any third platform is still nothing, and deliberately so. It would very nearly succeed —
// the tree is close to portable — and the binary that came out would read /etc/os-release, execute
// /usr/bin/apt-get and dial unix sockets under /run/hostseal, failing every operation while looking to an
// operator like a supported platform. A build that fails with "build constraints exclude all Go files"
// is a sentence somebody wrote.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pascalgross/hostseal/internal/agent"
	"github.com/pascalgross/hostseal/internal/buildinfo"
	"github.com/pascalgross/hostseal/internal/canonical"
	"github.com/pascalgross/hostseal/internal/collect"
	"github.com/pascalgross/hostseal/internal/collect/collector"
	"github.com/pascalgross/hostseal/internal/collect/platform"
	"github.com/pascalgross/hostseal/internal/intent"
	"github.com/pascalgross/hostseal/internal/policy"
	"github.com/pascalgross/hostseal/internal/privsep"
	"github.com/pascalgross/hostseal/internal/run"
)

// StateDir is where the agent keeps everything it writes.
//
// It is agent.DefaultStateDir rather than a second copy of the path, because the two disagreeing would
// mean a flag default pointing somewhere the agent does not look — and the path differs by platform now,
// so a literal here would have been right on exactly one of them.
const StateDir = agent.DefaultStateDir

// usage prints the command list.
//
// It is written out rather than generated because the agent's surface is meant to stay small enough to
// list, and a help text that grows without anyone noticing is the first sign that it has not.
func usage() {
	fmt.Fprintf(os.Stderr, `hostseal-agent %s

usage:
  hostseal-agent run             run the agent in the foreground, as systemd does
  hostseal-agent facts           collect and print exactly what this host would report
  hostseal-agent policy check    validate the local policy file and print the effective policy
  hostseal-agent doctor          check this host's privileged path from the agent's own account
  hostseal-agent version         print the version

The agent connects outbound only. It has no listening port and no server-to-agent channel.
`, buildinfo.String())
}

// main dispatches to a subcommand.
func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "run":
		os.Exit(runCommand(args[1:]))
	case "facts":
		os.Exit(factsCommand(args[1:]))
	case "policy":
		os.Exit(policyCommand(args[1:]))
	case "doctor":
		os.Exit(doctorCommand(args[1:]))
	case "version":
		fmt.Println("hostseal-agent " + buildinfo.String())
	default:
		fmt.Fprintf(os.Stderr, "hostseal-agent: unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
}

// setupLogging configures structured logging to stderr, which systemd routes to the journal.
//
// The agent logs JSON for the same reason the helpers do: what an operator needs six months after an
// incident is a machine-readable trail of what was asked, what was decided and why, and grepping that
// out of prose does not work.
func setupLogging() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With(
		"component", "agent",
		"version", buildinfo.Version,
		"commit", buildinfo.Revision(),
	))
}

// runCommand starts the agent and blocks until it is asked to stop.
//
// A host that has not been enrolled does not exit. It reports its local configuration on a timer and
// waits, because the alternative — a service that fails to start until somebody runs hostseal enroll —
// leaves systemd restarting it every five seconds and fills the journal with noise on exactly the hosts
// an operator has not got to yet.
func runCommand(argv []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	policyPath := fs.String("policy", policy.Path, "policy file to read")
	stateDir := fs.String("state-dir", StateDir, "directory holding enrolment state")
	interval := fs.Duration("report-interval", 15*time.Minute,
		"how often an unenrolled agent re-reads and reports local state")
	noJitter := fs.Bool("no-startup-jitter", false,
		"contact the control plane immediately instead of waiting a random delay")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	setupLogging()

	// The loop, as a closure, so that the platform decides where its context comes from. On Linux that
	// is a signal handler; on Windows, when the process was started by the service control manager, it
	// is the SCM's own stop request — which arrives as a message on a channel rather than as a signal,
	// and which the process must acknowledge within a deadline or be killed.
	loop := func(ctx context.Context) int {
		slog.Info("hostseal agent starting",
			"version", buildinfo.Version,
			"commit", buildinfo.Revision(),
			"state_dir", *stateDir,
			"profile", agent.HostProfile(),
			"intents", len(intent.ProfileMembers(agent.HostProfile())),
			"helper_sockets", privilegedEndpoints(),
		)
		reportState(*policyPath)

		instance, err := agent.New(agent.Options{StateDir: *stateDir, PolicyPath: *policyPath})
		if err != nil {
			slog.Warn("not enrolled; reporting local state only",
				"error", err,
				"note", "run `hostseal enroll --server URL --token TOKEN` to connect this host. "+
					"Updates continue to be applied from the local policy either way.")
			return idle(ctx, *policyPath, *interval)
		}

		if err := instance.Run(ctx, agent.Options{SkipStartupJitter: *noJitter}); err != nil {
			slog.Error("the agent stopped with an error", "error", err)
			return 1
		}
		return 0
	}

	return runService(loop)
}

// idle reports local state on a timer for a host that is not enrolled.
//
// It exists so that an unenrolled host still has a running service with a readable journal, rather than
// a unit systemd is restarting in a loop. Patching continues regardless: unattended-upgrades runs on
// its own timer and does not need HostSeal to be reachable, or even enrolled.
func idle(ctx context.Context, policyPath string, interval time.Duration) int {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("hostseal agent stopping")
			return 0
		case <-ticker.C:
			reportState(policyPath)
		}
	}
}

// reportState logs the host's effective local configuration.
//
// It re-reads the policy on every call rather than caching it, because an administrator who edits
// policy.toml expects the change to take effect without restarting a service, and because the same
// re-read discipline is what the root helpers rely on.
func reportState(policyPath string) {
	p, err := policy.LoadFrom(policyPath)
	switch {
	case errors.Is(err, policy.ErrNoPolicyFile):
		slog.Warn("no policy file; using the built-in default", "path", policyPath)
	case err != nil:
		slog.Error("policy could not be read; this host will refuse all privileged work",
			"path", policyPath, "error", err)
	}

	slog.Info("effective local policy",
		"source", p.Source(),
		"updates_allow", p.Updates.Allow,
		"auto_apply", p.Updates.AutoApply,
		"window", p.Window().String(),
		"timezone", p.Updates.Timezone,
		"reboot", p.Updates.Reboot,
		"restartable", p.Services.Restartable,
		"max_job_age_seconds", p.Limits.MaxJobAgeSeconds,
		"paused", policy.Paused(),
	)
}

// factsCommand implements `hostseal-agent facts`.
//
// It collects and prints exactly what a heartbeat would carry. That is worth a subcommand rather than
// being inferred from the journal: the first question about a wrong number on a dashboard is whether
// the host reported it wrongly or the control plane displayed it wrongly, and this answers that in one
// command, on the host, with no control plane involved at all.
//
// It is also what the integration suite compares against apt's own output, which is how the
// security/regular split is checked on a real machine rather than against a fixture.
//
// It reads the policy file, which for a command that changes nothing looks unnecessary and is not: the
// local policy decides which sections a host discloses at all, so a subcommand that skipped it would
// print a document the heartbeat would not send — and would fail at the one job it exists to do, which
// is to tell "the host reported it wrongly" from "the control plane displayed it wrongly".
func factsCommand(argv []string) int {
	fs := flag.NewFlagSet("facts", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the facts document as JSON, exactly as it goes on the wire")
	policyPath := fs.String("policy", policy.Path, "policy file to read")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	setupLogging()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	plat, dist, err := platform.Detect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal-agent: %v\n", err)
		return 1
	}

	// The same fall-through the agent itself uses: a missing file takes the built-in default, an
	// unreadable one takes the closed policy, and neither is fatal to printing the facts. Reporting
	// less than the heartbeat would is the correct behaviour for a host whose policy cannot be read.
	p, err := policy.LoadFrom(*policyPath)
	switch {
	case errors.Is(err, policy.ErrNoPolicyFile):
		slog.Warn("no policy file; using the built-in default", "path", *policyPath)
	case err != nil:
		slog.Error("policy could not be read; sections this host may decline to report are omitted",
			"path", *policyPath, "error", err)
	}

	facts, err := collect.Gather(ctx, plat, p, collector.All()...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal-agent: collecting facts: %v\n", err)
		return 1
	}

	if *asJSON {
		// The canonical encoding, not encoding/json's default: this is the document the digest is
		// computed over, so printing anything else would answer a slightly different question.
		raw, err := canonical.Marshal(facts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hostseal-agent: encoding facts: %v\n", err)
			return 1
		}
		fmt.Println(string(raw))
		return 0
	}

	digest, err := canonical.Digest(facts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal-agent: digesting facts: %v\n", err)
		return 1
	}

	fmt.Printf("hostname            %s\n", facts.Hostname)
	fmt.Printf("distribution        %s\n", dist)
	fmt.Printf("supported           %t\n", dist.Supported)
	fmt.Printf("kernel              %s\n", facts.Kernel)
	fmt.Printf("architecture        %s\n", facts.Architecture)
	fmt.Printf("updates             %d security of %d total\n",
		facts.Packages.UpgradableSecurity, facts.Packages.UpgradableTotal)
	fmt.Printf("reboot required     %t (%s)\n", facts.Reboot.Required, facts.Reboot.Source)
	if len(facts.Reboot.Services) > 0 {
		fmt.Printf("services to restart %v\n", facts.Reboot.Services)
	}
	fmt.Printf("service scan whole  %t\n", facts.Reboot.ServiceScanComplete)
	if facts.Subscription.Applicable {
		fmt.Printf("ubuntu pro          attached=%t %s\n", facts.Subscription.Attached, facts.Subscription.Note)
	} else {
		fmt.Printf("ubuntu pro          not applicable\n")
	}
	fmt.Printf("units               %d\n", len(facts.Services))
	for _, c := range collector.All() {
		// Listed from the registry rather than from the document, so that a section the local policy
		// withheld is visible as withheld. Iterating the document alone would print nothing for it,
		// which reads exactly like a collector nobody wrote.
		if _, reported := facts.Extra[c.Name()]; reported {
			fmt.Printf("collector           %s\n", c.Name())
			continue
		}
		if gated, ok := c.(collect.PolicyGated); ok && !gated.PermittedBy(p) {
			fmt.Printf("collector           %s (withheld by %s)\n", c.Name(), p.Source())
			continue
		}
		fmt.Printf("collector           %s (failed; see the log above)\n", c.Name())
	}
	fmt.Printf("facts digest        %s\n", digest)
	return 0
}

// policyCommand implements `hostseal-agent policy check`.
//
// It exists so that an administrator can validate an edit before restarting anything. A policy file
// that does not parse causes the host to refuse all privileged work rather than fall back to a
// default, which is the right behaviour and a miserable way to discover a typo.
func policyCommand(argv []string) int {
	if len(argv) == 0 || argv[0] != "check" {
		fmt.Fprintln(os.Stderr, "usage: hostseal-agent policy check [--policy PATH]")
		return 2
	}
	fs := flag.NewFlagSet("policy check", flag.ExitOnError)
	policyPath := fs.String("policy", policy.Path, "policy file to validate")
	if err := fs.Parse(argv[1:]); err != nil {
		return 2
	}

	p, err := policy.LoadFrom(*policyPath)
	if errors.Is(err, policy.ErrNoPolicyFile) {
		fmt.Printf("no policy file at %s; the built-in default would be used:\n", *policyPath)
		err = nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s is not valid: %v\n", *policyPath, err)
		fmt.Fprintln(os.Stderr, "this host would refuse all privileged work until it is fixed")
		return 1
	}

	fmt.Printf("source              %s\n", p.Source())
	fmt.Printf("updates.allow       %s\n", p.Updates.Allow)
	fmt.Printf("updates.auto_apply  %t\n", p.Updates.AutoApply)
	fmt.Printf("updates.window      %s (%s)\n", p.Window(), p.Updates.Timezone)
	fmt.Printf("updates.reboot      %s\n", p.Updates.Reboot)
	fmt.Printf("services.restartable %v\n", p.Services.Restartable)
	fmt.Printf("services.watched    %v\n", p.Services.Watched)
	fmt.Printf("containers.report   %t\n", p.Containers.Report)
	// Printed even though this key bounds only what the host says, because packaging/policy.toml and
	// docs/INSTALL.md both name this command as the way to check an edit to it — and a check whose
	// output is byte-identical before and after the edit is a check that confirms nothing.
	fmt.Printf("resources.report    %t\n", p.Resources.Report)
	fmt.Printf("updates.scan        %t\n", p.Updates.Scan)
	fmt.Printf("limits.max_job_age_seconds %d\n", p.Limits.MaxJobAgeSeconds)
	fmt.Printf("paused              %t\n", policy.Paused())
	if !p.Window().Always() {
		fmt.Printf("window next opens   %s\n", p.Window().NextOpen(time.Now()).Format(time.RFC3339))
	}
	return 0
}

// doctorCommand implements `hostseal-agent doctor`.
//
// It answers one question an operator otherwise cannot answer without waiting for a job to fail: can
// this process, as the account it actually runs as, reach the three root helpers? Every layer of that
// path is somebody else's to break — a socket unit that did not get enabled, a group that was renamed,
// a tmpfiles fragment that did not run after a reboot — and every one of them fails the same way from
// the control plane's side, as a privileged job that did not work weeks later.
//
// It changes nothing. The probe names an intent that is in no catalogue and on no route, so the helper
// refuses it before decoding a parameter or reading a policy; a refusal is what success looks like
// here. There is no harmless privileged intent to send instead, because every one of them changes the
// machine, which is the point of them being privileged.
func doctorCommand(argv []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	if err := fs.Parse(argv); err != nil {
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("running as        uid %d\n", os.Getuid())
	fmt.Println("programs this build may start, and no others:")
	for _, program := range run.Allowlist() {
		fmt.Printf("  %s\n", program)
	}

	fmt.Println("privileged path:")
	client := privsep.NewClient()
	healthy := true
	for _, socket := range privsep.Endpoints() {
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		resp, err := client.Probe(probeCtx, socket)
		cancel()
		switch {
		case err != nil:
			healthy = false
			fmt.Printf("  %-32s unreachable: %v\n", socket, err)
		case resp.ExitCode == 0:
			// A helper that answered "fine" to a name nothing serves is acting on requests it does not
			// recognise, which is a worse finding than an unreachable socket rather than a better one.
			healthy = false
			fmt.Printf("  %-32s ANSWERED an intent nothing serves; this build is wrong\n", socket)
		default:
			fmt.Printf("  %-32s reachable, and refuses what it does not serve\n", socket)
		}
	}

	fmt.Println("intents that have a privileged route:")
	for _, name := range intent.Names() {
		if socket, routed := privsep.Endpoint(name); routed {
			fmt.Printf("  %-26s %s\n", name, socket)
		}
	}

	if !healthy {
		fmt.Fprintln(os.Stderr,
			"\nThis host reports fine and cannot be patched, restarted or rebooted by the control\n"+
				"plane. Check that the three hostseal-*.socket units are enabled and running, and that\n"+
				"this account is in the hostseal group.")
		return 1
	}
	fmt.Println("\nthe privileged path is intact")
	return 0
}
