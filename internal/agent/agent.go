// Package agent is the HostSeal agent's protocol client and main loop.
//
// It connects outbound and never listens. There is no server-to-agent direction in the protocol at all:
// every byte moves on a connection this process opened, which is why a managed host needs no inbound
// firewall rule and why putting the fleet behind a VPN buys nothing.
//
// The loop is arranged around four things that are production incidents rather than inefficiencies when
// skipped, each of which is in docs/PROTOCOL.md and implemented here:
//
//   - Digest-first heartbeats, so five hundred hosts cost hundreds of bytes a minute rather than
//     hundreds of kilobytes.
//   - Full-jitter backoff and a randomised delay after boot, because five hundred agents reconnecting
//     in the same second is the most common way an agent fleet kills its own control plane — and it
//     happens exactly when the control plane has just come back.
//   - Results spooled to disk and fsynced *before* the operation runs, because host.reboot completes by
//     the host disappearing.
//   - Server-set pacing, honoured but clamped, so a control plane can back a fleet off during an
//     incident without an agent deploy and a buggy one cannot induce a hot loop.
package agent

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/pascalgross/hostseal/internal/buildinfo"
	"github.com/pascalgross/hostseal/internal/ca"
	"github.com/pascalgross/hostseal/internal/canonical"
	"github.com/pascalgross/hostseal/internal/collect"
	"github.com/pascalgross/hostseal/internal/collect/collector"
	"github.com/pascalgross/hostseal/internal/collect/platform"
	"github.com/pascalgross/hostseal/internal/policy"
	"github.com/pascalgross/hostseal/internal/privsep"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/signing"
)

// BootIDPath is the kernel's identifier for the current boot.
//
// It is used rather than uptime because a reboot must be visible as a discrete event: uptime going
// backwards can also mean a clock adjustment, and the two want different responses.
const BootIDPath = "/proc/sys/kernel/random/boot_id"

// Agent is a running HostSeal agent.
type Agent struct {
	// state is what was learned at enrolment.
	state *State

	// client speaks the protocol to the control plane.
	client *Client

	// platform is the distribution-family implementation for this host.
	platform collect.Platform

	// nonces refuses replayed signatures across restarts.
	nonces *NonceStore

	// elevate is the route to the three root helpers, over the sockets in /run/hostseal.
	//
	// It is the agent's entire relationship with privilege: it names an intent and forwards the
	// parameter bytes it received, and it is told what happened. There is deliberately nothing here
	// that could name a program, and nothing this process does with the reply except report it.
	elevate privsep.Invoker

	// policyPath is the local policy file, re-read on every cycle.
	policyPath string

	// heartbeatSeconds is the server-set pacing, clamped.
	heartbeatSeconds int

	// clockOffset is the agent's measurement of its offset from the control plane.
	clockOffset time.Duration

	// backoff paces retries after failures.
	backoff *Backoff
}

// Options configure a running agent.
type Options struct {
	// StateDir is where the agent keeps its key, certificate and spools.
	StateDir string

	// PolicyPath is the local policy file.
	PolicyPath string

	// SkipStartupJitter runs the first cycle immediately, for tests and for a foreground run.
	//
	// It exists as an option rather than being inferred, because the jitter it disables is what stops a
	// fleet restarted by a configuration-management run from arriving in the same second.
	SkipStartupJitter bool

	// Elevate substitutes the route to the root helpers, for tests. Empty means the real one.
	//
	// The agent's job path has to be exercised without a root helper and without systemd, for the same
	// reason it is exercised without a real platform: a test that needed either would be a test of the
	// developer's machine. It is not an extension point — internal/privsep holds exactly one real
	// implementation and is arranged so that there cannot be a second.
	Elevate privsep.Invoker
}

// New builds an agent from persisted enrolment state.
func New(opts Options) (*Agent, error) {
	if opts.StateDir == "" {
		opts.StateDir = "/var/lib/hostseal"
	}
	if opts.PolicyPath == "" {
		opts.PolicyPath = policy.Path
	}

	state, err := LoadState(opts.StateDir)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(state.ServerURL, opts.StateDir, state.Path(CABundleFile))
	if err != nil {
		return nil, err
	}
	plat, dist, err := platform.Detect()
	if err != nil {
		return nil, fmt.Errorf("agent: identifying this host: %w", err)
	}
	if !dist.Supported {
		// Reported rather than refused. A host on an unsupported release is exactly the host somebody
		// most needs to see in a fleet list, and refusing to run on it would remove it from view.
		slog.Warn("this release is not in HostSeal's supported set",
			"distribution", dist.String(), "codename", dist.Codename)
	}
	nonces, err := LoadNonceStore(opts.StateDir)
	if err != nil {
		return nil, err
	}

	elevate := opts.Elevate
	if elevate == nil {
		elevate = privsep.NewClient()
	}

	return &Agent{
		state:            state,
		client:           client,
		platform:         plat,
		nonces:           nonces,
		elevate:          elevate,
		policyPath:       opts.PolicyPath,
		heartbeatSeconds: protocol.DefaultHeartbeatSeconds,
		backoff:          NewBackoff(),
	}, nil
}

// Run drives the agent until the context ends.
func (a *Agent) Run(ctx context.Context, opts Options) error {
	slog.Info("agent connected to a control plane",
		"host", a.state.HostID, "server", a.state.ServerURL, "version", buildinfo.String())

	// Anything spooled before a reboot goes out first, before the agent does anything else. A result
	// written just before the machine went down is the one most likely to be waited on.
	DeliverPending(ctx, a.client, a.state.Dir())

	if !opts.SkipStartupJitter {
		delay := Jitter(time.Duration(a.heartbeatSeconds)*time.Second, 1.0)
		slog.Info("waiting before the first contact", "delay", delay.Round(time.Second))
		if !Sleep(ctx, delay) {
			return nil
		}
	}

	// Full report on the first beat after a start. The control plane may have missed everything that
	// changed while this agent was down, and a digest it cannot resolve costs one extra round trip.
	wantFull := true

	for {
		// A cancelled context is an ordinary shutdown here rather than a failure: systemd sends SIGTERM
		// and expects the process to exit cleanly, so this returns nil.
		select {
		case <-ctx.Done():
			slog.Info("hostseal agent stopping")
			return nil
		default:
		}

		next, err := a.cycle(ctx, wantFull)
		wantFull = next

		switch {
		case err == nil:
			a.backoff.Reset()
			interval := time.Duration(a.heartbeatSeconds) * time.Second
			// Jitter every interval, not only the first. Without it a fleet re-synchronises within a
			// few hours of any event that restarted it all at once.
			if !Sleep(ctx, interval+Jitter(interval, 0.1)) {
				return nil
			}

		case IsUnauthorised(err):
			// A 401 stops the loop rather than retrying. A host that re-enrolled itself whenever its
			// certificate was rejected would be a host an attacker could cause to re-enrol; and a host
			// that retried a rejected certificate every minute would be a denial of service against
			// the control plane it can no longer talk to. It keeps running — patching continues from
			// the local policy on its own timer — and an operator decides.
			slog.Error("the control plane rejected this agent's certificate; not retrying",
				"error", err,
				"note", "the host will keep patching from its local policy. "+
					"Re-enrol it if this was intended.")
			<-ctx.Done()
			return nil //nolint:nilerr // stopping without retrying is the intended response to a 401

		default:
			delay := a.backoff.Next()
			if requested := RetryAfter(err); requested > 0 {
				delay = requested
			}
			slog.Warn("cycle failed; backing off",
				"error", err, "attempt", a.backoff.Attempt(), "retry_in", delay.Round(time.Second))
			if !Sleep(ctx, delay) {
				return nil
			}
		}
	}
}

// cycle performs one heartbeat, one job poll and any due maintenance.
//
// It returns whether the next beat should carry a full report, which is how the server's want flags
// reach the following iteration.
func (a *Agent) cycle(ctx context.Context, wantFull bool) (bool, error) {
	p, err := policy.LoadFrom(a.policyPath)
	if err != nil && !errors.Is(err, policy.ErrNoPolicyFile) {
		slog.Error("policy could not be read; this host will refuse privileged work",
			"path", a.policyPath, "error", err)
	}

	signers, err := signing.LoadTrustedSigners()
	if err != nil {
		slog.Error("the trust anchor could not be read; destructive jobs will be refused", "error", err)
		signers = &signing.SignerSet{}
	}

	req, err := a.buildHeartbeat(ctx, p, signers, wantFull)
	if err != nil {
		return wantFull, err
	}

	beatCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	res, err := a.client.Heartbeat(beatCtx, req)
	cancel()
	if err != nil {
		return wantFull, err
	}

	if !res.ServerTime.IsZero() {
		// Used only to compute and report an offset. The agent never adjusts its clock, its timers, or
		// any validity check to server-supplied time.
		a.clockOffset = time.Since(res.ServerTime)
		if absDuration(a.clockOffset) > protocol.MaxClockSkewSeconds*time.Second {
			slog.Warn("this host's clock is far from the control plane's; privileged intents will "+
				"refuse", "offset", a.clockOffset.Round(time.Second))
		}
	}
	if res.NextHeartbeatSeconds > 0 {
		a.heartbeatSeconds = protocol.ClampHeartbeatSeconds(res.NextHeartbeatSeconds)
	}

	// Cached before the poll, so that a job arriving in the same cycle as a rotated key verifies
	// against the key the control plane is currently signing with rather than the previous one.
	if err := StoreOnlineKey(a.state.Dir(), res.OnlineKey); err != nil {
		slog.Error("could not cache the control plane's online key; routine jobs may be refused",
			"error", err)
	}
	online, err := LoadOnlineKey(a.state.Dir())
	if err != nil {
		slog.Error("the control plane's online key could not be read; routine jobs will be refused",
			"error", err)
		online = &signing.SignerSet{}
	}

	a.maybeRenew(ctx)
	a.pollAndRun(ctx, p, signers, online)

	return res.WantFullReport || res.WantFacts || res.WantPolicy || res.WantSigners, nil
}

// buildHeartbeat assembles a heartbeat, digest-first.
//
// Facts are gathered on every cycle whether or not they are sent, because the digest cannot be computed
// without them. That is the deliberate trade: local work on the host, which is cheap and parallel across
// the fleet, in exchange for not moving the bytes, which is expensive and serialised at the control
// plane.
func (a *Agent) buildHeartbeat(ctx context.Context, p policy.Policy, signers *signing.SignerSet,
	wantFull bool) (protocol.HeartbeatRequest, error) {

	facts, err := collect.Gather(ctx, a.platform, p, collector.All()...)
	if err != nil {
		return protocol.HeartbeatRequest{}, fmt.Errorf("agent: gathering facts: %w", err)
	}
	factsDigest, err := canonical.Digest(facts)
	if err != nil {
		return protocol.HeartbeatRequest{}, fmt.Errorf("agent: digesting facts: %w", err)
	}

	policyView := policyView(p)
	policyDigest, err := canonical.Digest(policyView)
	if err != nil {
		return protocol.HeartbeatRequest{}, fmt.Errorf("agent: digesting the policy: %w", err)
	}

	signerViews := signerViews(signers)
	signersDigest, err := signers.Digest()
	if err != nil {
		return protocol.HeartbeatRequest{}, fmt.Errorf("agent: digesting the trust anchor: %w", err)
	}

	req := protocol.HeartbeatRequest{
		AgentVersion:       buildinfo.Version,
		BootID:             bootID(),
		UptimeSeconds:      uptimeSeconds(),
		FactsDigest:        factsDigest,
		PolicyDigest:       policyDigest,
		SignersDigest:      signersDigest,
		ClockOffsetSeconds: int64(a.clockOffset.Seconds()),
		Paused:             policy.Paused(),
	}
	if wantFull {
		req.Facts = facts
		req.Policy = policyView
		req.Signers = signerViews
	}
	return req, nil
}

// policyView renders the effective local policy for reporting.
//
// It is a projection rather than the policy struct itself, so that the digest and the reported document
// cover exactly the settings that bound what the control plane may ask for — and so that adding an
// unrelated internal field does not make every host in a fleet look changed.
func policyView(p policy.Policy) map[string]any {
	return map[string]any{
		"updates": map[string]any{
			"allow":     string(p.Updates.Allow),
			"autoApply": p.Updates.AutoApply,
			"window":    p.Window().String(),
			"timezone":  p.Updates.Timezone,
			"reboot":    string(p.Updates.Reboot),
		},
		"services": map[string]any{
			"restartable": append([]string{}, p.Services.Restartable...),
			"watched":     append([]string{}, p.Services.Watched...),
		},
		// Reported even though it bounds nothing the control plane may ask for, because it bounds what
		// the control plane is told — and a UI that cannot see it has no way to tell an empty container
		// card from a host that has declined to fill one in.
		"containers": map[string]any{
			"report": p.Containers.Report,
		},
		// Here for the same reason, and with one more of its own: this gate ships on, so its interesting
		// value is the false one. A host that has switched capacity reporting off would otherwise be
		// indistinguishable from one whose agent is too old to have the section at all, and the two want
		// different responses from whoever is looking for the disk that is filling up.
		"resources": map[string]any{
			"report": p.Resources.Report,
		},
		// And this one, whose absence a client cannot infer from anything else: a host that has switched
		// network reporting off looks exactly like one whose netlink access was taken away, and the two
		// want different responses.
		"network": map[string]any{
			"report": p.Network.Report,
		},
		"limits": map[string]any{
			"maxJobAgeSeconds": p.Limits.MaxJobAgeSeconds,
		},
		"source": p.Source(),
	}
}

// signerViews renders the host's trusted key identities for reporting.
//
// Identities and algorithms only, never the keys or the file. The control plane has no business holding
// a copy of a host's trust anchor, and showing an operator "ops-yubikey-1 (pkcs11)" needs no more.
func signerViews(signers *signing.SignerSet) []protocol.SignerSummary {
	out := make([]protocol.SignerSummary, 0, signers.Len())
	for _, k := range signers.Keys() {
		out = append(out, protocol.SignerSummary{
			KeyID:     k.KeyID,
			Algorithm: string(k.Algorithm),
			Backend:   k.Backend,
		})
	}
	return out
}

// pollAndRun long-polls for work and runs whatever comes back.
//
// Each result is spooled to disk before it is sent and removed only after the control plane accepts it,
// so a lost response causes a redelivery rather than a re-execution.
func (a *Agent) pollAndRun(ctx context.Context, p policy.Policy, signers, online *signing.SignerSet) {
	pollCtx, cancel := context.WithTimeout(ctx, (protocol.DefaultJobWaitSeconds+15)*time.Second)
	defer cancel()

	jobs, err := a.client.PollJobs(pollCtx, protocol.DefaultJobWaitSeconds)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("could not poll for jobs", "error", err)
		}
		return
	}
	for _, job := range jobs {
		if ctx.Err() != nil {
			return
		}
		runner := Runner{
			HostID:      a.state.HostID,
			Policy:      p,
			Signers:     signers,
			Online:      online,
			Nonces:      a.nonces,
			Platform:    a.platform,
			Elevate:     a.elevate,
			ClockOffset: a.clockOffset,
			Spool: func(provisional protocol.ResultRequest) error {
				return SpoolResult(a.state.Dir(), provisional)
			},
		}
		result := runner.Run(ctx, job)
		slog.Info("job finished", "job", job.ID, "intent", job.Intent, "status", result.Status)

		// Written again, unconditionally: for an operation that may not return this replaces the
		// provisional record, and for everything else it is the only one.
		if err := SpoolResult(a.state.Dir(), result); err != nil {
			slog.Error("could not spool a job result; it may be lost if this host restarts",
				"job", job.ID, "error", err)
		}
		if err := a.client.ReportResult(ctx, result); err != nil {
			if !permanentlyRefused(err) {
				slog.Warn("could not report a job result; it stays spooled for the next pass",
					"job", job.ID, "error", err)
				continue
			}
			// Refused rather than undelivered: see DeliverPending for why that is the one case where
			// the spool file goes rather than staying.
			slog.Error("a job result was refused permanently and has been discarded",
				"job", job.ID, "status", result.Status, "error", err)
		}
		spoolFile, pathErr := SpoolPath(a.state.Dir(), result.JobID)
		if pathErr != nil {
			slog.Warn("a job id that is not an identifier reached the spool path",
				"job", result.JobID, "error", pathErr)
			continue
		}
		if err := os.Remove(spoolFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("reported a result but could not remove its spool file",
				"path", spoolFile, "error", err)
		}
	}
}

// maybeRenew re-keys the client certificate when it is two thirds through its life.
//
// The renewal point is jittered so that a fleet enrolled on the same afternoon does not renew in the
// same minute ninety days later. That stampede arrives exactly once, which is another way of saying it
// is never load-tested.
func (a *Agent) maybeRenew(ctx context.Context) {
	cert, err := CredentialLeaf(a.state.Dir())
	if err != nil {
		slog.Error("could not read the client certificate", "error", err)
		return
	}

	renewAt := ca.RenewAt(cert).Add(Jitter(24*time.Hour, 1.0))
	if time.Now().Before(renewAt) {
		return
	}

	slog.Info("renewing the client certificate",
		"not_after", cert.NotAfter.Format(time.RFC3339), "renew_at", renewAt.Format(time.RFC3339))

	key, csrPEM, err := generateKeyAndCSR()
	if err != nil {
		slog.Error("could not build a renewal request", "error", err)
		return
	}
	renewCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	res, err := a.client.Renew(renewCtx, string(csrPEM))
	if err != nil {
		// Renewal happens with a third of the certificate's life still to run, so a failure here has
		// thirty days of retries ahead of it. Logging and carrying on is correct; the old certificate
		// still works.
		slog.Warn("certificate renewal failed; the current certificate is still valid", "error", err)
		return
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		slog.Error("could not encode the renewed private key", "error", err)
		return
	}

	// One file, one rename. The key and the certificate are promoted together, so there is no instant at
	// which the pair on disk belongs to two different key pairs — the failure that used to be
	// unrecoverable, because the private key matching the working certificate would already be gone.
	// The client loads the pair from disk on each request, so the new one takes effect without a
	// restart, and the superseded pair stays beside it as a fallback.
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := WriteCredential(a.state.Dir(), []byte(res.Certificate), keyPEM); err != nil {
		slog.Error("could not promote the renewed credential; the current one is unchanged", "error", err)
		return
	}
	if res.CABundle != "" {
		if err := WriteFileAtomic(a.state.Path(CABundleFile), []byte(res.CABundle), 0o644); err != nil {
			slog.Warn("could not write the renewed CA bundle", "error", err)
		}
	}
	slog.Info("certificate renewed", "not_after", res.NotAfter.Format(time.RFC3339))
}

// bootID returns the kernel's identifier for the current boot.
func bootID() string {
	raw, err := os.ReadFile(BootIDPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// uptimeSeconds returns how long the host has been up.
func uptimeSeconds() int64 {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(raw)), " ")
	seconds, _, _ := strings.Cut(first, ".")
	var n int64
	for _, c := range seconds {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}
