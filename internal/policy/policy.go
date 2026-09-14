// Package policy parses and evaluates /etc/hostseal/policy.toml, the file a host uses to bound what the
// control plane may ask of it.
//
// It is the second of the three mechanisms behind docs/SECURITY.md §1. The rule it implements is one
// line — effective permission is min(central request, local policy), never the max — and the reason
// this package exists separately from the agent is where that rule has to run. The agent's own check
// saves a round trip and produces a better error message; the check that matters runs as root inside
// the helpers in helpers/, re-reading the root-owned file from disk, because that is what keeps the
// guarantee true when the agent process itself is compromised.
//
// Two consequences shape the API. Load always returns a usable Policy, falling closed on any parse
// error, because a host whose policy file is unreadable must refuse privileged work rather than run
// unbounded. And Decide takes the current time explicitly rather than calling time.Now, so that
// maintenance-window behaviour is testable without waiting for Sunday.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Allow is how far a host will go in applying package updates.
//
// The three values are ordered, and that ordering is the whole of the clamping rule: the effective
// permission for a job is the lower of what the control plane asked for and what the host allows.
type Allow string

// The update permission levels, in increasing order of what they permit.
const (
	// AllowNone refuses every update application, from anyone, in any role.
	AllowNone Allow = "none"

	// AllowSecurity permits updates from the distribution's security origins only.
	AllowSecurity Allow = "security"

	// AllowAll permits every available update.
	AllowAll Allow = "all"
)

// rank returns the ordering position of an update permission level.
//
// It exists so that Min below is a comparison rather than a nested switch, and so that an unrecognised
// value ranks below AllowNone and therefore clamps everything to nothing. Failing closed on a typo in
// a hand-edited file is the only acceptable behaviour for this particular field.
func (a Allow) rank() int {
	switch a {
	case AllowNone:
		return 0
	case AllowSecurity:
		return 1
	case AllowAll:
		return 2
	default:
		return -1
	}
}

// Valid reports whether the value is one of the three defined levels.
func (a Allow) Valid() bool { return a.rank() >= 0 }

// Min returns the lower of two update permission levels.
//
// This one function is the entire "never the max" rule from docs/SECURITY.md §2.2. It is exported and
// separately tested because every privileged path in the agent and in the helpers must go through it,
// and a second implementation of the same comparison somewhere else is precisely how a rule like this
// stops being true.
func Min(a, b Allow) Allow {
	if b.rank() < a.rank() {
		a = b
	}
	if !a.Valid() {
		return AllowNone
	}
	return a
}

// RebootMode is whether and when a host will reboot on request.
type RebootMode string

// The reboot modes. There is deliberately no "always": a reboot outside a window is a reboot during
// business hours, and a host that permits that has no maintenance window at all.
const (
	// RebootNever refuses every reboot request.
	RebootNever RebootMode = "never"

	// RebootWindow permits a reboot only inside the configured maintenance window.
	RebootWindow RebootMode = "window"
)

// Valid reports whether the value is one of the defined modes.
func (r RebootMode) Valid() bool { return r == RebootNever || r == RebootWindow }

// Updates is the [updates] section of the policy file.
type Updates struct {
	// Allow is how far this host will go in applying updates.
	Allow Allow `toml:"allow"`

	// AutoApply is whether the host applies permitted updates on its own timer.
	//
	// It is separate from Allow because the two answer different questions. Allow bounds what the
	// control plane may ask for; AutoApply decides whether the host also does it unprompted, which is
	// what keeps a fleet patched through a control-plane outage.
	//
	// **HostSeal still does not implement it.** The timer that applies updates unprompted is
	// unattended-upgrades', configured by the distribution and not by HostSeal, so this setting is
	// reported to the control plane and acted on by nothing. It is in the file from the first release
	// because it belongs there, and because adding a policy key later means every host in a fleet has a
	// policy file older than the software reading it.
	//
	// Making it real means writing /etc/apt/apt.conf.d on the host, and that is a larger decision than
	// it looks. HostSeal deliberately configures nothing about the host's own apt — the fragment the
	// update helper uses is named by APT_CONFIG for one invocation, precisely so that it changes
	// nothing for anything else — and there is no intent that writes a file, no helper that could own
	// one, and docs/EXTENDING.md rules out a fourth. So it waits for a design rather than for an
	// afternoon.
	AutoApply bool `toml:"auto_apply"`

	// Scan is whether this host will enumerate its pending updates when asked.
	//
	// It exists because on Windows the question is not free. `apt-get --just-print` is local, takes
	// milliseconds and changes nothing, so no Linux host has ever needed a way to refuse it. A Windows
	// Update scan goes to the network, mutates %windir%\SoftwareDistribution and takes minutes — which
	// makes it privileged work wearing a read class, and docs/SECURITY.md's own rule for adding an
	// intent applies: every privileged operation must be refusable locally, or the guarantee is no
	// longer true. Without this key a control plane holding nothing but mTLS could drive every Windows
	// host into a continuous scan loop, and the host would have been given no policy to exceed.
	//
	// It bounds the *scan*, not the applying — Allow does that, and the two are independent. A host with
	// allow = "none" still has every reason to report what is pending; refusing to apply an update and
	// refusing to look at it are different decisions.
	//
	// The shipped default is true, which is the opposite of [containers] report and for a defensible
	// reason: a container name describes what a business runs, and is a disclosure a host has not agreed
	// to make. A count of missing patches is the number this product exists to show, and an operator who
	// installs a fleet agent has asked for it. What the key buys them is a way to say no on the hosts
	// where the cost is not worth it.
	//
	// It has no effect on Linux. Reporting it on every host anyway is deliberate: a fleet is mixed, and
	// a key that appeared only in Windows policy files would be one an operator meets for the first time
	// during an incident.
	Scan bool `toml:"scan"`

	// Window is the maintenance window, empty meaning any time.
	Window string `toml:"window"`

	// Timezone is the IANA zone the window is expressed in.
	//
	// It is explicit rather than inherited from the host because a fleet spanning regions has hosts
	// whose local time is not the time the operator means, and "03:00" silently meaning two different
	// hours on two hosts is the kind of thing discovered during the outage rather than before it.
	Timezone string `toml:"timezone"`

	// Reboot is whether and when this host will reboot on request.
	Reboot RebootMode `toml:"reboot"`
}

// Services is the [services] section of the policy file.
type Services struct {
	// Restartable lists the units this host will start, stop or restart on request.
	//
	// Entries are matched with shell-style globbing so that a fleet-wide policy can name
	// "hostseal-*.service" without enumerating instances. The list is empty in the shipped default:
	// like trusted-signers, a fresh host permits nothing until an administrator says otherwise.
	Restartable []string `toml:"restartable"`

	// Watched lists the units whose state changes this host considers worth an event, with the same
	// shell-style globbing as Restartable.
	//
	// It lives here, in the host's file, because which units matter is a per-host question: the
	// machine's owner knows that nginx.service matters and motd-news.timer does not, and the control
	// plane can at most read what they wrote down. The empty default means everything — a fresh host
	// should surface a failed unit rather than hide it behind a setting nobody has heard of — and a
	// host that wants quiet, or that one day wants to report only these units, writes the list. It
	// bounds what the control plane says about this host, never what may be done to it, which is why
	// widening it is not a permission change.
	Watched []string `toml:"watched"`
}

// Containers is the [containers] section of the policy file.
type Containers struct {
	// Report is whether this host reports the containers running on it.
	//
	// It ships false, in the same spirit as trusted-signers shipping empty: a fresh host does the
	// least revealing thing until an administrator decides otherwise. Container state is a genuinely
	// different disclosure from a unit list — names describe what a business runs, image tags leak
	// internal registry hostnames, and command lines have a long history of carrying credentials — and
	// a host that agreed to report its package state has not thereby agreed to report that. HostSeal's
	// own collector reports an executable name rather than a command line for exactly that reason, but
	// the host still gets to say no.
	//
	// It bounds what this host *says*, never what may be done to it, so turning it on is not a
	// permission change and no signature is involved. Note that the resource figures under it change
	// on every collection, so a host that turns it on sends a full report on every heartbeat rather
	// than a digest.
	Report bool `toml:"report"`
}

// Resources is the [resources] section of the policy file.
type Resources struct {
	// Report is whether this host reports its capacity and how much of it is in use.
	//
	// It ships **true**, which is the opposite of [containers] report, and the difference is the same
	// one [updates] scan draws. A container name describes what a business runs and is a disclosure a
	// host has not agreed to make; a disk that is about to fill up is the kind of fleet health an
	// operator who installed a fleet agent has asked about. What this key buys them is a way to say no
	// on the hosts where the answer is nobody else's business.
	//
	// It is gated at all for two reasons that outlive the default. The first is docs/EXTENDING.md's
	// rule, which is that a section a host might reasonably decline gets a way to decline it — and mount
	// points are host filesystem layout, which internal/collect/containers.go refuses to disclose as a
	// side effect of asking a different question. The second is bandwidth: every figure in the section is
	// banded so that an unchanged host produces an unchanged digest, but a host that is genuinely busy
	// crosses a band often, and an operator on a metered link gets to stop paying for that.
	//
	// It bounds what this host *says*, never what may be done to it, so turning it off is not a
	// permission change and no signature is involved.
	Report bool `toml:"report"`
}

// Limits is the [limits] section of the policy file.
type Limits struct {
	// MaxJobAgeSeconds is how long after issue a job may still be executed.
	//
	// It bounds the damage of a job that sat in a queue across an outage: a restart signed on Tuesday
	// should not execute on Friday because the agent was offline in between. It is enforced locally so
	// that it holds even when the control plane is the thing that went wrong.
	MaxJobAgeSeconds int `toml:"max_job_age_seconds"`
}

// Policy is a parsed and validated /etc/hostseal/policy.toml.
//
// It is a value type with no pointers into the file it came from, so a helper can load it, use it and
// let it go without worrying about aliasing. Loading is cheap and happens per invocation on purpose:
// the helper must act on what the file says now, not on what it said when some long-running process
// started.
type Policy struct {
	// Updates bounds package update application.
	Updates Updates `toml:"updates"`

	// Services bounds which units may be acted on.
	Services Services `toml:"services"`

	// Containers bounds what this host says about the containers running on it.
	Containers Containers `toml:"containers"`

	// Resources bounds what this host says about its capacity and how much of it is in use.
	Resources Resources `toml:"resources"`

	// Limits bounds job age.
	Limits Limits `toml:"limits"`

	// window is the parsed form of Updates.Window, resolved against Updates.Timezone.
	window Window

	// source records where this policy was loaded from, for error messages.
	source string
}

// Default returns the policy a host uses when no file has been read.
//
// The defaults are deliberately the most restrictive ones that still leave the product useful: security
// updates only, no automatic reboot, and nothing restartable. That matches the shipped policy.toml and
// the empty trusted-signers file — a freshly installed agent should be able to report on a host and to
// keep it patched, and should be able to do nothing else until somebody decides otherwise.
func Default() Policy {
	p := Policy{
		Updates: Updates{
			Allow:     AllowSecurity,
			AutoApply: true,
			// True, and it survives an absent key because Parse decodes over Default rather than into a
			// zero value — so a policy file written before this key existed keeps reporting updates
			// instead of silently going quiet on every host in an existing fleet.
			Scan:     true,
			Window:   "",
			Timezone: "UTC",
			Reboot:   RebootNever,
		},
		Services: Services{Restartable: nil},
		// Written out rather than left to the zero value, because a default that matters is one a
		// reader should be able to find by looking at the defaults.
		Containers: Containers{Report: false},
		// True, and written out beside the false above so that the two sit where a reader compares
		// them. It also survives an absent key, because Parse decodes over Default rather than into a
		// zero value — so a policy file written before this key existed keeps reporting capacity
		// instead of going quiet on every host in an existing fleet the day the agent is upgraded.
		Resources: Resources{Report: true},
		Limits:    Limits{MaxJobAgeSeconds: 900},
		source:    "built-in default",
	}
	// Validated rather than hand-assembled, so the derived window matches the string beside it. A
	// zero-valued Window reports itself closed at every instant while Updates.Window says "always",
	// and the two disagreeing would be a policy whose behaviour did not match its own display.
	if err := p.validate(); err != nil {
		panic("policy: the built-in default does not validate: " + err.Error())
	}
	return p
}

// Closed returns the policy a host uses when its policy file cannot be trusted.
//
// It permits nothing at all. Load returns it alongside an error when the file exists but does not
// parse, because the alternative — carrying on with the built-in default — would mean a syntax error
// in a hand-edited file silently widened what a host accepts. Failing closed makes that a visible
// outage instead of an invisible one.
func Closed() Policy {
	p := Policy{
		// Scan is false here, unlike in Default. A host whose policy file does not parse has said
		// nothing about what it permits, and an update scan is minutes of work and a network
		// conversation — so the closed policy declines it along with everything else.
		Updates:    Updates{Allow: AllowNone, AutoApply: false, Scan: false, Timezone: "UTC", Reboot: RebootNever},
		Containers: Containers{Report: false},
		// False here although it is true in Default, which is the same asymmetry Scan carries one line
		// up and for the same reason: a host whose policy file does not parse has said nothing about
		// what it discloses, and the closed policy declines on its behalf rather than on its default.
		Resources: Resources{Report: false},
		Limits:    Limits{MaxJobAgeSeconds: 900},
		source:    "closed (policy could not be loaded)",
	}
	if err := p.validate(); err != nil {
		panic("policy: the closed policy does not validate: " + err.Error())
	}
	return p
}

// Source describes where the policy came from, for logs and error messages.
func (p Policy) Source() string { return p.source }

// Window returns the parsed maintenance window.
func (p Policy) Window() Window { return p.window }

// ErrNoPolicyFile reports that no policy file exists at the expected path.
//
// It is distinguished from a parse failure because the two mean opposite things: a missing file is a
// host that has not been configured, which takes the built-in default; an unparseable file is a host
// whose administrator meant something the agent could not read, which takes the closed policy.
var ErrNoPolicyFile = errors.New("policy: no policy file")

// Load reads and validates the policy at Path.
//
// It always returns a usable Policy. On a missing file it returns Default and ErrNoPolicyFile; on any
// other failure it returns Closed and the error. Callers are expected to log the error and carry on
// with the returned policy rather than to treat it as fatal, because an agent that exits on a bad
// policy file is an agent that stops reporting on the host that most needs looking at.
func Load() (Policy, error) { return LoadFrom(Path) }

// LoadFrom reads and validates a policy from an explicit path.
//
// It exists so that tests and `hostseal-agent policy check` exercise the same code as production rather
// than a parallel implementation that happens to agree today.
//
// The root helpers deliberately do not expose it. A helper that took a policy path from its command
// line would be one a compromised agent could point at a file it had just written — the sudoers entry
// pins the program and not its arguments, and the agent can write /var/lib/hostseal — so the enforcement
// would still run as root, against exactly the policy the attacker chose.
func LoadFrom(path string) (Policy, error) {
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		p := Default()
		p.source = fmt.Sprintf("%s (absent)", path)
		return p, fmt.Errorf("%w at %s", ErrNoPolicyFile, path)
	case err != nil:
		return Closed(), fmt.Errorf("policy: reading %s: %w", path, err)
	}
	p, err := Parse(raw)
	if err != nil {
		return Closed(), fmt.Errorf("policy: parsing %s: %w", path, err)
	}
	p.source = path
	return p, nil
}

// Parse decodes and validates policy TOML.
//
// Unknown keys are rejected rather than ignored. A policy file is edited by hand under time pressure,
// and "allow_updates = all" silently doing nothing while the operator believes it took effect is worse
// than an error at load, which is at least visible in the journal before anything depends on it.
func Parse(raw []byte) (Policy, error) {
	p := Default()
	md, err := toml.Decode(string(raw), &p)
	if err != nil {
		return Closed(), err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return Closed(), fmt.Errorf("unknown key(s): %s", strings.Join(keys, ", "))
	}
	if err := p.validate(); err != nil {
		return Closed(), err
	}
	return p, nil
}

// validate checks a decoded policy and resolves its derived fields.
//
// It resolves the maintenance window here, at load, rather than at each evaluation, so that a
// misspelled timezone or an unparseable window is an error the administrator sees when the file is
// read — not a silent refusal at 03:00 on the one night the window mattered.
func (p *Policy) validate() error {
	if !p.Updates.Allow.Valid() {
		return fmt.Errorf("updates.allow: %q is not one of none, security, all", p.Updates.Allow)
	}
	if !p.Updates.Reboot.Valid() {
		return fmt.Errorf("updates.reboot: %q is not one of never, window", p.Updates.Reboot)
	}
	// "window" with no window configured would mean "reboot at any time", because an empty window is
	// always open. That is not what anybody writing `reboot = "window"` meant, and it is the kind of
	// trap that is discovered by a host rebooting at eleven in the morning. There is deliberately no
	// `reboot = "always"`, so the only way to say it is to say it in the window.
	if p.Updates.Reboot == RebootWindow && strings.TrimSpace(p.Updates.Window) == "" {
		return errors.New(`updates.reboot = "window" requires updates.window to be set; ` +
			`an empty window is always open, which would permit a reboot at any time`)
	}
	if p.Updates.Timezone == "" {
		p.Updates.Timezone = "UTC"
	}
	loc, err := time.LoadLocation(p.Updates.Timezone)
	if err != nil {
		return fmt.Errorf("updates.timezone: %w", err)
	}
	w, err := ParseWindow(p.Updates.Window, loc)
	if err != nil {
		return fmt.Errorf("updates.window: %w", err)
	}
	p.window = w

	if p.Limits.MaxJobAgeSeconds <= 0 {
		return fmt.Errorf("limits.max_job_age_seconds: %d must be positive", p.Limits.MaxJobAgeSeconds)
	}
	for _, pattern := range p.Services.Restartable {
		if _, err := filepath.Match(pattern, "probe.service"); err != nil {
			return fmt.Errorf("services.restartable: %q is not a valid pattern: %w", pattern, err)
		}
	}
	for _, pattern := range p.Services.Watched {
		if _, err := filepath.Match(pattern, "probe.service"); err != nil {
			return fmt.Errorf("services.watched: %q is not a valid pattern: %w", pattern, err)
		}
	}
	return nil
}

// Paused reports whether a local administrator has stopped this host from acting on jobs.
//
// It is checked on every privileged evaluation rather than cached, because the point of the marker is
// that creating it takes effect immediately and without the agent's cooperation.
func Paused() bool { return pausedAt(PausedPath) }

// pausedAt reports whether the marker file exists at an explicit path.
func pausedAt(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// RestartableAllows reports whether a unit name is on the restartable list.
//
// Matching is by shell-style glob so a policy can name "hostseal-*.service" without enumerating
// instances. An empty list matches nothing, which is the shipped default: a host permits no service
// operations at all until an administrator writes down which ones it permits.
func (p Policy) RestartableAllows(unit string) bool {
	for _, pattern := range p.Services.Restartable {
		if ok, err := filepath.Match(pattern, unit); err == nil && ok {
			return true
		}
	}
	return false
}
