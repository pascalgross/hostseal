// Package collect gathers the facts a HostSeal agent reports about its host.
//
// Everything here is read-only and runs as the unprivileged hostseal user with no capabilities. A
// collector that needs root is not a collector; it is a request for a new intent, which is a different
// and much longer conversation.
//
// The package is split into a Platform interface with one implementation per distribution family
// because four differences between Ubuntu and Debian produce **silent wrong answers** rather than
// errors, and a single implementation with a few if-statements is how all four get shipped:
//
//  1. Security-origin patterns differ. Wrong here means the security/regular split is quietly
//     incorrect — the one number the product exists to show.
//  2. /var/run/reboot-required is an Ubuntu update-notifier convention, not a Debian one. Treating the
//     marker as the answer means Debian hosts silently report that no reboot is ever needed.
//  3. Ubuntu Pro and Livepatch do not exist on Debian. Rendering "unknown" rather than "not
//     applicable" puts a permanent amber badge on every Debian host, which teaches operators to ignore
//     the dashboard.
//  4. apt-check ships in update-notifier-common, absent from minimal images of both families. Treating
//     it as the primary source means zero updates reported on exactly the hosts most likely to be
//     forgotten.
//
// Every bound in docs/PROTOCOL.md §4.5 is applied here rather than at the transport, because the reason
// for the bound is the host, not the wire: in multi-tenant hosting, one host filling the database fills
// it for other customers.
package collect

import (
	"context"
	"fmt"

	"github.com/pascalgross/hostseal/internal/policy"
)

// Bounds on what a single host may report, from docs/PROTOCOL.md §4.5.
const (
	// MaxServices caps the units in one report.
	MaxServices = 500

	// MaxPackages caps the upgradable packages listed in one report.
	MaxPackages = 500

	// MaxRebootReasons caps the packages named as requiring a reboot.
	MaxRebootReasons = 100

	// MaxContainers caps the containers listed in one report.
	//
	// Lower than the others because a container row is much wider than a package name and because a
	// host running more than two hundred containers is one whose fleet-level answer is "look at the
	// orchestrator", not "read two thousand rows in a heartbeat".
	MaxContainers = 200

	// MaxFilesystems caps the mounted filesystems listed in one report.
	//
	// Low, because the list is already filtered down to filesystems that can actually fill up, and a
	// host with more than fifty of those is a storage server whose answer is its own tooling rather than
	// a fleet dashboard. The bound is here rather than at the transport for the reason the others are:
	// the mount table on a container host is unbounded — every image layer and every bind mount is a
	// line — so the host has to be the thing that stops counting.
	MaxFilesystems = 50

	// MaxInterfaces caps the network interfaces listed in one report.
	//
	// It bounds both the configuration this agent reports and the traffic counters beside it, and it is
	// the bound that was missing: a Docker host has one veth pair per container, so a machine running
	// two hundred containers has upwards of two hundred interfaces, each carrying up to ten addresses.
	// That is an unbounded list in a document with a one-mebibyte ceiling, which docs/PROTOCOL.md §4.5
	// exists to refuse. Fifty is far above any physical machine and far below the number a container
	// host produces, which is the line worth drawing.
	MaxInterfaces = 50
)

// Family is the distribution family a platform implementation handles.
type Family string

// The distribution families HostSeal supports.
const (
	// FamilyUbuntu covers the Ubuntu LTS releases in standard support.
	FamilyUbuntu Family = "ubuntu"

	// FamilyDebian covers Debian stable and oldstable.
	FamilyDebian Family = "debian"

	// FamilyWindows covers the Windows Server releases in standard support.
	//
	// It is a family beside the two distribution families rather than a second axis, because everything
	// downstream of this value asks the same question of it: which implementation answers for this host.
	// A separate operating-system field would have to be threaded through the wire format, the store and
	// the UI to say something this already says, and every place that forgot would default to Linux.
	FamilyWindows Family = "windows"
)

// Distribution identifies the operating system of a host.
type Distribution struct {
	// ID is the os-release ID field, such as "ubuntu" or "debian".
	ID string `json:"id"`

	// Family is which platform implementation handles this host.
	Family Family `json:"family"`

	// Codename is the release codename, such as "noble" or "bookworm".
	Codename string `json:"codename"`

	// Version is the release version, such as "24.04" or "12".
	Version string `json:"version"`

	// PrettyName is the os-release PRETTY_NAME, for display.
	PrettyName string `json:"prettyName"`

	// Supported reports whether this release is one HostSeal supports.
	//
	// The policy is a rule rather than a list: the Ubuntu LTS releases in standard support, plus Debian
	// stable and oldstable. Ubuntu 20.04 is excluded as ESM-only. An unsupported host still reports —
	// refusing to look at it would make the fleet list lie by omission — but says so.
	Supported bool `json:"supported"`
}

// String renders the distribution for logs and the UI.
func (d Distribution) String() string {
	if d.PrettyName != "" {
		return d.PrettyName
	}
	return fmt.Sprintf("%s %s (%s)", d.ID, d.Version, d.Codename)
}

// Package is one upgradable package.
type Package struct {
	// Name is the binary package name.
	Name string `json:"name"`

	// CurrentVersion is the version installed now, empty for a new dependency being pulled in.
	CurrentVersion string `json:"currentVersion,omitempty"`

	// CandidateVersion is the version that would be installed.
	CandidateVersion string `json:"candidateVersion"`

	// Origins are the apt release strings the candidate comes from, as printed by apt-get.
	Origins []string `json:"origins,omitempty"`

	// Security reports whether any origin is one of this platform's security origins.
	//
	// This one boolean is the number the product exists to show, and it is computed per platform
	// because the origin patterns differ between Ubuntu and Debian in a way that fails silently.
	Security bool `json:"security"`

	// Architecture is the package architecture.
	Architecture string `json:"architecture,omitempty"`
}

// PackageReport summarises pending updates.
type PackageReport struct {
	// UpgradableSecurity is how many pending updates come from a security origin.
	UpgradableSecurity int `json:"upgradableSecurity"`

	// UpgradableTotal is how many updates are pending in total.
	UpgradableTotal int `json:"upgradableTotal"`

	// Packages is the list, truncated to MaxPackages.
	Packages []Package `json:"packages,omitempty"`

	// Truncated reports that the list was cut short, so a reader knows the counts and the list
	// disagree on purpose rather than by a bug.
	Truncated bool `json:"truncated,omitempty"`

	// Incomplete reports that the package list could not be gathered at all.
	//
	// It exists because the zero value of this struct is indistinguishable from a genuine answer, and
	// the two mean opposite things. A host whose apt lock was held — the case Gather explicitly
	// anticipates and logs — sends `upgradableSecurity: 0` exactly as a freshly-patched host does, so
	// without this a reader has to treat "nobody could look" as "nothing to find". That is the
	// direction a fleet-health reader must never be wrong in, and it is the same distinction
	// RebootReport.Conclusive draws for the reboot question and ContainerReport.ScanComplete for
	// containers.
	//
	// Negative and omitempty, unlike those two, and the asymmetry is deliberate rather than untidy.
	// They have always been on the wire, so an absent value means an agent that predates nothing. This
	// field is new, so an absent value means an agent that has not been upgraded yet — and a positive
	// spelling would make every host in every existing fleet report as unmeasured on the day the
	// control plane is updated. Absent therefore has to mean "this agent did not say", which is the
	// truth about an old agent, and the flag says the one thing a new agent knows and an old one
	// cannot.
	Incomplete bool `json:"incomplete,omitempty"`
}

// RebootReport is whether the host needs a reboot, and what still runs replaced libraries.
type RebootReport struct {
	// Required reports whether a reboot is needed.
	Required bool `json:"required"`

	// Reasons names the packages that require it, truncated to MaxRebootReasons.
	Reasons []string `json:"reasons,omitempty"`

	// ReasonsTruncated reports that the list was cut short.
	//
	// docs/PROTOCOL.md §4.5 requires a flag on any section the agent bounds, and this one was bounded
	// silently. A reader seeing exactly a hundred reasons should know whether that is the number or the
	// limit.
	ReasonsTruncated bool `json:"reasonsTruncated,omitempty"`

	// Services lists units that needrestart says still hold replaced libraries.
	//
	// This is the more actionable half and the one most update dashboards skip: "which running
	// services still hold the old OpenSSL" is a question an operator can act on this afternoon,
	// whereas "a reboot is required" is one they will schedule for a fortnight's time.
	Services []string `json:"services,omitempty"`

	// ServiceScanComplete reports whether the needrestart scan could see every process.
	//
	// needrestart only sees processes the calling user owns, and the agent is deliberately
	// unprivileged. An incomplete scan is reported as incomplete rather than presented as a clean
	// bill of health, because "no services need restarting" and "I could not see the services that
	// do" must not look the same in the UI.
	ServiceScanComplete bool `json:"serviceScanComplete"`

	// Conclusive reports whether anything on this host was able to answer the question at all.
	//
	// It exists for the same reason ServiceScanComplete does, one level up: "no reboot is needed" and
	// "nothing here can tell me whether one is needed" are different answers that produce the same
	// Required=false, and on a Debian host without needrestart the second is the common one — the
	// marker file is an Ubuntu update-notifier convention rather than a standard, and needrestart is a
	// Recommends. Without this field the distinction survives only in Source, as prose, which no caller
	// can act on.
	//
	// It has no omitempty deliberately. An inconclusive answer is exactly the case worth seeing, and
	// with omitempty it would be the one that vanished from the wire.
	Conclusive bool `json:"conclusive"`

	// Source describes where the answer came from, for the UI and for debugging a wrong answer.
	Source string `json:"source,omitempty"`
}

// Subscription is Ubuntu Pro and Livepatch state.
type Subscription struct {
	// Applicable reports whether the concept exists on this host at all.
	//
	// It is false on Debian, and clients must render that as "not applicable" rather than "unknown" or
	// an empty amber badge. A Debian host with a permanent ESM warning teaches people to ignore the
	// dashboard, which costs more than the warning was ever worth.
	Applicable bool `json:"applicable"`

	// Attached reports whether the host is attached to a subscription.
	Attached bool `json:"attached"`

	// Services maps Ubuntu Pro service names to their status.
	Services map[string]string `json:"services,omitempty"`

	// Note explains an absent or unreadable answer in words, for the UI.
	Note string `json:"note,omitempty"`
}

// Unit is one systemd unit's state.
type Unit struct {
	// Name is the unit name, such as "nginx.service".
	Name string `json:"name"`

	// Description is the unit's own description.
	Description string `json:"description,omitempty"`

	// LoadState is systemd's load state: loaded, not-found, masked.
	LoadState string `json:"loadState"`

	// ActiveState is systemd's active state: active, inactive, failed.
	ActiveState string `json:"activeState"`

	// SubState is systemd's finer-grained state: running, exited, dead.
	SubState string `json:"subState"`
}

// Facts is everything an agent reports about its host.
//
// The field names and shapes match docs/PROTOCOL.md §4.2 exactly. Where they drift, the document is the
// specification and this is the bug.
type Facts struct {
	// Hostname is the host's own name.
	Hostname string `json:"hostname"`

	// Distribution identifies the operating system.
	Distribution Distribution `json:"distribution"`

	// Kernel is the running kernel release.
	Kernel string `json:"kernel"`

	// Architecture is the machine architecture.
	Architecture string `json:"architecture"`

	// Reboot is whether a reboot is needed and what still runs replaced libraries.
	Reboot RebootReport `json:"reboot"`

	// Subscription is Ubuntu Pro state, or a not-applicable marker on Debian.
	Subscription Subscription `json:"subscription"`

	// Packages summarises pending updates.
	Packages PackageReport `json:"packages"`

	// Services is systemd unit state, truncated to MaxServices.
	Services []Unit `json:"services,omitempty"`

	// ServicesTruncated reports that the unit list was cut short.
	ServicesTruncated bool `json:"servicesTruncated,omitempty"`

	// Extra holds the output of registered Collectors, keyed by collector name.
	//
	// It is a map rather than named fields because that is what makes the seam a seam: adding a fact
	// means adding a collector and nothing else. A collector that failed leaves its key absent and its
	// reason in the journal.
	Extra map[string]any `json:"extra,omitempty"`
}

// Platform is the per-distribution-family behaviour fact collection depends on.
//
// Adding a family means adding an implementation and registering it, never editing a switch. Any change
// that requires modifying a type switch in this package is a missing seam and a legitimate bug report.
//
// An implementation must state, in its own doc comment, what it does about each of the four
// silent-wrong-answer traps listed in this package's documentation. All four fail quietly rather than
// loudly, so "it worked on my machine" does not detect them.
type Platform interface {
	// Identify reports which distribution this is.
	Identify() (Distribution, error)

	// UpgradablePackages lists pending updates with the security ones marked.
	UpgradablePackages(ctx context.Context) ([]Package, error)

	// Services reports the state of the host's service manager, and whether the list was truncated.
	//
	// It is on the seam rather than a package-level function because the two answers are not the same
	// question asked twice: systemd unit state comes over D-Bus and Windows service state comes from
	// the SCM, and they share nothing but the shape of the result. Gather used to call ListUnits
	// directly, which this package's own documentation called a missing seam and a legitimate bug
	// report — the type switch it would otherwise need in Gather is exactly what the seam exists to
	// prevent.
	Services(ctx context.Context) ([]Unit, bool, error)

	// KernelRelease returns the running kernel or operating-system build, or "unknown".
	//
	// It never fails, for the reason hostname() never fails: a heartbeat carrying an odd version string
	// is worth far more than no heartbeat, and the host is identified by its certificate rather than by
	// this value. It is on the seam because the Linux answer is a file under /proc and the Windows
	// answer is a registry build number, and a package-level function reading /proc would return
	// "unknown" for every Windows host for ever — a silent wrong answer of exactly the class this
	// interface exists to name.
	KernelRelease() string

	// SecurityOrigins returns the unattended-upgrades origin patterns for this family.
	//
	// It is informational: the security classification is done inside UpgradablePackages, because the
	// two families need genuinely different matching rather than the same rule with different strings.
	// This exists so the UI and generated unattended-upgrades configuration can show an operator which
	// origins a host treats as security, which is the setting people most often get wrong by hand.
	SecurityOrigins() []string

	// RebootRequired reports whether the host needs a reboot and why.
	RebootRequired(ctx context.Context) (RebootReport, error)

	// SubscriptionStatus reports Ubuntu Pro state, or nil where the concept does not exist.
	//
	// nil means "not applicable" and must be rendered as such. Returning a zero-valued struct instead
	// would make Debian indistinguishable from an Ubuntu host whose status could not be read.
	SubscriptionStatus(ctx context.Context) (*Subscription, error)
}

// PolicyGatedPackages is the optional half of the Platform seam, for a platform whose package
// enumeration is itself expensive or privileged.
//
// It is the same shape as PolicyGated one level up, and it exists for a reason that only appeared with
// the second operating system. On Linux, listing pending updates is `apt-get --just-print`: local,
// milliseconds, changes nothing — so no host has ever needed a way to refuse it, and Gather calls it
// unconditionally. On Windows the same question is a Windows Update scan that goes to the network,
// mutates state under %windir% and takes minutes. That is privileged work wearing a read class, and
// docs/SECURITY.md's own rule for adding an intent applies to it: every privileged operation must be
// refusable locally, or the guarantee is no longer true.
//
// A platform that does not implement it is asked nothing and behaves exactly as before, which is what
// keeps this from being a change to the Linux agent.
//
// The reason is returned as well as the verdict so that the refusal reaches an operator as a sentence
// rather than as a gap. A report marked incomplete with no explanation is the same shape of problem as
// a report of zero pending updates on a host nobody could scan.
type PolicyGatedPackages interface {
	// PackagesPermittedBy reports whether local policy allows this host to enumerate its updates, and
	// why not where it does not.
	PackagesPermittedBy(p policy.Policy) (bool, string)
}
