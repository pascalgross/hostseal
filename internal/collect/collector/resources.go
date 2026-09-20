package collector

import (
	"context"

	"github.com/pascalgross/hostseal/internal/collect"
	"github.com/pascalgross/hostseal/internal/policy"
)

// resourcesCollector reports how much of this host's capacity is gone, without a monitoring agent.
//
// It exists because the two questions a fleet tool is asked at three in the morning — "which machine is
// about to run out of disk" and "which one is not keeping up" — were, until now, the two it could not
// answer at all. A unit list says nginx.service is active; it does not say the partition underneath it
// is at ninety-eight per cent, which is the state in which an active nginx stops serving anything.
//
// What it produces is deliberately a snapshot rather than a time series, and README.md's "no metrics
// platform — Prometheus does time series properly" survives this collector intact rather than in spite
// of it. Every volatile figure is banded, so an unchanged host produces byte-identical bytes and the
// digest-first heartbeat in docs/PROTOCOL.md §4.1 keeps doing its job; one value arrives per heartbeat
// and nothing is retained between them. An operator who needs per-second resolution still wants
// Prometheus, and this is the number that tells them which host to point it at.
//
// It reads /proc and calls statfs as the unprivileged hostseal user. No socket, no group, no helper, no
// new intent — the same shape as the containers collector, and docs/SECURITY.md §6 is unchanged by it.
//
// It is a struct rather than a CollectorFunc because it has something to say about the policy, and
// PolicyGated is a method rather than a closure field.
type resourcesCollector struct{}

// init registers the resources collector.
func init() {
	Register(resourcesCollector{})
}

// Name is the key this collector's output appears under in the facts document.
func (resourcesCollector) Name() string { return "resources" }

// Collect reads the host's capacity and use from /proc and statfs.
//
// It never returns an error. Every way the scan can come up short — a Windows host with no /proc, an
// NFS mount whose server is unreachable, a kernel that does not publish MemAvailable — is a fact the
// report itself states, and an error would instead drop the section entirely and tell an operator
// nothing.
func (resourcesCollector) Collect(context.Context) (any, error) {
	return collect.CollectResources(), nil
}

// PermittedBy reports whether the host's local policy allows its capacity to be reported.
//
// Unlike the containers gate, this one is true unless an administrator writes `[resources] report =
// false`, and the asymmetry is argued out on policy.Resources.Report: what a host runs is its owner's
// business, and whether its disk is full is the question the fleet agent was installed to answer. The
// gate exists so that the host still gets the last word.
func (resourcesCollector) PermittedBy(p policy.Policy) bool { return p.Resources.Report }
