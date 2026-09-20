package collector

import (
	"context"
	"testing"

	"github.com/pascalgross/hostseal/internal/collect"
	"github.com/pascalgross/hostseal/internal/policy"
)

// resources returns the registered resources collector.
//
// Looked up through All rather than constructed, for the reason the containers helper is: the thing
// worth asserting is that the registered collector behaves this way, and a second instance built in the
// test would prove nothing about the one that runs on a host.
func resources(t *testing.T) collect.Collector {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "resources" {
			return c
		}
	}
	t.Fatal("no collector is registered as \"resources\"")
	return nil
}

// TestTheResourceSectionIsOnUntilAHostOptsOut is the shipped default, asserted rather than assumed.
//
// It is the opposite default from the containers gate beside it, and both are deliberate, so both are
// pinned: a change that flipped either would otherwise be a one-word diff nobody caught. A disk at
// ninety-eight per cent is the fleet health somebody installed this agent to see, and a host that wants
// to keep its filesystem layout to itself says so.
func TestTheResourceSectionIsOnUntilAHostOptsOut(t *testing.T) {
	gated, ok := resources(t).(collect.PolicyGated)
	if !ok {
		t.Fatal("the resources collector is not policy-gated, so no host can decline to report capacity")
	}

	if !gated.PermittedBy(policy.Default()) {
		t.Error("the built-in default does not report capacity, so an ordinary host sends nothing")
	}
	if gated.PermittedBy(policy.Closed()) {
		t.Error("a host whose policy could not be read reports its capacity; a policy that failed to " +
			"load must disclose less, not more")
	}

	opted, err := policy.Parse([]byte("[resources]\nreport = false\n"))
	if err != nil {
		t.Fatalf("parsing a policy that opts out: %v", err)
	}
	if gated.PermittedBy(opted) {
		t.Error("a host that wrote report = false reports its capacity anyway")
	}

	// A policy file written before this key existed must keep the shipped default rather than falling to
	// a zero value, which is what Parse decoding over Default buys. Without it every host in an existing
	// fleet would go quiet on the day its agent was upgraded.
	silent, err := policy.Parse([]byte("[updates]\nallow = \"security\"\n"))
	if err != nil {
		t.Fatalf("parsing a policy that predates the key: %v", err)
	}
	if !gated.PermittedBy(silent) {
		t.Error("a policy file that does not mention the key switches capacity reporting off")
	}
}

// TestTheResourceCollectorAnswersWhereverTheTestsRun covers the machine this runs on.
//
// TestTheShippedCollectorsRun executes every registered collector for real, so this one has to return a
// usable, non-nil section wherever the tests happen to run — a laptop, a CI runner in a container with a
// mount table nothing like a server's, a Windows builder with no /proc at all. Every way the scan can
// come up short is a fact the report itself states, and an error would drop the section, which tells an
// operator nothing.
func TestTheResourceCollectorAnswersWhereverTheTestsRun(t *testing.T) {
	section, err := resources(t).Collect(context.Background())
	if err != nil {
		t.Fatalf("the resources collector returned an error rather than a report: %v", err)
	}
	report, ok := section.(collect.ResourceReport)
	if !ok {
		t.Fatalf("the section is %T, not a collect.ResourceReport", section)
	}
	if report.Filesystems == nil || report.Interfaces == nil {
		// Nil encodes as null rather than as [], and "I looked and found none" must not encode the same
		// way as "this section was not produced".
		t.Error("the lists are nil rather than empty")
	}
	if !report.ScanComplete && report.Note == "" {
		t.Error("an incomplete scan says nothing about what it could not read")
	}
}
