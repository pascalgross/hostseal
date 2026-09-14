package collector

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/pascalgross/hostseal/internal/collect"
)

// noAddresses is the address lookup for a test that is not about addresses.
//
// An empty result rather than an error, because the two take different branches and a test asserting
// something else should take the ordinary one.
func noAddresses(net.Interface) ([]net.Addr, error) { return nil, nil }

// addr is a net.Addr built from a string, for handing fixed addresses to describeInterfaces.
//
// net.Addr is an interface and every concrete implementation in the standard library parses something,
// so the shortest way to a fixture is a two-method type. It exists because the reported field is
// addr.String() and nothing else about the address is read.
type addr string

// Network names the address family, which this collector never reads.
func (addr) Network() string { return "ip+net" }

// String renders the address, which is the only thing the collector reports.
func (a addr) String() string { return string(a) }

// TestHardwareAddressesAreReported covers the decision this collector reversed.
//
// Until this version the doc comment said hardware addresses were deliberately absent. They are the only
// thing in this report that identifies a machine to something outside HostSeal — a DHCP lease, a switch
// port, a hypervisor's NIC — so the field is pinned here rather than left to be quietly dropped by
// somebody reading the old rationale in a diff.
func TestHardwareAddressesAreReported(t *testing.T) {
	mac, err := net.ParseMAC("52:54:00:12:34:56")
	if err != nil {
		t.Fatal(err)
	}
	out, truncated := describeInterfaces([]net.Interface{
		{Name: "eth0", MTU: 1500, Flags: net.FlagUp, HardwareAddr: mac},
		{Name: "tun0", MTU: 1400, Flags: net.FlagUp | net.FlagPointToPoint},
	}, noAddresses)

	if truncated {
		t.Error("a two-interface host reports its list as truncated")
	}
	if len(out) != 2 {
		t.Fatalf("reported %d interfaces, want 2: %+v", len(out), out)
	}
	if out[0].HardwareAddress != "52:54:00:12:34:56" {
		t.Errorf("eth0's hardwareAddress is %q, want 52:54:00:12:34:56", out[0].HardwareAddress)
	}

	// A tunnel genuinely has no hardware address, and the field is absent rather than empty: "" would be
	// a claim about the hardware rather than an admission that there is none.
	raw, err := json.Marshal(out[1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hardwareAddress") {
		t.Errorf("an interface with no hardware address carries the field anyway: %s", raw)
	}
}

// TestTheLoopbackInterfaceIsNotReported covers the one interface every host has and nobody needs.
func TestTheLoopbackInterfaceIsNotReported(t *testing.T) {
	out, _ := describeInterfaces([]net.Interface{
		{Name: "lo", MTU: 65536, Flags: net.FlagUp | net.FlagLoopback},
		{Name: "eth0", MTU: 1500, Flags: net.FlagUp},
	}, noAddresses)

	if len(out) != 1 || out[0].Name != "eth0" {
		t.Errorf("reported %+v, want eth0 alone", out)
	}
}

// TestAddressesAreSortedThenCut covers the order of the two operations.
//
// Sorted first, so that a host over the cap reports the same ten addresses on every heartbeat rather
// than a different ten each time — which would change the facts digest for no reason at all and put the
// host into a full report on every beat.
func TestAddressesAreSortedThenCut(t *testing.T) {
	var many []net.Addr
	for i := maxAddresses + 5; i > 0; i-- {
		many = append(many, addr(fmt.Sprintf("10.0.%03d.1/24", i)))
	}
	out, _ := describeInterfaces([]net.Interface{{Name: "eth0", MTU: 1500, Flags: net.FlagUp}},
		func(net.Interface) ([]net.Addr, error) { return many, nil })

	if len(out) != 1 {
		t.Fatalf("reported %d interfaces, want 1", len(out))
	}
	if got := len(out[0].Addresses); got != maxAddresses {
		t.Fatalf("reported %d addresses, want the cap of %d", got, maxAddresses)
	}
	if !out[0].AddressesTruncated {
		t.Error("a cut address list is not flagged as truncated")
	}
	if out[0].Addresses[0] != "10.0.001.1/24" {
		t.Errorf("the surviving addresses start at %q, so the cut came before the sort",
			out[0].Addresses[0])
	}
}

// TestInterfacesAreBoundedAndSaySo covers the cap that was missing until this version.
//
// A Docker host has one veth pair per container, so a machine running two hundred containers put two
// hundred interfaces and up to two thousand addresses into a document with a one-mebibyte ceiling.
// docs/PROTOCOL.md §4.5 requires a bound on any section the agent can grow without limit, and a reader
// seeing exactly fifty interfaces must be able to tell the number from the limit.
func TestInterfacesAreBoundedAndSaySo(t *testing.T) {
	var many []net.Interface
	for i := collect.MaxInterfaces + 9; i > 0; i-- {
		many = append(many, net.Interface{Name: fmt.Sprintf("veth%03d", i), MTU: 1500, Flags: net.FlagUp})
	}
	out, truncated := describeInterfaces(many, noAddresses)

	if len(out) != collect.MaxInterfaces {
		t.Errorf("reported %d interfaces, want the cap of %d", len(out), collect.MaxInterfaces)
	}
	if !truncated {
		t.Error("a cut interface list is not flagged as truncated")
	}
	if out[0].Name != "veth001" {
		t.Errorf("the surviving interfaces start at %q, so the cut came before the sort", out[0].Name)
	}
}

// TestAnInterfaceWhoseAddressesCannotBeReadIsStillReported covers the partial answer.
//
// The interface itself — its name, its MTU, whether it is up, its hardware address — is worth reporting
// even when the address lookup fails, and dropping the whole row would make an interface disappear from
// a host that has it.
func TestAnInterfaceWhoseAddressesCannotBeReadIsStillReported(t *testing.T) {
	out, _ := describeInterfaces([]net.Interface{{Name: "eth0", MTU: 1500, Flags: net.FlagUp}},
		func(net.Interface) ([]net.Addr, error) { return nil, fmt.Errorf("netlink refused") })

	if len(out) != 1 || out[0].Name != "eth0" {
		t.Fatalf("reported %+v, want eth0 with no addresses", out)
	}
	if len(out[0].Addresses) != 0 || out[0].AddressesTruncated {
		t.Errorf("an unreadable address list produced %+v", out[0])
	}
}
