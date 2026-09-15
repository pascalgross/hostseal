package collector

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/pascalgross/hostseal/internal/collect"
	"github.com/pascalgross/hostseal/internal/policy"
)

// noAddresses is the address lookup for a test that is not about addresses.
//
// An empty result rather than an error, because the two take different branches and a test asserting
// something else should take the ordinary one.
func noAddresses(net.Interface) ([]net.Addr, error) { return nil, nil }

// noDevices is the device lookup for a test that is not about which interfaces are real.
//
// False for everything, so the rank collapses to the address test and then to the name — which is the
// ordering every test written before the cap learned to prefer physical cards was asserting.
func noDevices(string) bool { return false }

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

// network returns the registered network collector.
//
// Looked up through All rather than constructed, for the reason the containers and resources helpers
// are: the assertion worth making is about the collector that runs on a host.
func network(t *testing.T) collect.Collector {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "network" {
			return c
		}
	}
	t.Fatal("no collector is registered as \"network\"")
	return nil
}

// TestTheNetworkSectionCanBeRefused covers the gate this collector did not have.
//
// It had none at all until hardware addresses were added, which was an omission rather than a decision:
// docs/EXTENDING.md's rule is that a section a host might reasonably decline gets a way to decline it,
// and a durable hardware identifier in a control plane somebody else operates is such a section. The
// default points the other way from the containers gate, and both directions are pinned here because
// both are deliberate.
func TestTheNetworkSectionCanBeRefused(t *testing.T) {
	gated, ok := network(t).(collect.PolicyGated)
	if !ok {
		t.Fatal("the network collector is not policy-gated, so no host can decline to report its " +
			"addresses and hardware addresses")
	}

	if !gated.PermittedBy(policy.Default()) {
		t.Error("the built-in default stopped reporting network configuration; this section predates " +
			"its key, so the default must preserve what every existing host already sends")
	}
	if gated.PermittedBy(policy.Closed()) {
		t.Error("a host whose policy could not be read reports its network configuration; a policy " +
			"that failed to load must disclose less, not more, whatever the default says")
	}

	opted, err := policy.Parse([]byte("[network]\nreport = false\n"))
	if err != nil {
		t.Fatalf("parsing a policy that opts out: %v", err)
	}
	if gated.PermittedBy(opted) {
		t.Error("a host that wrote report = false reports its network configuration anyway")
	}

	// The case that matters most for a default-on key: a policy file written before it existed must
	// keep the shipped value rather than fall to a zero one.
	silent, err := policy.Parse([]byte("[updates]\nallow = \"security\"\n"))
	if err != nil {
		t.Fatalf("parsing a policy that predates the key: %v", err)
	}
	if !gated.PermittedBy(silent) {
		t.Error("a policy file that does not mention the key switches network reporting off")
	}
}

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
	}, noAddresses, noDevices)

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
	}, noAddresses, noDevices)

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
		func(net.Interface) ([]net.Addr, error) { return many, nil }, noDevices)

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

// TestTheCapKeepsTheCardAndDropsTheVeths is the finding this ranking exists for.
//
// A Docker workstation has fifty `veth*` interfaces and one `wlp2s0`, and a plain alphabetical cut keeps
// the veths: "veth" sorts before "wlp". The one row dropped is then the physical card — the only MAC
// address in the report that identifies the machine to a DHCP server or a switch, which is the whole
// reason hardware addresses were added. Deterministic and useless is still useless.
func TestTheCapKeepsTheCardAndDropsTheVeths(t *testing.T) {
	var interfaces []net.Interface
	for i := range collect.MaxInterfaces {
		interfaces = append(interfaces,
			net.Interface{Name: fmt.Sprintf("veth%03d", i), MTU: 1500, Flags: net.FlagUp})
	}
	// Sorts last by name, and first by rank.
	interfaces = append(interfaces, net.Interface{Name: "wlp2s0", MTU: 1500, Flags: net.FlagUp})
	// No device of its own, but configured and carrying traffic: it outranks a veth and not a card.
	interfaces = append(interfaces, net.Interface{Name: "br0", MTU: 1500, Flags: net.FlagUp})

	out, truncated := describeInterfaces(interfaces,
		func(i net.Interface) ([]net.Addr, error) {
			if i.Name == "br0" {
				return []net.Addr{addr("10.0.0.1/24")}, nil
			}
			return nil, nil
		},
		func(name string) bool { return name == "wlp2s0" })

	if !truncated {
		t.Fatal("a cut interface list is not flagged as truncated")
	}
	byName := map[string]bool{}
	for _, iface := range out {
		byName[iface.Name] = true
	}
	if !byName["wlp2s0"] {
		t.Error("the physical card was cut in favour of veth pairs, which is the bug this test exists " +
			"for: the only hardware address worth having is the one that got dropped")
	}
	if !byName["br0"] {
		t.Error("a configured bridge with an address was cut in favour of veth pairs")
	}

	// Still alphabetical on the wire. The rank decides what survives; it is not an order a client
	// should have to know about.
	for i := 1; i < len(out); i++ {
		if out[i-1].Name >= out[i].Name {
			t.Fatalf("the reported list is not sorted by name: %q then %q", out[i-1].Name, out[i].Name)
		}
	}
}

// TestInterfaceRankPrefersRealDevicesThenConfiguredOnes covers the three levels directly.
//
// Each level has its own reason, and the middle one is the one that would be lost first: a bond, a
// bridge and a VLAN have no device of their own but are things somebody configured, so they belong
// above the veth pairs and below the card.
func TestInterfaceRankPrefersRealDevicesThenConfiguredOnes(t *testing.T) {
	physical := func(name string) bool { return name == "eth0" }
	cases := []struct {
		reported networkInterface
		want     int
	}{
		{networkInterface{Name: "eth0"}, 0},
		{networkInterface{Name: "eth0", Addresses: []string{"10.0.0.2/24"}}, 0},
		{networkInterface{Name: "br0", Addresses: []string{"10.0.0.1/24"}}, 1},
		{networkInterface{Name: "veth12ab"}, 2},
		{networkInterface{Name: "docker0"}, 2},
	}
	for _, c := range cases {
		if got := interfaceRank(c.reported, physical); got != c.want {
			t.Errorf("interfaceRank(%q) = %d, want %d", c.reported.Name, got, c.want)
		}
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
	out, truncated := describeInterfaces(many, noAddresses, noDevices)

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
		func(net.Interface) ([]net.Addr, error) { return nil, fmt.Errorf("netlink refused") }, noDevices)

	if len(out) != 1 || out[0].Name != "eth0" {
		t.Fatalf("reported %+v, want eth0 with no addresses", out)
	}
	if len(out[0].Addresses) != 0 || out[0].AddressesTruncated {
		t.Errorf("an unreadable address list produced %+v", out[0])
	}
}
