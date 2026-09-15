package collector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"

	"github.com/pascalgross/hostseal/internal/collect"
	"github.com/pascalgross/hostseal/internal/policy"
)

// maxAddresses caps the addresses reported for one interface.
//
// A host with a large number of virtual addresses — a load balancer, a container host — would otherwise
// send hundreds of lines every time its facts changed. Ten is enough to recognise a machine.
const maxAddresses = 10

// sysClassNet is where the kernel publishes per-interface attributes.
//
// Only one of them is read — whether a `device` entry exists — and that is what separates a network card
// from something a container runtime created. See interfaceRank for why that distinction decides which
// interfaces survive the cap.
const sysClassNet = "/sys/class/net"

// networkInterface is one interface as reported to the control plane.
type networkInterface struct {
	// Name is the kernel's name for the interface, such as "eth0".
	Name string `json:"name"`

	// HardwareAddress is the interface's MAC address, absent where it has none.
	//
	// Absent rather than empty on a point-to-point or tunnel interface, which genuinely has no hardware
	// address — reporting "" would be a claim about the hardware rather than an admission that there is
	// none.
	HardwareAddress string `json:"hardwareAddress,omitempty"`

	// MTU is the interface's maximum transmission unit.
	MTU int `json:"mtu"`

	// Up reports whether the interface is administratively up.
	Up bool `json:"up"`

	// Addresses are the assigned addresses in CIDR form, capped at maxAddresses.
	Addresses []string `json:"addresses,omitempty"`

	// AddressesTruncated reports that the list was cut short.
	AddressesTruncated bool `json:"addressesTruncated,omitempty"`
}

// networkCollector reports the host's own network interfaces, and lets the host decline to.
//
// It is a struct rather than a CollectorFunc for the reason containersCollector is one: it has something
// to say about the policy, and PolicyGated is a method rather than a closure field. It was a
// CollectorFunc until hardware addresses were added — the section had no gate at all, which was an
// omission rather than a decision, and an awkward one to defend once docs/SECURITY.md had to name it as
// the one disclosure a host could not refuse.
type networkCollector struct{}

// init registers the network collector.
func init() {
	Register(networkCollector{})
}

// Name is the key this collector's output appears under in the facts document.
func (networkCollector) Name() string { return "network" }

// Collect reports the host's interfaces, or the error that stopped it.
//
// Unlike the containers and resources collectors, this one does return an error: net.Interfaces failing
// is not a fact about the host that a report could state, it is the whole section being unavailable, and
// Gather drops the section and logs the reason. The empty-list case is different and is a note, because
// a host with no non-loopback interface is a fact worth stating.
func (networkCollector) Collect(ctx context.Context) (any, error) { return collectNetwork(ctx) }

// PermittedBy reports whether the host's local policy allows its network configuration to be reported.
//
// True unless an administrator writes `[network] report = false`, which is argued out on
// policy.Network.Report: the section predates its key, so the default preserves what every existing host
// already sends, and the key exists because a MAC address is a durable hardware identifier that a host
// may not want in somebody else's database.
func (networkCollector) PermittedBy(p policy.Policy) bool { return p.Network.Report }

// collectNetwork reports the host's network interfaces, their addresses and their hardware addresses.
//
// It is the collector that justifies AF_NETLINK in the systemd unit's RestrictAddressFamilies:
// net.Interfaces uses a netlink socket on Linux, and without that family it returns nothing — and does
// so without an error, which is the class of failure this project tries hardest not to ship.
//
// Hardware addresses were deliberately absent here until this version, on the argument that they
// "identify a machine no better than the host id already does". That was the right answer to the wrong
// question. Nothing about a MAC address makes a host more identifiable *to the control plane*, which
// already holds a certificate fingerprint and a hostname — but it is the only thing in this report that
// identifies the machine to something that is **not** HostSeal: a DHCP lease, a switch port, a
// hypervisor's virtual NIC, an asset database somebody has been maintaining by hand since before the
// fleet existed. That is a join nothing else here can make, and it is the join an operator needs at the
// moment they are trying to work out which physical box a hostname corresponds to. The old sentence's
// real objection — that it is the sort of thing that ends up in a support ticket — is a reason to keep
// the whole section small, to keep it out of the wallboard, and to give the host a way to refuse it, all
// three of which this collector now does.
func collectNetwork(context.Context) (any, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Wrapped rather than passed as a method expression, because Addrs has a pointer receiver and the
	// loop below hands the function a value — a detail the compiler catches, so it is noted rather than
	// worried about.
	out, truncated := describeInterfaces(interfaces, func(i net.Interface) ([]net.Addr, error) {
		return i.Addrs()
	}, hasDevice)
	if len(out) == 0 {
		// Reported as an explicit note rather than an empty list. A host with no interfaces at all is
		// either a container with a very unusual configuration or an agent whose netlink access has
		// been taken away, and the two want different responses.
		return map[string]any{
			"interfaces": out,
			"note":       "no non-loopback interfaces were visible; check RestrictAddressFamilies includes AF_NETLINK",
		}, nil
	}
	section := map[string]any{"interfaces": out}
	if truncated {
		// Present only when the list was cut, so its absence means a complete list rather than an agent
		// that predates the bound. docs/PROTOCOL.md §4.5 requires the flag on any section the agent
		// truncates, and a reader seeing exactly fifty interfaces should know whether that is the number
		// or the limit.
		section["interfacesTruncated"] = true
	}
	return section, nil
}

// describeInterfaces renders the reported view of a set of interfaces.
//
// It takes the address lookup as a function for the reason collect.ParseSimulation takes its origin test
// as one: net.Interfaces and Interface.Addrs reach a netlink socket and cannot be pointed at a fixture,
// so the only way to test the truncation, the sorting and the loopback rule is to hand the pure half of
// this collector its inputs. Everything that decides what a host says lives here; the netlink call and
// the empty-list note stay with the caller.
func describeInterfaces(interfaces []net.Interface,
	addressesOf func(net.Interface) ([]net.Addr, error),
	backedByDevice func(string) bool) (out []networkInterface, truncated bool) {

	// Ranked alongside the rows so the cap below can prefer the interfaces this section exists for,
	// without the rank itself reaching the wire.
	type ranked struct {
		reported networkInterface
		rank     int
	}
	rows := make([]ranked, 0, len(interfaces))
	for _, iface := range interfaces {
		// The loopback interface is the same on every host and tells an operator nothing.
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		reported := networkInterface{
			Name:            iface.Name,
			HardwareAddress: iface.HardwareAddr.String(),
			MTU:             iface.MTU,
			Up:              iface.Flags&net.FlagUp != 0,
		}

		addrs, addrErr := addressesOf(iface)
		if addrErr == nil {
			for _, addr := range addrs {
				reported.Addresses = append(reported.Addresses, addr.String())
			}
			sort.Strings(reported.Addresses)
			if len(reported.Addresses) > maxAddresses {
				reported.Addresses = reported.Addresses[:maxAddresses]
				reported.AddressesTruncated = true
			}
		}
		rows = append(rows, ranked{reported: reported, rank: interfaceRank(reported, backedByDevice)})
	}

	// Ranked first, then named, so the cut is both deterministic and worth having. A plain alphabetical
	// cut would be deterministic and useless on the host that needs the bound: a Docker workstation with
	// fifty `veth*` interfaces and one `wlp2s0` keeps the veths and drops the Wi-Fi card, because "veth"
	// sorts before "wlp" — losing precisely the hardware address this section was added to report.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].rank != rows[j].rank {
			return rows[i].rank < rows[j].rank
		}
		return rows[i].reported.Name < rows[j].reported.Name
	})
	// The cap itself was missing until this version: a Docker host has one veth pair per container, so a
	// machine running two hundred containers put two hundred interfaces and up to two thousand addresses
	// into a document with a one-mebibyte ceiling. docs/PROTOCOL.md §4.5 requires a bound on any section
	// the agent can grow without limit, and this was one.
	if len(rows) > collect.MaxInterfaces {
		rows = rows[:collect.MaxInterfaces]
		truncated = true
	}

	out = make([]networkInterface, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.reported)
	}
	// Re-sorted by name once the cut is made, because the rank is how this function chooses and the name
	// is how a reader finds a row. A list whose order encoded an internal judgement would be one a client
	// had to learn about to read.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, truncated
}

// interfaceRank orders interfaces by how likely one is to be the answer somebody wanted.
//
// It decides only which rows survive the cap, never what any row says, and it has three levels because
// there are three genuinely different kinds of interface on a machine that has more than fifty.
//
// A real device behind it ranks first: /sys/class/net/<name>/device exists for a network card the kernel
// drives, physical or virtio, and does not exist for anything synthesised in software. That is the test
// udev and `ip link` use, rather than a list of name prefixes that would need a new entry every time a
// container runtime invented one. It is deliberately not the locally-administered bit in the hardware
// address: every KVM guest's card is locally administered, which would rank the commonest machine in a
// fleet below the veth pairs on it.
//
// An interface with an address ranks second: a bond, a bridge or a VLAN has no device of its own but
// carries traffic somebody configured. Everything else ranks last, which on the hosts where this matters
// means the veth pairs.
func interfaceRank(reported networkInterface, backedByDevice func(string) bool) int {
	switch {
	case backedByDevice(reported.Name):
		return 0
	case len(reported.Addresses) > 0:
		return 1
	default:
		return 2
	}
}

// hasDevice reports whether the kernel has a real network device behind an interface name.
//
// It reads a path rather than taking a parameter for the root, unlike everything in internal/collect,
// because this package has no fixture trees and the one caller is the live collector — the pure function
// above takes it as an argument, which is where the testing seam belongs.
func hasDevice(name string) bool {
	// Cleaned and taken as a basename, because the name arrives from the kernel through net.Interfaces
	// and is about to be joined onto a path. Nothing here should be able to walk out of /sys/class/net
	// even if that assumption ever stops holding.
	_, err := os.Stat(filepath.Join(sysClassNet, filepath.Base(filepath.Clean(name)), "device"))
	return err == nil
}
