package collector

import (
	"context"
	"net"
	"sort"

	"github.com/pascalgross/hostseal/internal/collect"
)

// maxAddresses caps the addresses reported for one interface.
//
// A host with a large number of virtual addresses — a load balancer, a container host — would otherwise
// send hundreds of lines every time its facts changed. Ten is enough to recognise a machine.
const maxAddresses = 10

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

// init registers the network collector.
func init() {
	Register(collect.NewCollectorFunc("network", collectNetwork))
}

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
// the whole section small and to keep it out of the wallboard, both of which still hold.
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
	})
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
	addressesOf func(net.Interface) ([]net.Addr, error)) (out []networkInterface, truncated bool) {

	out = make([]networkInterface, 0, len(interfaces))
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
		out = append(out, reported)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	// Sorted before the cap, so a host over the limit reports the same interfaces on every beat rather
	// than a different set each time, which would change the facts digest for no reason at all. The cap
	// itself was missing until this version: a Docker host has one veth pair per container, so a machine
	// running two hundred containers put two hundred interfaces and up to two thousand addresses into a
	// document with a one-mebibyte ceiling. docs/PROTOCOL.md §4.5 requires a bound on any section the
	// agent can grow without limit, and this was one.
	if len(out) > collect.MaxInterfaces {
		out = out[:collect.MaxInterfaces]
		truncated = true
	}
	return out, truncated
}
