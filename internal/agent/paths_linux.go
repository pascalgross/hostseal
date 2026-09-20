//go:build linux

package agent

// DefaultStateDir is where the agent keeps everything it writes.
//
// It is the only writable path the hardened systemd unit grants, which is deliberate: an agent that can
// write nowhere else cannot be talked into leaving something behind in a directory that matters.
const DefaultStateDir = "/var/lib/hostseal"

// DefaultServerCABundle is where an administrator puts the control plane's CA before enrolling.
//
// It exists because enrolment is the one request an agent makes with nothing on disk to verify against.
// Every request after it uses the bundle the enrolment response carried, written to CABundleFile — but
// that response is itself fetched over TLS, so the first connection needs an authority chosen locally
// and in advance. `hostseal enroll` reads this path when --ca is not given, which is what makes the
// documented ordering — install the certificate, then enrol — mean something rather than being a step
// that writes a file nothing opens.
//
// /etc/hostseal rather than the state directory: this is administrator-supplied configuration, chosen
// before the agent exists, and the state directory is the agent's to rewrite.
const DefaultServerCABundle = "/etc/hostseal/server-ca.crt"

// MachineIDPath is systemd's machine identifier, which is documented as confidential.
const MachineIDPath = "/etc/machine-id"

// RestartCommand is what an operator runs to make a freshly enrolled host act on its enrolment.
//
// A restart rather than a start, and that is the whole reason this is printed at all: the package
// starts the service at install time, so by the time anybody enrols there is already an agent running —
// one that found no credential, said so, and went into the idle loop in cmd/hostseal-agent. That loop
// re-reads the policy on every tick and never re-reads the enrolment state, so an operator who enrols
// and stops there has a running service, a host the control plane has heard of once, and no facts
// arriving. "Start" invited exactly that: it succeeds, changes nothing, and reports success.
//
// A constant per platform because `hostseal enroll` ships on both and the Windows service is not
// managed by systemd, so the Linux command printed on a Windows host is advice that cannot be followed.
const RestartCommand = "systemctl restart hostseal-agent"
