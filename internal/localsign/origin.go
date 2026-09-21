package localsign

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateOrigin checks one --origin and returns it in the form a browser will send.
//
// A browser's Origin header is a scheme, a host and a non-default port, and nothing else: no trailing
// slash, no path, no credentials. An operator will reasonably paste the address out of their browser's
// address bar, which has all of those — so the ones that carry no meaning here are normalised away and
// the ones that do are refused. The alternative is a signer that is configured correctly as far as its
// operator can see and refuses every request, with the difference invisible in both places it is
// written down.
//
// http is allowed only for loopback. It is how the web application is served during development —
// `ng serve` on http://localhost:4200 — and it is the one case where "unencrypted" does not mean "over
// a network". Anywhere else it would mean an origin anybody on the path can impersonate, which is not
// a thing to let name a signing service.
func ValidateOrigin(raw string) (string, error) {
	origin := strings.TrimSpace(raw)
	switch origin {
	case "":
		return "", fmt.Errorf("localsign: an empty --origin names nothing")
	case "*", "null":
		return "", fmt.Errorf("localsign: --origin %q would let any page in the browser ask this "+
			"service for a signature. Name the address of the HostSeal web interface instead, for "+
			"example https://hostseal.example.org", origin)
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		return "", fmt.Errorf("localsign: --origin %q is not a URL: %w", raw, err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("localsign: --origin %q carries more than an origin. A browser sends "+
			"only the scheme, host and port — write %s://%s", raw, parsed.Scheme, parsed.Host)
	}

	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("localsign: --origin %q names no host", raw)
	}
	switch scheme {
	case "https":
	case "http":
		if !loopbackName(host) {
			return "", fmt.Errorf("localsign: --origin %q is http and not loopback. An origin that "+
				"anybody on the network can impersonate is not one to let ask for signatures; use "+
				"https://%s", raw, hostLiteral(host))
		}
	default:
		return "", fmt.Errorf("localsign: --origin %q has scheme %q; a browser origin is http or https",
			raw, parsed.Scheme)
	}

	// The default port is dropped because a browser drops it: a page at https://hostseal.example.org:443
	// sends Origin: https://hostseal.example.org, and an allowlist holding the longer spelling would
	// match nothing an operator could see was different.
	port := parsed.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port == "" {
		return scheme + "://" + hostLiteral(host), nil
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

// hostLiteral renders a host the way a URL spells it, which for IPv6 means inside brackets.
//
// net/url's Hostname strips the brackets an IPv6 literal is written in, and net.JoinHostPort puts them
// back — but only when there is a port to join. An origin with no port went through neither, so
// https://[::1] normalised to https://::1 and then matched nothing: a browser serialises the Origin
// header with the brackets, so every request from that page was refused while the allowlist looked
// exactly right in the terminal. The two spellings have to be one before the comparison, and this is
// the half net.JoinHostPort does not cover.
func hostLiteral(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// ValidateAddr checks that a listen address is loopback.
//
// Refused rather than warned about, because the failure has no symptom on the machine that caused it.
// A signer bound to 0.0.0.0 works perfectly for its operator and is simultaneously a signing service
// for everybody who can reach that laptop — on a conference network, on a client's VLAN — with the
// only thing between them and a fleet being whether somebody at the keyboard reads a prompt before
// answering it.
//
// A hostname is refused as well, even one that resolves to loopback, because what it resolves to is
// not decided here and can change: the point of this check is that the answer is readable from the
// address itself.
func ValidateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("localsign: %q is not a host:port address: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("localsign: %q names no port", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("localsign: %q is not an IP address. This service listens on loopback and "+
			"nowhere else, so its address is written as one — %s, or [::1]:%s for IPv6",
			host, DefaultAddr, port)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("localsign: %q is not a loopback address. A signer reachable from the "+
			"network is a signing service for whoever can reach this machine; it listens on %s or "+
			"another 127.0.0.0/8 address, and nothing else", host, DefaultAddr)
	}
	return nil
}

// loopbackHost reports whether a request's Host header addresses this machine's loopback interface.
//
// It is the defence against DNS rebinding, which is the one attack an origin allowlist does not stop
// on its own: a page at https://attacker.example whose hostname resolves, after a moment, to 127.0.0.1
// reaches this service from an origin that is genuinely its own. What it cannot do is make the browser
// send a Host header of 127.0.0.1, because the browser sends the name the page asked for.
//
// The literal "localhost" is accepted beside the IP literals. It is reserved by RFC 6761 and resolved
// locally by every browser rather than through DNS, so it cannot be rebound — and refusing it would
// break the address most people type first for no gain at all.
func loopbackHost(host string) bool {
	name := host
	if split, _, err := net.SplitHostPort(host); err == nil {
		name = split
	}
	return loopbackName(strings.ToLower(strings.Trim(name, "[]")))
}

// loopbackName reports whether a hostname or IP literal means this machine.
func loopbackName(name string) bool {
	if name == "localhost" {
		return true
	}
	ip := net.ParseIP(name)
	return ip != nil && ip.IsLoopback()
}

// describeOrigin renders an origin for a refusal message.
//
// A missing Origin header is named as such rather than printed as an empty pair of quotes, because it
// is a different situation with a different remedy: a browser always sends one, so no Origin means
// something that is not a browser — usually a curl written while debugging — and the sentence should
// say so rather than look like a configuration mismatch.
func describeOrigin(origin string) string {
	if origin == "" {
		return "no browser origin at all (a curl, or another program)"
	}
	return `"` + origin + `"`
}
