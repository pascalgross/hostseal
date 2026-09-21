package localsign

import "testing"

// TestAnOriginIsNormalisedToWhatABrowserSends covers the accepting half of ValidateOrigin.
//
// Each of these is something an operator will paste out of an address bar, and each has to end up as
// the exact string the browser will put in the Origin header — because the allowlist is a string
// comparison, and a mismatch produces a signer that is configured correctly as far as anybody can see
// and refuses every request.
func TestAnOriginIsNormalisedToWhatABrowserSends(t *testing.T) {
	for given, want := range map[string]string{
		"https://hostseal.example.org":      "https://hostseal.example.org",
		"https://hostseal.example.org/":     "https://hostseal.example.org",
		"https://HostSeal.Example.ORG":      "https://hostseal.example.org",
		"https://hostseal.example.org:443":  "https://hostseal.example.org",
		"https://hostseal.example.org:8443": "https://hostseal.example.org:8443",
		"  https://hostseal.example.org  ":  "https://hostseal.example.org",
		"http://localhost:4200":             "http://localhost:4200",
		"http://127.0.0.1:4200":             "http://127.0.0.1:4200",
	} {
		got, err := ValidateOrigin(given)
		if err != nil {
			t.Errorf("%q was refused: %v", given, err)
			continue
		}
		if got != want {
			t.Errorf("%q normalised to %q, want %q", given, got, want)
		}
	}
}

// TestAnOriginThatIsNotOneIsRefused covers the refusing half.
//
// The http case is the one worth stating: an origin anybody on the path can impersonate is not a thing
// to let name a signing service, and the loopback exception exists only because `ng serve` is where
// this application is developed — there, "unencrypted" does not mean "over a network".
func TestAnOriginThatIsNotOneIsRefused(t *testing.T) {
	for _, given := range []string{
		"",
		"*",
		"null",
		"http://hostseal.example.org",
		"ftp://hostseal.example.org",
		"https://",
		"https://hostseal.example.org/templates",
		"https://hostseal.example.org?x=1",
		"https://user:pass@hostseal.example.org",
		"hostseal.example.org",
	} {
		if got, err := ValidateOrigin(given); err == nil {
			t.Errorf("%q was accepted as %q", given, got)
		}
	}
}

// TestAListenAddressOtherPeopleCanReachIsRefused is the check with no symptom of its own.
//
// A signer bound to 0.0.0.0 works perfectly for the operator who typed it and is simultaneously a
// signing service for everybody who can reach that laptop. Nothing about the running process says so,
// which is why this is a refusal at the point of typing rather than a warning in a log.
func TestAListenAddressOtherPeopleCanReachIsRefused(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0:18515",
		"192.168.1.10:18515",
		"[::]:18515",
		"localhost:18515",
		"hostseal.example.org:18515",
		"127.0.0.1",
		"",
	} {
		if err := ValidateAddr(addr); err == nil {
			t.Errorf("%q was accepted as a listen address", addr)
		}
	}

	for _, addr := range []string{"127.0.0.1:18515", "127.0.0.2:0", "[::1]:18515", DefaultAddr} {
		if err := ValidateAddr(addr); err != nil {
			t.Errorf("%q was refused: %v", addr, err)
		}
	}
}

// TestALoopbackHostIsToldApartFromARebindableName pins the DNS-rebinding check.
//
// "localhost" is on the accepting side deliberately: RFC 6761 reserves it and browsers resolve it
// without asking DNS, so it cannot be rebound — and refusing it would break the address most people
// type first, which is how a check gets removed rather than fixed. Everything with a dot in it is on
// the refusing side, including the name that begins with the word: a hostname is only ever as
// trustworthy as whoever answers for the zone it sits in.
func TestALoopbackHostIsToldApartFromARebindableName(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1:18515":                  true,
		"127.0.0.1":                        true,
		"127.0.0.53:18515":                 true,
		"[::1]:18515":                      true,
		"localhost:18515":                  true,
		"LOCALHOST:18515":                  true,
		"localhost":                        true,
		"rebound.attacker.example:18515":   false,
		"localhost.attacker.example:18515": false,
		"hostseal.example.org":             false,
		"10.0.0.5:18515":                   false,
	} {
		if got := loopbackHost(host); got != want {
			t.Errorf("loopbackHost(%q) is %v, want %v", host, got, want)
		}
	}
}
