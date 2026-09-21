package autostart

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// TestCommandLineQuotesTheArgumentsWindowsWouldOtherwiseSplit covers the rule this package cannot run.
//
// There is no Windows machine in this project's CI, so the quoting is asserted here against the
// documented behaviour of CommandLineToArgvW rather than against a parser. Each case is one thing an
// operator's signing command actually contains: a program path under Program Files, a PKCS#11 reference
// naming a token with spaces in it, and a module path that ends in a backslash.
func TestCommandLineQuotesTheArgumentsWindowsWouldOtherwiseSplit(t *testing.T) {
	cases := []struct {
		name string
		exe  string
		args []string
		want string
	}{
		{
			name: "nothing to quote",
			exe:  `C:\HostSeal\hostseal.exe`,
			args: []string{"signer", "--origin", "https://hostseal.example.org"},
			want: `C:\HostSeal\hostseal.exe signer --origin https://hostseal.example.org`,
		},
		{
			name: "a path with a space",
			exe:  `C:\Program Files\HostSeal\hostseal.exe`,
			args: []string{"signer"},
			want: `"C:\Program Files\HostSeal\hostseal.exe" signer`,
		},
		{
			name: "a PKCS#11 reference naming a token and a module",
			exe:  `C:\HostSeal\hostseal.exe`,
			args: []string{"signer", "--key", `pkcs11:token=YubiKey PIV #12345678;object=SIGN key` +
				`?module-path=C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll`},
			want: `C:\HostSeal\hostseal.exe signer --key ` +
				`"pkcs11:token=YubiKey PIV #12345678;object=SIGN key` +
				`?module-path=C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"`,
		},
		{
			// The case that is silently wrong rather than noisily wrong: a trailing backslash inside
			// quotes escapes the closing quote, so everything after it joins this argument.
			name: "a quoted argument ending in a backslash",
			exe:  `C:\HostSeal\hostseal.exe`,
			args: []string{`C:\Program Files\Yubico\`, "--origin", "https://hostseal.example.org"},
			want: `C:\HostSeal\hostseal.exe "C:\Program Files\Yubico\\" ` +
				`--origin https://hostseal.example.org`,
		},
		{
			name: "a quote inside an argument",
			exe:  `hostseal.exe`,
			args: []string{`a "quoted" word`},
			want: `hostseal.exe "a \"quoted\" word"`,
		},
		{
			name: "backslashes before a quote are doubled",
			exe:  `hostseal.exe`,
			args: []string{`ends with\\" and a space`},
			want: `hostseal.exe "ends with\\\\\" and a space"`,
		},
		{
			name: "an empty argument survives as an empty argument",
			exe:  `hostseal.exe`,
			args: []string{"--key", ""},
			want: `hostseal.exe --key ""`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CommandLine(tc.exe, tc.args); got != tc.want {
				t.Errorf("CommandLine(%q, %q):\n got %s\nwant %s", tc.exe, tc.args, got, tc.want)
			}
		})
	}
}

// TestCommandLineQuotesNothingItDoesNotHaveTo guards the other half of the rule.
//
// Over-quoting is harmless to Windows and misleading to people: the command line is printed for an
// operator to read and to paste, and one wrapped in quotes it did not need reads as though the tool
// knows something about the argument that it does not.
func TestCommandLineQuotesNothingItDoesNotHaveTo(t *testing.T) {
	line := CommandLine(`C:\HostSeal\hostseal.exe`, []string{"signer", "--idle", "30m"})
	if strings.Contains(line, `"`) {
		t.Errorf("CommandLine quoted an argument that needed none: %s", line)
	}
}

// TestUninstallSucceedsWhereNothingCanBeRegistered pins the promise the command relies on.
//
// `hostseal signer --uninstall` is the thing somebody runs when clearing a workstation, and it has to
// be safe to run without first knowing whether this platform ever had a registration. Reporting false
// rather than an error is what makes that true.
func TestUninstallSucceedsWhereNothingCanBeRegistered(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has a registration to remove; this is about the platforms that do not")
	}
	removed, err := Uninstall()
	if err != nil {
		t.Fatalf("Uninstall() returned %v, want no error", err)
	}
	if removed {
		t.Error("Uninstall() reported removing something on a platform that registers nothing")
	}
}

// TestInstallRefusesWhereTheConfirmationWouldHaveNoTerminal states the refusal as a property.
//
// It is here so that adding a Unix autostart is a commit that changes a test with a reason written in
// it, rather than one that quietly gives the signer a home where its confirmation cannot be read.
func TestInstallRefusesWhereTheConfirmationWouldHaveNoTerminal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers a logon entry in the operator's own session")
	}
	if _, err := Install("/usr/bin/hostseal", []string{"signer"}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Install() returned %v, want ErrUnsupported", err)
	}
}
