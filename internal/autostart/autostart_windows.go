//go:build windows

package autostart

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// runKey is the per-user key Windows reads at logon.
//
// HKEY_CURRENT_USER and deliberately not HKEY_LOCAL_MACHINE. The signer holds one person's token and
// signs with one person's key; a machine-wide entry would need an administrator to install, would start
// a signer for every account that ever logs in to that workstation, and would present each of them with
// a PIN prompt for a token that is not theirs.
const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// valueName is the name of the value under that key.
//
// A constant, and one name rather than one per key reference, so that installing twice replaces the
// registration rather than accumulating a second signer that fights the first for the port. An operator
// who changes their token or their control plane's address runs --install again and gets what they
// asked for.
const valueName = "HostSeal signer"

// Install writes the logon entry, replacing any earlier one.
//
// The command line is composed here rather than taken from the caller's argv, because what should run
// at the next logon is the command the operator has just described with flags — not the one they typed,
// which contained --install and will not next time.
func Install(exe string, args []string) (Entry, error) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return Entry{}, fmt.Errorf("autostart: opening HKCU\\%s: %w", runKey, err)
	}
	defer func() { _ = key.Close() }()

	command := CommandLine(exe, args)
	if err := key.SetStringValue(valueName, command); err != nil {
		return Entry{}, fmt.Errorf("autostart: writing %q: %w", valueName, err)
	}
	return Entry{Where: `HKCU\` + runKey + `\` + valueName, Command: command}, nil
}

// Uninstall removes the logon entry, and reports whether there was one.
//
// A missing value is not an error. Somebody running --uninstall wants no signer starting at logon, and
// that is the state they are in either way; failing would turn a second attempt, or an uninstall after a
// reinstalled profile, into an error message about something that is already true.
func Uninstall() (bool, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("autostart: opening HKCU\\%s: %w", runKey, err)
	}
	defer func() { _ = key.Close() }()

	err = key.DeleteValue(valueName)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("autostart: removing %q: %w", valueName, err)
	}
	return true, nil
}

// Current reports the registered entry, if there is one.
//
// It exists so that --install can print what it replaced. A registration an operator forgot about is
// the one that would otherwise start a signer for a token they no longer carry, and silently replacing
// it would remove the only moment they were going to notice.
func Current() (Entry, bool, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, fmt.Errorf("autostart: opening HKCU\\%s: %w", runKey, err)
	}
	defer func() { _ = key.Close() }()

	command, _, err := key.GetStringValue(valueName)
	if errors.Is(err, registry.ErrNotExist) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, fmt.Errorf("autostart: reading %q: %w", valueName, err)
	}
	return Entry{Where: `HKCU\` + runKey + `\` + valueName, Command: command}, true, nil
}
