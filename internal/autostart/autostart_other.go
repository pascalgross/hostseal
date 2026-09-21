//go:build !windows

package autostart

// Install refuses, because there is no logon entry here that keeps the confirmation.
//
// The mechanisms a Unix desktop offers are a systemd user unit and a desktop autostart entry. The first
// has no terminal at all: the signer's confirmation is read from standard input, end of input is a no,
// and a unit that declined every signature would be a worse outcome than no autostart — it would look
// like a broken signer rather than like a missing one. The second starts a terminal emulator whose name
// this project would have to guess, on a desktop it cannot test, to save one command.
//
// So the operator starts it when they need it, which is also what the idle exit assumes. The error says
// so rather than the command reporting a success that registered nothing.
func Install(_ string, _ []string) (Entry, error) {
	return Entry{}, ErrUnsupported
}

// Uninstall reports that there was nothing to remove.
//
// Not an error, so that the same command is safe to run anywhere. Somebody clearing a workstation
// should not have to know which platform had a registration in order to be sure none is left.
func Uninstall() (bool, error) {
	return false, nil
}

// Current reports that nothing is registered, for the same reason.
func Current() (Entry, bool, error) {
	return Entry{}, false, nil
}
