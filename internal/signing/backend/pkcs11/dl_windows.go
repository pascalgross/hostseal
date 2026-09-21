package pkcs11

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// This file is the Windows half of the loader seam dl_unix.go describes, and it exists because an
// operator's workstation is very often a Windows one while the fleet is not. Before it, a person with
// a YubiKey and a Windows laptop could hold the destructive tier's key on the one device that cannot
// be copied and still had to sign from somewhere else — which in practice means a key file, which is
// the thing the token was bought to avoid.
//
// A Windows *host* gains nothing from this and needs nothing from it: it executes the read tier, which
// carries no signature at all, and links no backend either way. What changes is where a signature can
// be made.
//
// The calls are `windows.LoadLibraryEx` and `GetProcAddress` rather than purego's `Dlopen`, which is
// POSIX-only; purego's own call layer — the part that turns a C function pointer into a Go function
// value — supports Windows, so only these three functions are platform-specific. That support is
// amd64 and arm64, which is what HostSeal builds for Windows; a 32-bit Windows build would fail to
// compile inside purego rather than silently mis-call a module, which is the right way round.

// exampleModulePath is the module an error message names when a reference gives none.
//
// Yubico's, installed by the YubiKey Manager and the PIV Tool, because a Windows operator signing with
// a token is overwhelmingly signing with a YubiKey — and because an example that names a file somebody
// can go and look for beats a generic one they cannot. It is an example in a sentence and nothing
// else: no path is searched, no vendor is assumed, and the module this backend loads is the one the
// reference names.
const exampleModulePath = `C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll`

// dlOpen loads a DLL and returns its handle.
//
// Two things here are not the obvious ones.
//
// The path is made absolute first, because LOAD_WITH_ALTERED_SEARCH_PATH is documented to apply only
// to an absolute path — with a relative one the flag is ignored and the ordinary search order runs
// instead, which is the failure this flag exists to avoid.
//
// And the flag itself: it makes the module's own directory the first place its dependencies are looked
// for. A vendor PKCS#11 module is rarely one file — Yubico's `libykcs11.dll` sits beside the libraries
// it was built against — and without it Windows searches the application directory and then `PATH`,
// which both fails for the honest case and loads whatever is earliest on `PATH` for the dishonest one.
func dlOpen(path string) (uintptr, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return 0, fmt.Errorf("resolving %s: %w", path, err)
	}
	handle, err := windows.LoadLibraryEx(absolute, 0, windows.LOAD_WITH_ALTERED_SEARCH_PATH)
	if err != nil {
		return 0, err
	}
	return uintptr(handle), nil
}

// dlSym resolves one symbol in a loaded DLL.
func dlSym(handle uintptr, symbol string) (uintptr, error) {
	address, err := windows.GetProcAddress(windows.Handle(handle), symbol)
	if err != nil {
		return 0, fmt.Errorf("symbol %s: %w", symbol, err)
	}
	return address, nil
}

// dlClose unloads a DLL.
func dlClose(handle uintptr) error { return windows.FreeLibrary(windows.Handle(handle)) }
