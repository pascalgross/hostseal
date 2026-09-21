//go:build !windows

package pkcs11

import (
	"fmt"

	"github.com/ebitengine/purego"
)

// This file is one half of the only platform difference in this backend: how a shared library is
// brought into the process. Everything above it — the URI, the slot search, the ABI, the signing — is
// the same code on every platform, because PKCS#11 is the same specification everywhere and a module
// is a module. What differs is `dlopen` against `LoadLibrary`, and it differs in three functions.
//
// Keeping the difference here rather than in ffi.go is what let Windows be added without a second copy
// of the ABI: a reviewer comparing the two halves is comparing six lines, not six hundred, and the
// entry-point table that would be expensive to get wrong has no platform in it at all. The structure
// widths and offsets, which do differ, are abi.go's one table rather than a second copy of anything.

// exampleModulePath is the module an error message names when a reference gives none.
//
// It is per-platform because the example is the whole value of the sentence: an operator on Windows
// being told to write `/usr/lib/opensc-pkcs11.so` learns nothing about where their own module is, and
// the commonest reason a reference is missing `module-path=` is not knowing that it takes one.
//
// OpenSC rather than a vendor module, because it is the one that is a package away on every
// distribution — and because nothing here searches for it: it is an example in a sentence, and the
// path an operator types is the only path this backend ever loads.
const exampleModulePath = "/usr/lib/opensc-pkcs11.so"

// dlOpen loads a shared library and returns its handle.
//
// RTLD_NOW rather than RTLD_LAZY: a module missing a symbol should fail here, where the error names
// the module an operator typed, rather than at the first call into it — which on this path would be
// somewhere inside a signature an operator has already confirmed and touched their token for.
//
// RTLD_LOCAL keeps the module's symbols out of the global namespace, so that loading a vendor module
// cannot shadow a symbol for anything else in the process.
func dlOpen(path string) (uintptr, error) {
	handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

// dlSym resolves one symbol in a loaded library.
func dlSym(handle uintptr, symbol string) (uintptr, error) {
	address, err := purego.Dlsym(handle, symbol)
	if err != nil {
		return 0, fmt.Errorf("symbol %s: %w", symbol, err)
	}
	return address, nil
}

// dlClose unloads a library.
//
// The error is returned rather than swallowed so that both platforms have the same signature; every
// caller ignores it, because a module that will not unload is not something a signing tool can act on
// and the process is on its way out by then anyway.
func dlClose(handle uintptr) error { return purego.Dlclose(handle) }
