package main

// The PKCS#11 backend, registered by its own init function.
//
// It is imported here, in a file of its own, rather than beside the other blank imports in main.go,
// because it is the one backend that brings foreign code into this process: it loads a shared library
// an operator names, through `dlopen` on Unix and `LoadLibraryEx` on Windows. A reviewer asking "what
// does this binary load that it did not compile" should find the answer in one named file rather than
// in the middle of an import block.
//
// It carries no build constraint. It used to carry `!windows`, because purego's `dlopen` is POSIX-only
// and nothing had been written for the other side — which left an operator with a YubiKey and a
// Windows workstation holding the destructive tier's key on the one device that cannot be copied, and
// still signing from somewhere else. `internal/signing/backend/pkcs11` now has a loader per platform
// and one ABI, so this is an ordinary import on both.
//
// A Windows *host* still links none of it and needs none of it: it executes the read tier, which
// carries no signature at all. What this file governs is where a signature can be made, and
// TestGuaranteeNoManagedHostBinaryLoadsASigningBackend asserts that the answer is nowhere a managed
// host runs.
import _ "github.com/pascalgross/hostseal/internal/signing/backend/pkcs11"
