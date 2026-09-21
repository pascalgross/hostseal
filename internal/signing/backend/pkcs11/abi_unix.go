//go:build !windows

package pkcs11

// ckULong is PKCS#11's CK_ULONG, which on LP64 Unix is eight bytes.
//
// A defined type rather than an alias for uint64, so that every conversion to and from a fixed width
// is written down: the same name is four bytes on Windows, and code that compiled on both by accident
// is exactly what this file exists to prevent.
type ckULong uint64

// layout is how this platform's compiler lays out the Cryptoki structures.
var layout = unixABI
