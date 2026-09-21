package pkcs11

// ckULong is PKCS#11's CK_ULONG, which on Windows is four bytes.
//
// `unsigned long int` stayed 32 bits when Windows pointers became 64, so every handle, count, flag and
// return value in Cryptoki is half the width it is on Unix — while the pointers beside them are not.
// That is the whole reason this package has an ABI table at all.
type ckULong uint32

// layout is how this platform's compiler lays out the Cryptoki structures.
var layout = windowsABI
