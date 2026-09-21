package pkcs11

// This file is the answer to the one thing about PKCS#11 that is not the same everywhere, and it is
// not the thing anybody expects.
//
// The specification's own header notes, quoted in every vendor's copy of pkcs11.h including Yubico's:
// "The Cryptoki convention on packing is that structures should be 1-byte aligned", achieved on
// Windows with `#pragma pack(push, cryptoki, 1)` and on Unix by doing nothing at all. And CK_ULONG is
// `unsigned long int`, which is eight bytes on LP64 Unix and **four** on Windows, where `long` stayed
// 32 bits when pointers became 64. So the same module source compiled for the two platforms speaks two
// different binary languages: same field order, different widths, different offsets, different sizes.
//
// A Go struct cannot express either the packing or the per-platform width, so nothing above this layer
// declares one. The structures are built and read as bytes through the table below, which is the only
// place the two ABIs differ — the entry-point indices, the URI, the slot search and the signing path
// are one copy shared by both.
//
// Both tables live here rather than one per platform file so that a test on any platform can check
// both. That matters more here than anywhere else in this project: the Windows numbers are read from
// the specification rather than from a machine, and `go build` for Windows cannot tell a right offset
// from a wrong one. See TestTheCTypesAreTheSizeCExpects, which asserts both tables and is the reason
// this shape was chosen over two copies of the FFI.

// abiLayout is where the fields of the four PKCS#11 structures this package passes sit, in bytes.
//
// Sizes and offsets rather than a Go struct per platform, because the Windows layout is packed and Go
// has no packing. It is a value rather than a set of constants so that both platforms' tables can be
// compared in one test on either platform.
type abiLayout struct {
	// ulong is sizeof(CK_ULONG): the width of every handle, count, flag and return value.
	ulong int

	// attributeSize is sizeof(CK_ATTRIBUTE), the stride of a template array.
	attributeSize int

	// attributeType, attributeValue and attributeLen are the offsets of CK_ATTRIBUTE's three fields.
	attributeType  int
	attributeValue int
	attributeLen   int

	// mechanismSize is sizeof(CK_MECHANISM).
	mechanismSize int

	// mechanismType, mechanismParam and mechanismParamLen are the offsets of CK_MECHANISM's fields.
	mechanismType     int
	mechanismParam    int
	mechanismParamLen int

	// initializeArgsSize is sizeof(CK_C_INITIALIZE_ARGS).
	initializeArgsSize int

	// initializeArgsFlags is the offset of its flags field, after the four mutex callbacks.
	initializeArgsFlags int

	// functionListFirst is the offset of the first entry point in CK_FUNCTION_LIST.
	//
	// The list opens with a CK_VERSION — two CK_BYTEs — and the pointers follow. Unaligned on
	// Windows, where the structure is packed and they start at two; aligned on Unix, where the
	// compiler puts six bytes of padding in and they start at eight. Getting this wrong shifts every
	// entry point by one and calls C_Finalize where C_Initialize was meant.
	functionListFirst int
}

// unixABI is the layout an LP64 Unix compiler produces with no packing directive.
//
// CK_ULONG is eight bytes, and each structure is aligned as the compiler sees fit: CK_ATTRIBUTE is
// {8, pointer at 8, 8} = 24 bytes, and CK_FUNCTION_LIST's two-byte version is followed by six bytes of
// padding. This is the layout the round-trip tests exercise against a real module.
var unixABI = abiLayout{
	ulong:               8,
	attributeSize:       24,
	attributeType:       0,
	attributeValue:      8,
	attributeLen:        16,
	mechanismSize:       24,
	mechanismType:       0,
	mechanismParam:      8,
	mechanismParamLen:   16,
	initializeArgsSize:  48,
	initializeArgsFlags: 32,
	functionListFirst:   8,
}

// windowsABI is the layout a Windows compiler produces under the Cryptoki packing directive.
//
// Four-byte CK_ULONG, one-byte packing, eight-byte pointers. CK_ATTRIBUTE is {type at 0, pointer at 4,
// length at 12} = 16 bytes; CK_C_INITIALIZE_ARGS is four callbacks, flags at 32 and pReserved at 36 =
// 44; and CK_FUNCTION_LIST's entry points start at 2, unaligned.
//
// These numbers come from the specification and from the vendor headers that follow it, not from a
// machine: no Windows host has run this. What can be checked without one is checked — the arithmetic
// is asserted in a test that runs everywhere, and the Unix half of the same table is exercised against
// a real module — and what cannot is said plainly here rather than left for somebody to discover.
var windowsABI = abiLayout{
	ulong:               4,
	attributeSize:       16,
	attributeType:       0,
	attributeValue:      4,
	attributeLen:        12,
	mechanismSize:       16,
	mechanismType:       0,
	mechanismParam:      4,
	mechanismParamLen:   12,
	initializeArgsSize:  44,
	initializeArgsFlags: 32,
	functionListFirst:   2,
}
