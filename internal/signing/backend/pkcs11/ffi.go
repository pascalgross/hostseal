package pkcs11

import (
	"fmt"
	"unsafe"

	"github.com/ebitengine/purego"
)

// This file is the only place in HostSeal that hands Go memory to a C ABI, and it is one file on
// purpose. Every unsafe.Pointer conversion in the project lives here, where a reviewer can read all of
// them at once and where .golangci.yml can scope gosec's G103 to a single named path with a written
// reason. Nothing above this layer sees a pointer.
//
// It is reached through purego rather than cgo. That is not a preference: the Makefile builds every
// binary with CGO_ENABLED=0 and the release workflow cross-builds amd64 and arm64 in one loop on one
// runner, and cgo would replace that with a cross-compiler whose version becomes an unpinned input to
// a reproducibility claim the project asks people to check. purego keeps the build exactly as it is,
// at the price of an ABI that the compiler cannot check — which is what the size assertions in
// pkcs11_test.go are for.
//
// Loading the library is the one thing in here that is not portable, and it is the one thing this file
// does not do: dl_unix.go and dl_windows.go hold `dlopen` and `LoadLibraryEx` respectively, and the ABI
// below is shared by both. PKCS#11 is one specification on every platform, so a second copy of these
// entry-point indices for Windows would have been six hundred lines that can drift for no reason.
//
// The library is loaded only when an operator hands `hostseal sign` a pkcs11: reference naming a
// module. It is emphatically not the plugin loader docs/EXTENDING.md refuses: that refusal is about
// the *agent*, which loads no code at run time and does not link this package at all — a property
// TestGuaranteeNoManagedHostBinaryLoadsASigningBackend asserts rather than assumes.

// ckULong is PKCS#11's CK_ULONG.
//
// Eight bytes on every platform HostSeal ships to, which is what makes the struct layouts below right.
// It is a named type so that a plain int cannot be passed where the ABI expects this width.
type ckULong = uint64

// ckReturn is PKCS#11's CK_RV, the return value of every entry point.
type ckReturn = uint64

// The PKCS#11 return values this package distinguishes.
//
// Only the ones with a distinct meaning to a caller. Everything else is reported by number through
// ckError, because a partial table that silently rendered an unknown code as "unknown error" would
// hide exactly the module-specific failure an operator needs to search for.
const (
	// ckrOK is success.
	ckrOK ckReturn = 0x00

	// ckrBufferTooSmall is the expected answer to the first half of every two-call idiom below.
	ckrBufferTooSmall ckReturn = 0x150

	// ckrPINIncorrect is worth naming because it is the one an operator causes and can fix.
	ckrPINIncorrect ckReturn = 0xA0

	// ckrPINLockedOut is worth naming because the fix is not "try again": the token has locked the
	// user PIN and needs its SO PIN to reset, and repeated attempts make it worse.
	ckrPINLockedOut ckReturn = 0xA4
)

// PKCS#11 session, user and object constants.
const (
	// ckfSerialSession must be set on every session; the flag is vestigial and required.
	ckfSerialSession ckULong = 0x04

	// ckfOSLockingOK tells a module it may use the operating system's locking primitives.
	//
	// Passed rather than a nil argument list. A nil one works with SoftHSM and tells a module that it
	// may not use OS locking, which is not what a multi-goroutine Go program should be claiming.
	ckfOSLockingOK ckULong = 0x02

	// ckuUser is the ordinary token user, as opposed to the security officer.
	ckuUser ckULong = 1

	// ckoPublicKey and ckoPrivateKey are the CKA_CLASS values this package searches for.
	ckoPublicKey  ckULong = 2
	ckoPrivateKey ckULong = 3

	// The CKA_KEY_TYPE values HostSeal's two wire algorithms can come from.
	ckkEC        ckULong = 0x03
	ckkECEdwards ckULong = 0x40
	ckkRSA       ckULong = 0x00

	// The attributes this package reads or matches on.
	ckaClass    ckULong = 0x00
	ckaLabel    ckULong = 0x03
	ckaKeyType  ckULong = 0x100
	ckaID       ckULong = 0x102
	ckaECParams ckULong = 0x180
	ckaECPoint  ckULong = 0x181

	// ckmECDSA signs a digest the caller supplies and returns a raw r‖s pair.
	//
	// Not CKM_ECDSA_SHA256: that mechanism hashes the payload itself, which would change what the
	// signature is over, and many PIV tokens do not implement it at all.
	ckmECDSA ckULong = 0x1041

	// ckmEDDSA signs the payload itself, because Ed25519 hashes internally.
	ckmEDDSA ckULong = 0x1057
)

// Function indices into CK_FUNCTION_LIST, in the order PKCS#11 v2.40 defines them.
//
// The list is a struct of 68 function pointers after a two-byte version, and the order is fixed by the
// specification — a v3.0 module still returns the 2.40-shaped list from C_GetFunctionList, because v3
// adds C_GetInterface beside it rather than changing this. Indices rather than 68 named fields
// because 54 of them would be dead weight in a file whose whole point is that a reviewer can read it;
// the ones used are named here, and every one of them is exercised by the round-trip test against a
// real module, which is what would catch an off-by-one.
const (
	fnInitialize        = 0
	fnFinalize          = 1
	fnGetSlotList       = 4
	fnGetTokenInfo      = 6
	fnOpenSession       = 12
	fnCloseSession      = 13
	fnLogin             = 18
	fnLogout            = 19
	fnGetAttributeValue = 24
	fnFindObjectsInit   = 26
	fnFindObjects       = 27
	fnFindObjectsFinal  = 28
	fnSignInit          = 42
	fnSign              = 43

	// fnCount is the number of entries in the v2.40 list, and the bound the size test checks.
	fnCount = 68
)

// functionList mirrors CK_FUNCTION_LIST.
//
// The padding is the C compiler's: CK_VERSION is two CK_BYTEs and the pointers that follow are
// eight-byte aligned, so six bytes sit between them. Getting that wrong shifts every entry point by
// one and calls C_Finalize where C_Initialize was meant — which is why its size is asserted.
type functionList struct {
	// _ is CK_VERSION — two CK_BYTEs the module fills in with the Cryptoki version — and the six
	// bytes of alignment padding after it. Blank rather than named because this package does not read
	// the version: a module that answered C_GetFunctionList is one whose list is laid out this way,
	// and a version check that accepted 2.40 and rejected 3.0 would refuse modules that work.
	_ [8]byte

	// fn holds the entry points, indexed by the constants above.
	fn [fnCount]uintptr
}

// ckAttribute mirrors CK_ATTRIBUTE: a typed slot that a module reads from or writes into.
type ckAttribute struct {
	// kind is the CKA_* attribute type.
	kind ckULong

	// value points at the caller's buffer, or is nil when asking for a length.
	value unsafe.Pointer

	// valueLen is the buffer's size going in and the attribute's size coming out.
	valueLen ckULong
}

// ckMechanism mirrors CK_MECHANISM: which operation, and its parameters.
type ckMechanism struct {
	// mechanism is the CKM_* identifier.
	mechanism ckULong

	// parameter and paramLen describe the mechanism's parameter block; both are zero for the two
	// signature mechanisms this package uses.
	parameter unsafe.Pointer
	paramLen  ckULong
}

// ckInitializeArgs mirrors CK_C_INITIALIZE_ARGS.
//
// Only Flags is set. The four mutex callbacks stay nil, which together with CKF_OS_LOCKING_OK tells
// the module to use the platform's own locking rather than callbacks into a Go runtime that cannot
// safely provide them.
type ckInitializeArgs struct {
	// _ is CreateMutex, DestroyMutex, LockMutex and UnlockMutex: the four optional callbacks, left
	// nil so the module uses the platform's own locking rather than calling back into a Go runtime
	// that cannot safely provide them. Blank because leaving them nil is the whole of what this
	// package does with them, and a named field nothing assigns is a field somebody will assign.
	_ [4]uintptr

	// flags carries CKF_OS_LOCKING_OK.
	flags ckULong

	// _ is pReserved, which the specification requires to be nil.
	_ unsafe.Pointer
}

// tokenInfoBytes is the buffer a CK_TOKEN_INFO is read into.
//
// The struct is a little over two hundred bytes and this package needs two fields from it. Reading into
// an over-large opaque buffer rather than declaring a partial struct is deliberate: a struct with the
// trailing fields omitted is a buffer the module writes past, and a struct with all of them is fifty
// lines of layout that must stay in step with a specification for no benefit.
const tokenInfoBytes = 1024

// The two CK_TOKEN_INFO fields this package reads, by offset and width.
//
// The structure opens with four fixed-width, space-padded character arrays — label[32],
// manufacturerID[32], model[16], serialNumber[16] — and these are the first and the fourth. The two in
// between are skipped rather than read because they name a product line rather than a physical token,
// which is the distinction findSlot matches on. Offsets rather than field names for the reason
// tokenInfoBytes gives: naming them would mean declaring the whole structure.
const (
	tokenLabelOffset  = 0
	tokenLabelBytes   = 32
	tokenSerialOffset = 80
	tokenSerialBytes  = 16
)

// tokenIdentity is what a slot's token calls itself.
//
// The two fields travel together because they come out of one C_GetTokenInfo call and because a
// reference may name either or both: reading the structure once and returning both is cheaper than two
// accessors that each read it, and it is what lets an error message print the serials beside the labels
// without a second pass over the slots.
type tokenIdentity struct {
	// label is CK_TOKEN_INFO.label, which the reference's token= attribute matches.
	label string

	// serial is CK_TOKEN_INFO.serialNumber, which the reference's serial= attribute matches.
	//
	// Empty when the token reports none. That is not an error: the specification pads the field with
	// spaces and does not require it to be meaningful, and some tokens ship blank ones.
	serial string
}

// String renders a token the way an error message names it.
//
// The serial is printed beside the label rather than instead of it, because the commonest cause of a
// reference that matches nothing is a serial read off the wrong sticker — and an operator comparing
// what they typed needs to see both halves of what was actually found.
func (t tokenIdentity) String() string {
	if t.serial == "" {
		return fmt.Sprintf("%q (no serial)", t.label)
	}
	return fmt.Sprintf("%q (serial %s)", t.label, t.serial)
}

// module is a loaded PKCS#11 library and the entry points this package calls.
//
// Each entry point is a Go function value bound to a C function pointer by purego. Binding once at
// load time rather than dispatching per call is what keeps every unsafe conversion in this file to the
// arguments themselves.
type module struct {
	// handle is the loaded library's handle — dlopen's on Unix, LoadLibraryEx's on Windows — closed
	// with the module.
	handle uintptr

	// path is what was loaded, for error messages that name the module rather than the operation.
	path string

	// The bound entry points. Buffers are unsafe.Pointer uniformly rather than typed pointers, so
	// that one rule — "a pointer argument is the address of memory that outlives the call" — covers
	// every one of them.
	initialize        func(args unsafe.Pointer) ckReturn
	finalize          func(reserved unsafe.Pointer) ckReturn
	getSlotList       func(tokenPresent uint8, slots, count unsafe.Pointer) ckReturn
	getTokenInfo      func(slot ckULong, info unsafe.Pointer) ckReturn
	openSession       func(slot, flags ckULong, app, notify, session unsafe.Pointer) ckReturn
	closeSession      func(session ckULong) ckReturn
	login             func(session, userType ckULong, pin unsafe.Pointer, pinLen ckULong) ckReturn
	logout            func(session ckULong) ckReturn
	getAttributeValue func(session, object ckULong, template unsafe.Pointer, count ckULong) ckReturn
	findObjectsInit   func(session ckULong, template unsafe.Pointer, count ckULong) ckReturn
	findObjects       func(session ckULong, objects unsafe.Pointer, max ckULong, count unsafe.Pointer) ckReturn
	findObjectsFinal  func(session ckULong) ckReturn
	signInit          func(session ckULong, mechanism unsafe.Pointer, key ckULong) ckReturn
	sign              func(session ckULong, data unsafe.Pointer, dataLen ckULong,
		signature, signatureLen unsafe.Pointer) ckReturn
}

// ckError is a PKCS#11 return value that is not CKR_OK.
//
// It carries the numeric code as well as the operation, because module-specific failures are searched
// for by number: an operator with a vendor token and a CKR_0x000000d5 has something to look up, and
// "the token refused the operation" has nothing.
type ckError struct {
	// op names the entry point that failed.
	op string

	// rv is the CK_RV the module returned.
	rv ckReturn
}

// Error renders the failure with its code.
func (e ckError) Error() string {
	switch e.rv {
	case ckrPINIncorrect:
		return fmt.Sprintf("pkcs11: %s: the PIN is incorrect (CKR_PIN_INCORRECT). "+
			"Tokens lock the user PIN after a few attempts", e.op)
	case ckrPINLockedOut:
		return fmt.Sprintf("pkcs11: %s: the token has locked this PIN (CKR_PIN_LOCKED). "+
			"Trying again will not help; it needs the security officer's PIN to reset", e.op)
	default:
		return fmt.Sprintf("pkcs11: %s failed with CKR 0x%02X", e.op, e.rv)
	}
}

// check turns a return value into an error, or nil.
func check(op string, rv ckReturn) error {
	if rv == ckrOK {
		return nil
	}
	return ckError{op: op, rv: rv}
}

// openModule loads a PKCS#11 library and binds the entry points this package uses.
//
// C_GetFunctionList is the only symbol resolved by name, because it is the only one the specification
// requires a module to export; the other 67 are pointers inside the struct it fills, and several
// vendor modules export nothing else.
func openModule(path string) (*module, error) {
	handle, err := dlOpen(path)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: cannot load the module %s: %w", path, err)
	}

	var getFunctionList func(list unsafe.Pointer) ckReturn
	if err := bind(handle, &getFunctionList, "C_GetFunctionList"); err != nil {
		_ = dlClose(handle)
		return nil, fmt.Errorf("pkcs11: %s is not a PKCS#11 module: %w", path, err)
	}

	var list *functionList
	if rv := getFunctionList(unsafe.Pointer(&list)); rv != ckrOK {
		_ = dlClose(handle)
		return nil, check("C_GetFunctionList", rv)
	}
	if list == nil {
		_ = dlClose(handle)
		return nil, fmt.Errorf("pkcs11: %s returned no function list", path)
	}

	m := &module{handle: handle, path: path}
	for _, entry := range []struct {
		// index is the entry point's position in CK_FUNCTION_LIST.
		index int

		// target is the address of the field to bind.
		target any
	}{
		{fnInitialize, &m.initialize},
		{fnFinalize, &m.finalize},
		{fnGetSlotList, &m.getSlotList},
		{fnGetTokenInfo, &m.getTokenInfo},
		{fnOpenSession, &m.openSession},
		{fnCloseSession, &m.closeSession},
		{fnLogin, &m.login},
		{fnLogout, &m.logout},
		{fnGetAttributeValue, &m.getAttributeValue},
		{fnFindObjectsInit, &m.findObjectsInit},
		{fnFindObjects, &m.findObjects},
		{fnFindObjectsFinal, &m.findObjectsFinal},
		{fnSignInit, &m.signInit},
		{fnSign, &m.sign},
	} {
		if list.fn[entry.index] == 0 {
			_ = dlClose(handle)
			return nil, fmt.Errorf("pkcs11: %s implements no entry point at index %d", path, entry.index)
		}
		bindAddress(entry.target, list.fn[entry.index])
	}
	return m, nil
}

// bind resolves one named symbol into a Go function value.
func bind(handle uintptr, target any, symbol string) error {
	address, err := dlSym(handle, symbol)
	if err != nil {
		return err
	}
	bindAddress(target, address)
	return nil
}

// bindAddress binds a C function pointer to a Go function value.
//
// It is the one line of purego that is not platform-specific — the call layer supports every platform
// this project builds for, and only the loader in dl_unix.go and dl_windows.go differs — and it is a
// function rather than a call at each site so that the whole of the FFI surface is nameable: `bind`,
// `bindAddress` and the three loader calls, and nothing else in the project touches a C ABI.
func bindAddress(target any, address uintptr) { purego.RegisterFunc(target, address) }

// close releases the library.
func (m *module) close() {
	if m.handle != 0 {
		_ = dlClose(m.handle)
		m.handle = 0
	}
}

// slots lists the slots that currently hold a token.
//
// The two-call idiom every PKCS#11 list uses: ask with a nil buffer to learn the count, allocate, ask
// again. A module may legitimately answer a different count the second time — a token removed between
// the calls — so the returned slice is cut to what the second call reported.
func (m *module) slots() ([]ckULong, error) {
	var count ckULong
	if err := check("C_GetSlotList", m.getSlotList(1, nil, unsafe.Pointer(&count))); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	list := make([]ckULong, count)
	if err := check("C_GetSlotList",
		m.getSlotList(1, unsafe.Pointer(&list[0]), unsafe.Pointer(&count))); err != nil {
		return nil, err
	}
	if int(count) < len(list) {
		list = list[:count]
	}
	return list, nil
}

// tokenInfo returns what a slot's token calls itself, trimmed of the specification's space padding.
func (m *module) tokenInfo(slot ckULong) (tokenIdentity, error) {
	var info [tokenInfoBytes]byte
	if err := check("C_GetTokenInfo", m.getTokenInfo(slot, unsafe.Pointer(&info[0]))); err != nil {
		return tokenIdentity{}, err
	}
	return tokenIdentity{
		label:  trimTokenField(info[tokenLabelOffset : tokenLabelOffset+tokenLabelBytes]),
		serial: trimTokenField(info[tokenSerialOffset : tokenSerialOffset+tokenSerialBytes]),
	}, nil
}

// trimTokenField renders a fixed-width, space-padded PKCS#11 string field.
//
// The specification pads with spaces and does not terminate, so a naive read carries trailing blanks
// into a comparison against an operator's URI and never matches.
func trimTokenField(raw []byte) string {
	end := len(raw)
	for end > 0 && (raw[end-1] == ' ' || raw[end-1] == 0) {
		end--
	}
	return string(raw[:end])
}

// openSessionOn opens a read-only session on a slot.
func (m *module) openSessionOn(slot ckULong) (ckULong, error) {
	var session ckULong
	err := check("C_OpenSession",
		m.openSession(slot, ckfSerialSession, nil, nil, unsafe.Pointer(&session)))
	return session, err
}

// loginUser authenticates as the token's ordinary user.
//
// An empty PIN is passed as a nil pointer with a zero length, which is how the specification spells
// "this token authenticates through its own pad rather than through the caller".
func (m *module) loginUser(session ckULong, pin []byte) error {
	if len(pin) == 0 {
		return check("C_Login", m.login(session, ckuUser, nil, 0))
	}
	return check("C_Login", m.login(session, ckuUser, unsafe.Pointer(&pin[0]), ckULong(len(pin))))
}

// find returns the handles matching a template, up to a bound.
//
// The bound is small and deliberate: this package looks for exactly one key, and a template that
// matched a hundred is a template the caller must make more specific rather than one this package
// should page through.
func (m *module) find(session ckULong, template []ckAttribute, max int) ([]ckULong, error) {
	var templatePtr unsafe.Pointer
	if len(template) > 0 {
		templatePtr = unsafe.Pointer(&template[0])
	}
	if err := check("C_FindObjectsInit",
		m.findObjectsInit(session, templatePtr, ckULong(len(template)))); err != nil {
		return nil, err
	}
	// Finalised on every path, including the error ones: a module that is left mid-search refuses the
	// next C_FindObjectsInit on the same session, which turns one bad template into a session that
	// can no longer look anything up.
	defer func() { _ = m.findObjectsFinal(session) }()

	handles := make([]ckULong, max)
	var found ckULong
	if err := check("C_FindObjects", m.findObjects(session, unsafe.Pointer(&handles[0]),
		ckULong(max), unsafe.Pointer(&found))); err != nil {
		return nil, err
	}
	return handles[:found], nil
}

// attribute reads one attribute's bytes from an object.
//
// The two-call idiom again, and the length call is where a missing attribute is discovered: a module
// answers CKR_ATTRIBUTE_TYPE_INVALID rather than a zero length, so the error is returned rather than
// rendered as an empty value.
func (m *module) attribute(session, object, kind ckULong) ([]byte, error) {
	template := []ckAttribute{{kind: kind}}
	rv := m.getAttributeValue(session, object, unsafe.Pointer(&template[0]), 1)
	if rv != ckrOK && rv != ckrBufferTooSmall {
		return nil, check("C_GetAttributeValue", rv)
	}
	if template[0].valueLen == 0 {
		return nil, nil
	}

	buf := make([]byte, template[0].valueLen)
	template[0].value = unsafe.Pointer(&buf[0])
	if err := check("C_GetAttributeValue",
		m.getAttributeValue(session, object, unsafe.Pointer(&template[0]), 1)); err != nil {
		return nil, err
	}
	return buf[:template[0].valueLen], nil
}

// attributeULong reads an attribute that holds a single CK_ULONG.
func (m *module) attributeULong(session, object, kind ckULong) (ckULong, error) {
	raw, err := m.attribute(session, object, kind)
	if err != nil {
		return 0, err
	}
	if len(raw) != int(unsafe.Sizeof(ckULong(0))) {
		return 0, fmt.Errorf("pkcs11: attribute 0x%X is %d bytes, expected %d",
			kind, len(raw), unsafe.Sizeof(ckULong(0)))
	}
	return *(*ckULong)(unsafe.Pointer(&raw[0])), nil
}

// signData runs C_SignInit and C_Sign over one buffer.
//
// The two-call idiom once more. The digest or payload is passed by address, so it must be non-empty —
// which it always is here, because the caller signs either a canonical JSON document or a SHA-256
// digest of one.
func (m *module) signData(session, key, mechanism ckULong, data []byte) ([]byte, error) {
	mech := ckMechanism{mechanism: mechanism}
	if err := check("C_SignInit", m.signInit(session, unsafe.Pointer(&mech), key)); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("pkcs11: refusing to sign an empty payload")
	}

	var length ckULong
	if err := check("C_Sign", m.sign(session, unsafe.Pointer(&data[0]), ckULong(len(data)),
		nil, unsafe.Pointer(&length))); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, fmt.Errorf("pkcs11: the token reported a zero-length signature")
	}

	signature := make([]byte, length)
	if err := check("C_Sign", m.sign(session, unsafe.Pointer(&data[0]), ckULong(len(data)),
		unsafe.Pointer(&signature[0]), unsafe.Pointer(&length))); err != nil {
		return nil, err
	}
	return signature[:length], nil
}

// sizeOfULong is CK_ULONG's width, for the attribute templates that pass one by address.
const sizeOfULong = unsafe.Sizeof(ckULong(0))

// pointerTo takes the address of a value for a C call.
//
// It exists so that every unsafe.Pointer conversion in the project is in this file: a caller writes
// pointerTo(&x) and never names unsafe at all. The value must outlive the call, which it does at every
// call site because each is a local whose address is taken for the duration of one entry point.
func pointerTo[T any](v *T) unsafe.Pointer { return unsafe.Pointer(v) }
