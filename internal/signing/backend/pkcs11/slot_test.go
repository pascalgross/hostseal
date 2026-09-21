package pkcs11

import (
	"strings"
	"testing"
	"unsafe"
)

// These tests drive a fake module rather than SoftHSM, for the reason hang_test.go gives about its own:
// the property under test is what happens when two tokens are plugged in, and no module CI can install
// presents two. module is a plain struct of function fields, so enumerating a token ring is a matter of
// setting two of them — and doing it here rather than with hardware is also what makes the case
// reproducible for a reviewer who has one YubiKey rather than two.

// ckrSlotIDInvalid is what a module answers about a slot it does not have.
//
// Declared here rather than in ffi.go because only the fake needs it: the backend distinguishes no
// return value beyond the four ffi.go names, and adding a fifth for a test to return would put a
// constant in the shipped file that nothing shipped reads.
const ckrSlotIDInvalid ckReturn = 0x03

// tokenRing builds a module that reports one slot per token, in the order given.
//
// The slot numbers deliberately do not start at zero, so that a test cannot pass by accident because
// findSlot returned an index where a slot identifier was meant.
func tokenRing(tokens ...tokenIdentity) *module {
	slots := make([]ckULong, len(tokens))
	for i := range tokens {
		slots[i] = ckULong(10 + i)
	}
	return &module{
		getSlotList: func(_ uint8, out, count unsafe.Pointer) ckReturn {
			// The two-call idiom module.slots uses: a nil buffer asks for the count.
			*(*ckULong)(count) = ckULong(len(slots))
			if out != nil {
				copy(unsafe.Slice((*ckULong)(out), len(slots)), slots)
			}
			return ckrOK
		},
		getTokenInfo: func(slot ckULong, info unsafe.Pointer) ckReturn {
			for i, candidate := range slots {
				if candidate == slot {
					writeTokenInfo(unsafe.Slice((*byte)(info), tokenInfoBytes), tokens[i])
					return ckrOK
				}
			}
			return ckrSlotIDInvalid
		},
	}
}

// writeTokenInfo lays a CK_TOKEN_INFO out the way a module does.
//
// Space padding rather than NUL, because that is what the specification says and it is the half a naive
// reader gets wrong: a label compared without trimming carries trailing blanks and never matches. The
// fake writes what a real module writes so that trimTokenField is exercised rather than bypassed.
func writeTokenInfo(buf []byte, token tokenIdentity) {
	for i := range buf {
		buf[i] = 0
	}
	field := func(offset, width int, value string) {
		for i := range width {
			buf[offset+i] = ' '
		}
		copy(buf[offset:offset+width], value)
	}
	field(tokenLabelOffset, tokenLabelBytes, token.label)
	field(tokenSerialOffset, tokenSerialBytes, token.serial)
}

// slotFor parses a reference and resolves it against a module, as open does.
func slotFor(t *testing.T, mod *module, ref string) (ckULong, error) {
	t.Helper()

	parsed, err := parseURI(ref + ";object=ops-key?module-path=/nonexistent/module.so")
	if err != nil {
		t.Fatalf("parsing %q: %v", ref, err)
	}
	return findSlot(mod, parsed)
}

// TestTwoTokensWithOneLabelAreToldApartBySerial is issue #35.
//
// Two identically provisioned YubiKeys labelled the same is the ordinary state of an operator who keeps
// a spare, and `token=ops` alone then signs with whichever the module enumerated first. Nothing says
// which that was, and the cost lands a layer down and a day later: the signature carries a key id the
// operator did not choose, every host refuses it as coming from no trusted signer, and the operator
// debugs their trust anchor rather than their key ring. serial= is the RFC 7512 attribute for exactly
// this, and this backend accepted and ignored it.
func TestTwoTokensWithOneLabelAreToldApartBySerial(t *testing.T) {
	ring := tokenRing(
		tokenIdentity{label: "ops", serial: "0001"},
		tokenIdentity{label: "ops", serial: "0002"},
		tokenIdentity{label: "spare", serial: "0003"},
	)

	for _, c := range []struct {
		// ref is the token half of the reference, as an operator would write it.
		ref string

		// want is the slot it must resolve to.
		want ckULong
	}{
		{"token=ops;serial=0001", 10},
		{"token=ops;serial=0002", 11},
		// The attribute alone is enough: it names one physical token, so there is nothing left to
		// disambiguate and requiring the label beside it would refuse a reference that is not ambiguous.
		{"serial=0002", 11},
		// A label that only one token carries keeps resolving without a serial, which is every operator
		// who has one token and the reason this is not a refusal in the parser.
		{"token=spare", 12},
		// The order the two are written in is the URI's, not the ring's.
		{"serial=0001;token=ops", 10},
	} {
		got, err := slotFor(t, ring, c.ref)
		if err != nil {
			t.Errorf("%s: %v", c.ref, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s resolved to slot %d, expected %d", c.ref, got, c.want)
		}
	}
}

// TestAnAmbiguousTokenLabelIsRefusedRatherThanGuessed is the half that makes serial= reachable.
//
// Honouring the attribute gives an operator the tool; nothing hands it to them unless the ambiguous
// reference says so. This backend already refuses to choose between several tokens when the reference
// names none, and refuses to choose between several keys when the reference matches more than one —
// maxMatches is two for that reason. A label that two tokens answer to is the same situation, and the
// message has to carry the serials because pasting one back into the reference is the fix.
func TestAnAmbiguousTokenLabelIsRefusedRatherThanGuessed(t *testing.T) {
	ring := tokenRing(
		tokenIdentity{label: "ops", serial: "0001"},
		tokenIdentity{label: "ops", serial: "0002"},
	)

	_, err := slotFor(t, ring, "token=ops")
	if err == nil {
		t.Fatal("a label two tokens answer to resolved to one of them; the same command would sign " +
			"with a different key depending on which token was enumerated first")
	}
	for _, want := range []string{"0001", "0002", "serial="} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so it does not say how to fix it: %v", want, err)
		}
	}
}

// TestSerialIsNotDemandedWhereItCouldNotHelp keeps the refusal above from becoming a regression.
//
// Two matches do not always mean two tokens. A module may enumerate one physical token in two slots,
// and a token may report no serial at all — some ship the field blank. In both cases every match
// carries the same serial, so serial= has nothing to choose between them and refusing would leave an
// operator with a reference that worked yesterday and no attribute that fixes it. The refusal is raised
// only where its own remedy exists.
func TestSerialIsNotDemandedWhereItCouldNotHelp(t *testing.T) {
	for _, c := range []struct {
		// what names the situation.
		what string

		// ring is the tokens the module reports.
		ring *module
	}{
		{"one token enumerated in two slots", tokenRing(
			tokenIdentity{label: "ops", serial: "0001"},
			tokenIdentity{label: "ops", serial: "0001"},
		)},
		{"two tokens that report no serial", tokenRing(
			tokenIdentity{label: "ops"},
			tokenIdentity{label: "ops"},
		)},
	} {
		got, err := slotFor(t, c.ring, "token=ops")
		if err != nil {
			t.Errorf("%s: %v", c.what, err)
			continue
		}
		if got != 10 {
			t.Errorf("%s: resolved to slot %d, expected the first at 10", c.what, got)
		}
	}
}

// TestAReferenceThatMatchesNoTokenSaysWhatIsThere covers the message an operator actually reaches.
//
// The commonest cause of a serial that matches nothing is one read off the wrong sticker, so the error
// has to print the serials beside the labels: an operator comparing what they typed needs both halves
// of what was found, and a message listing only the labels answers a question they did not ask.
func TestAReferenceThatMatchesNoTokenSaysWhatIsThere(t *testing.T) {
	ring := tokenRing(
		tokenIdentity{label: "ops", serial: "0001"},
		tokenIdentity{label: "spare"},
	)

	for _, c := range []struct {
		// ref is the token half of a reference naming nothing on the ring.
		ref string

		// wants are the fragments the refusal has to carry.
		wants []string
	}{
		{"token=ops;serial=9999", []string{`labelled "ops" with serial 9999`, `"ops" (serial 0001)`}},
		{"serial=9999", []string{"has serial 9999", `"ops" (serial 0001)`}},
		{"token=nope", []string{`is labelled "nope"`, `"ops" (serial 0001)`}},
		// A token with no serial is listed as having none rather than as having an empty one, so that
		// the line does not read as a serial the operator failed to type.
		{"token=nope", []string{`"spare" (no serial)`}},
	} {
		_, err := slotFor(t, ring, c.ref)
		if err == nil {
			t.Errorf("%s matched a token that is not present", c.ref)
			continue
		}
		for _, want := range c.wants {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal does not carry %q: %v", c.ref, want, err)
			}
		}
	}
}

// TestSerialMatchingIsByteExact pins the comparison the same way CKA_LABEL matching is pinned.
//
// A serial that differs in case or in padding is a different string to every other tool that speaks
// RFC 7512, and a backend that folded either would resolve a reference to a token the operator did not
// name — which is the failure this change exists to remove, arriving by a different route.
func TestSerialMatchingIsByteExact(t *testing.T) {
	ring := tokenRing(tokenIdentity{label: "ops", serial: "AB01"})

	for _, ref := range []string{"token=ops;serial=ab01", "token=ops;serial=AB01 ", "token=ops;serial=AB0"} {
		if _, err := slotFor(t, ring, ref); err == nil {
			t.Errorf("%q matched a token whose serial is AB01", ref)
		}
	}
	if _, err := slotFor(t, ring, "token=ops;serial=AB01"); err != nil {
		t.Errorf("the exact serial was refused: %v", err)
	}
}

// TestTheURIKeepsAcceptingWhatOtherToolsPrint is the constraint issue #35 puts on the change.
//
// p11tool and p11-kit print token URLs that always carry model=, manufacturer= and serial=, for every
// operator including the single-token case where there is nothing to disambiguate. Honouring serial=
// must not turn the parser into something that refuses those: the reason this backend speaks RFC 7512
// rather than a syntax of its own is that an operator who has configured a token once can paste what
// they already have.
func TestTheURIKeepsAcceptingWhatOtherToolsPrint(t *testing.T) {
	const printed = "model=PKCS%2315%20emulated;manufacturer=piv_II;serial=d276000124010200;token=ops;" +
		"object=ops-yubikey-1?module-path=/usr/lib/opensc-pkcs11.so"

	parsed, err := parseURI(printed)
	if err != nil {
		t.Fatalf("a URL p11-kit prints was refused: %v", err)
	}
	if parsed.serial != "d276000124010200" {
		t.Errorf("serial= parsed as %q", parsed.serial)
	}
	if parsed.token != "ops" || parsed.object != "ops-yubikey-1" {
		t.Errorf("the rest of the reference parsed as %+v", parsed)
	}

	// And the two that stay ignored stay ignored: they name a product line rather than a physical
	// token, so matching on them would add failure modes without adding precision.
	if !parsed.matches(tokenIdentity{label: "ops", serial: "d276000124010200"}) {
		t.Error("the reference does not match the token it names")
	}
}

// TestAReferenceThatNamesNoTokenStillNeedsOneWhenSeveralArePresent keeps the older refusal, and says
// that serial= is now a way out of it.
func TestAReferenceThatNamesNoTokenStillNeedsOneWhenSeveralArePresent(t *testing.T) {
	ring := tokenRing(
		tokenIdentity{label: "ops", serial: "0001"},
		tokenIdentity{label: "spare", serial: "0002"},
	)

	parsed, err := parseURI("object=ops-key?module-path=/nonexistent/module.so")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	_, err = findSlot(ring, parsed)
	if err == nil {
		t.Fatal("a reference naming no token resolved one of two")
	}
	if !strings.Contains(err.Error(), "serial=<serial>") {
		t.Errorf("the refusal does not offer serial= as a way to name one: %v", err)
	}
}

// TestThePINPromptNamesTheTokenTheReferenceNamed covers the words an operator reads at the one moment
// they are being asked for a secret.
//
// A prompt that said "the token" while two are plugged in is a prompt that cannot be answered
// confidently, and serial= is now a way to name one that the prompt has to be able to render.
func TestThePINPromptNamesTheTokenTheReferenceNamed(t *testing.T) {
	for _, c := range []struct {
		// ref is the token half of the reference.
		ref string

		// want is what the prompt has to call it.
		want string
	}{
		{"token=ops", "token ops"},
		{"serial=0001", "the token with serial 0001"},
		{"slot-id=3", "slot 3"},
		{"", "the token"},
		// The label wins when both are given: it is the word the operator chose for the token, and the
		// serial is the number they had to look up.
		{"token=ops;serial=0001", "token ops"},
	} {
		reference := c.ref
		if reference != "" {
			reference += ";"
		}
		parsed, err := parseURI(reference + "object=ops-key?module-path=/nonexistent/module.so")
		if err != nil {
			t.Fatalf("parsing %q: %v", c.ref, err)
		}
		if got := describeToken(parsed); got != c.want {
			t.Errorf("%q prompts for %q, expected %q", c.ref, got, c.want)
		}
	}
}

// unreadableTokens builds a module that lists slots and will not say what is in them.
//
// It exists for the one assertion that slot-id= alone reads no token information: a module whose
// C_GetTokenInfo always fails is the only way to prove a call was not made, and such a module is not
// hypothetical — a slot whose token was pulled between the two calls answers exactly this way.
func unreadableTokens(slots ...ckULong) *module {
	return &module{
		getSlotList: func(_ uint8, out, count unsafe.Pointer) ckReturn {
			*(*ckULong)(count) = ckULong(len(slots))
			if out != nil {
				copy(unsafe.Slice((*ckULong)(out), len(slots)), slots)
			}
			return ckrOK
		},
		getTokenInfo: func(_ ckULong, _ unsafe.Pointer) ckReturn { return ckrSlotIDInvalid },
	}
}

// TestSlotIDIsCheckedAgainstTheAttributesBesideIt is a P1 from the review on this pull request.
//
// slot-id= is checked before the label and now before the serial, and it selects a slot outright. That
// is deliberate and stays. What was wrong is that it also silently overruled the attributes written
// beside it: a reference carrying both slot-id= and serial= honoured the number and ignored the serial,
// so a slot number that had gone stale — and slot numbering is not stable across a replug on every
// module — resolved to whatever token is in that slot now. If that token holds a key with the same
// label, findOne finds it and `hostseal sign` signs with a key the operator did not name.
//
// That is the failure the whole of #35 is about, reached by the one route #35 did not close, and it got
// worse rather than better when serial= started meaning something: the message telling an operator to
// add slot-id= is one this backend now prints itself.
func TestSlotIDIsCheckedAgainstTheAttributesBesideIt(t *testing.T) {
	ring := tokenRing(
		tokenIdentity{label: "ops", serial: "0001"},
		tokenIdentity{label: "ops", serial: "0002"},
		tokenIdentity{label: "spare", serial: "0003"},
	)

	for _, c := range []struct {
		// ref is the token half of the reference.
		ref string

		// want is the slot it must resolve to, or zero when it must be refused.
		want ckULong

		// wants are the fragments a refusal has to carry.
		wants []string
	}{
		// The number and the attributes agree, which is the ordinary case and must not have become
		// slower or stricter.
		{ref: "slot-id=11;serial=0002", want: 11},
		{ref: "slot-id=11;token=ops", want: 11},
		{ref: "slot-id=11;token=ops;serial=0002", want: 11},
		// The number has gone stale and the serial is what notices.
		{ref: "slot-id=10;serial=0002", wants: []string{
			`slot 10 holds "ops" (serial 0001)`, "has serial 0002", "slot-id="}},
		{ref: "slot-id=12;token=ops;serial=0002", wants: []string{
			`slot 12 holds "spare" (serial 0003)`, `is labelled "ops" with serial 0002`}},
		// A label alone still catches a number pointing at a different token.
		{ref: "slot-id=12;token=ops", wants: []string{`slot 12 holds "spare" (serial 0003)`}},
	} {
		got, err := slotFor(t, ring, c.ref)
		if len(c.wants) == 0 {
			if err != nil {
				t.Errorf("%s: %v", c.ref, err)
			} else if got != c.want {
				t.Errorf("%s resolved to slot %d, expected %d", c.ref, got, c.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s resolved to slot %d; the slot number overruled the attribute written to "+
				"check it", c.ref, got)
			continue
		}
		for _, want := range c.wants {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal does not carry %q: %v", c.ref, want, err)
			}
		}
	}
}

// TestSlotIDAloneAsksTheTokenNothing keeps the check above from narrowing the escape hatch.
//
// slot-id= exists for the token this backend cannot otherwise name, and a module that will not report
// on its tokens is one of the reasons somebody reaches for it. A check that read CK_TOKEN_INFO even
// when the reference said nothing to check it against would turn the escape hatch into another way to
// fail, which is the opposite of what it is for.
func TestSlotIDAloneAsksTheTokenNothing(t *testing.T) {
	silent := unreadableTokens(10, 11)

	got, err := slotFor(t, silent, "slot-id=11")
	if err != nil {
		t.Fatalf("slot-id= alone consulted a token that will not answer: %v", err)
	}
	if got != 11 {
		t.Errorf("slot-id=11 resolved to slot %d", got)
	}

	// And a reference that does say something to check keeps failing loudly rather than assuming.
	if _, err := slotFor(t, silent, "slot-id=11;serial=0002"); err == nil {
		t.Error("a serial was treated as confirmed by a token that would not report its own")
	}
}
