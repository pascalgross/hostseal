package pkcs11

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/pascalgross/hostseal/internal/signing"
)

// blockingToken builds a Signer over a fake module whose C_Sign blocks until it is released.
//
// A fake rather than SoftHSM, because the property under test is what happens while the token has not
// answered yet — and SoftHSM, the only module CI has, always answers immediately. That is exactly why
// this went unnoticed: no module available to a test blocks, so nothing exercised the path an operator
// hits the first time they touch a YubiKey and change their mind.
//
// module is a plain struct of function fields, so the whole of what it takes is setting them. handle
// stays zero, which makes module.close a no-op rather than a dlclose of something never opened.
func blockingToken(t *testing.T) (*Signer, chan struct{}, *atomic.Int32) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	release := make(chan struct{})
	var finalized atomic.Int32
	mod := &module{
		signInit: func(_ ckULong, _ unsafe.Pointer, _ ckULong) ckReturn { return ckrOK },
		sign: func(_ ckULong, _ unsafe.Pointer, _ ckULong, _, _ unsafe.Pointer) ckReturn {
			// The finger that never arrives.
			<-release
			return ckrOK
		},
		logout:       func(_ ckULong) ckReturn { return ckrOK },
		closeSession: func(_ ckULong) ckReturn { return ckrOK },
		finalize: func(_ unsafe.Pointer) ckReturn {
			finalized.Add(1)
			return ckrOK
		},
	}
	return &Signer{
		mod: mod, session: 1, private: 2, keyID: "ops-token-1",
		algorithm: signing.ECDSAP256, public: &key.PublicKey,
	}, release, &finalized
}

// TestCloseDoesNotWaitForATokenTheOperatorGaveUpOn is the property issue #22 promises in words.
//
// "A touch-required token waits for a finger, and an operator who changes their mind at that moment
// should be able to interrupt." Sign already honours the context — it watches it beside the goroutine
// and returns — but that only gets the operator their error message. Both signing commands then run a
// deferred Close, and a Close that waits on the token lock hands the terminal back only once the token
// answers, which may be never. The operator sees "signing failed: context deadline exceeded" and then
// a shell that does not come back, with SIGINT already swallowed because the signal handler's channel
// has nobody left reading it.
//
// So the promise is not "Sign returns" but "the process can leave", and this is the assertion for it.
func TestCloseDoesNotWaitForATokenTheOperatorGaveUpOn(t *testing.T) {
	signer, release, finalized := blockingToken(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := signer.Sign(ctx, []byte("payload")); err == nil {
		t.Fatal("a signature against a token that never answered was reported as succeeding")
	}

	// The token is still held by the abandoned goroutine at this point. Close must not wait for it.
	done := make(chan error, 1)
	go func() { done <- signer.Close() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked on a token the operator had already given up on; the command would " +
			"print its failure and then hang, and SIGINT is no longer listened for by then")
	}

	// The half that keeps the assertion above honest. Returning promptly is easy to achieve by simply
	// never tearing the module down — which would leak the library and leave the session open — so the
	// teardown has to be shown to happen, and to happen only once the token has finished with the
	// session it was using.
	if n := finalized.Load(); n != 0 {
		t.Fatalf("the module was finalised %d times while a call was still running on the session; "+
			"dlclose under a live C_Sign unmaps the code the blocked thread is executing", n)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for finalized.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := finalized.Load(); n != 1 {
		t.Fatalf("the module was finalised %d times after the token answered, want exactly once", n)
	}

	// And a second Close is still a no-op, so a caller that defers one after an explicit one cannot
	// tear a module down twice.
	if err := signer.Close(); err != nil {
		t.Fatalf("a second Close: %v", err)
	}
	if n := finalized.Load(); n != 1 {
		t.Fatalf("a second Close finalised the module again: %d", n)
	}
}
