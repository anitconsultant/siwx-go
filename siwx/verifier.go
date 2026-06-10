package siwx

import (
	"context"
	"time"
)

// VerifyOpts carries the relying party's expectations for one verification call.
type VerifyOpts struct {
	// ExpectedDomain is the RFC 4501 authority the message must name. Required.
	ExpectedDomain string

	// ExpectedNonce is the server-issued nonce the message must carry.
	// Compared in constant time. Required.
	ExpectedNonce string

	// Observer receives lifecycle events. Nil means NopObserver.
	Observer Observer

	// Clock supplies the current time for expiry / not-before checks. Nil means RealClock.
	Clock Clock

	// AttemptID correlates all Observer events for this attempt.
	// Empty string: the registry generates one (crypto/rand hex, 16 bytes).
	AttemptID string
}

// Identity is the verified result.
type Identity struct {
	Account   CAIP10
	Domain    string
	Nonce     string
	IssuedAt  time.Time
	ExpiresAt *time.Time
}

// Verifier verifies one chain namespace's sign-in payload.
type Verifier interface {
	// Namespace returns the CAIP-2 namespace this verifier handles, e.g. "solana".
	Namespace() string
	Verify(ctx context.Context, msg []byte, sig []byte, opts VerifyOpts) (*Identity, error)
}

// VerifierRegistry dispatches verification to the appropriate namespace Verifier.
type VerifierRegistry interface {
	Register(v Verifier)
	Verify(ctx context.Context, chainID CAIP2, msg []byte, sig []byte, opts VerifyOpts) (*Identity, error)
}

// Clock supplies the current time. Nil fields on VerifyOpts use RealClock.
type Clock interface {
	Now() time.Time
}

// RealClock returns the actual wall-clock time.
type RealClock struct{}

// Now returns time.Now().
func (RealClock) Now() time.Time { return time.Now() }
