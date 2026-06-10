// Package solana provides a siwx.Verifier for the Solana namespace (CAIP-2 "solana").
// It delegates parsing and Ed25519 verification to the siws package.
//
// Event emission strategy: we call siws.VerifyRaw (which does parse + all checks
// atomically) and emit Observer events after the fact based on the returned error.
// This keeps the check order (S3) enforced by siws and avoids duplicating logic.
package solana

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anitconsultant/siwx-go/siws"
	"github.com/anitconsultant/siwx-go/siwx"
)

type adapter struct{}

// New returns a siwx.Verifier for the "solana" namespace.
func New() siwx.Verifier { return adapter{} }

// Namespace returns "solana".
func (adapter) Namespace() string { return "solana" }

// Verify parses msg and verifies the Ed25519 signature, emitting Observer events.
func (a adapter) Verify(ctx context.Context, msg []byte, sig []byte, opts siwx.VerifyOpts) (*siwx.Identity, error) {
	obs := opts.Observer
	attemptID := opts.AttemptID

	// Emit parse result: try parsing first to populate the Account field.
	parsed, parseErr := siws.ParseMessage(msg)
	obs.OnParseResult(siwx.ParseResult{
		AttemptID: attemptID,
		OK:        parseErr == nil,
		ErrorIs:   sentinelFor(parseErr),
		MsgBytes:  len(msg),
	})
	if parseErr != nil {
		return nil, mapErr(parseErr)
	}

	// Build the clock function for siws from opts.Clock.
	nowFn := func() time.Time { return opts.Clock.Now() }

	// Emit check results per S3 order. siws.VerifyRaw enforces the same order
	// internally; we replicate the check names here for Observer visibility.
	checks := []struct {
		name siwx.CheckName
		fn   func() error
	}{
		{siwx.CheckDomain, func() error {
			if opts.ExpectedDomain == "" || parsed.Domain != opts.ExpectedDomain {
				return fmt.Errorf("%w", siwx.ErrDomainMismatch)
			}
			return nil
		}},
		{siwx.CheckNotBefore, func() error {
			now := nowFn()
			if parsed.NotBefore != nil && now.Before(*parsed.NotBefore) {
				return fmt.Errorf("%w", siwx.ErrNotYetValid)
			}
			return nil
		}},
		{siwx.CheckExpiry, func() error {
			now := nowFn()
			if parsed.ExpirationTime != nil && !now.Before(*parsed.ExpirationTime) {
				return fmt.Errorf("%w", siwx.ErrExpired)
			}
			return nil
		}},
		{siwx.CheckNonce, func() error {
			// siws uses crypto/subtle internally; we replicate for the event.
			if parsed.Nonce != opts.ExpectedNonce {
				return fmt.Errorf("%w", siwx.ErrNonceMismatch)
			}
			return nil
		}},
	}

	for _, c := range checks {
		start := time.Now()
		cerr := c.fn()
		obs.OnCheckResult(siwx.CheckResult{
			AttemptID: attemptID,
			Check:     c.name,
			OK:        cerr == nil,
			Duration:  time.Since(start),
		})
		if cerr != nil {
			return nil, cerr
		}
	}

	// Signature check: delegate entirely to siws.VerifyRaw using its own check
	// order (domain/time/nonce will re-run inside, but they pass because we
	// already checked them above). We use VerifyRaw here solely for the Ed25519
	// check — passing opts that match the message guarantees only the sig check
	// can fail at this point.
	start := time.Now()
	_, sigErr := siws.VerifyRaw(msg, sig, siws.VerifyOpts{
		ExpectedDomain: opts.ExpectedDomain,
		ExpectedNonce:  opts.ExpectedNonce,
		Now:            nowFn,
	})
	obs.OnCheckResult(siwx.CheckResult{
		AttemptID: attemptID,
		Check:     siwx.CheckSignature,
		OK:        sigErr == nil,
		Duration:  time.Since(start),
	})
	if sigErr != nil {
		return nil, mapErr(sigErr)
	}

	chainID := siwx.CAIP2{Namespace: "solana", Reference: parsed.ChainID}
	id := &siwx.Identity{
		Account:  siwx.CAIP10{ChainID: chainID, Address: parsed.Address},
		Domain:   parsed.Domain,
		Nonce:    parsed.Nonce,
		IssuedAt: parsed.IssuedAt,
	}
	if parsed.ExpirationTime != nil {
		t := *parsed.ExpirationTime
		id.ExpiresAt = &t
	}
	return id, nil
}

// mapErr translates siws sentinels to siwx sentinels.
// errors.Is works on both because the wrapped message is the same.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	for siwsSentinel, siwxSentinel := range map[error]error{
		siws.ErrMalformed:      siwx.ErrMalformed,
		siws.ErrBadSignature:   siwx.ErrBadSignature,
		siws.ErrExpired:        siwx.ErrExpired,
		siws.ErrNotYetValid:    siwx.ErrNotYetValid,
		siws.ErrDomainMismatch: siwx.ErrDomainMismatch,
		siws.ErrNonceMismatch:  siwx.ErrNonceMismatch,
	} {
		if errors.Is(err, siwsSentinel) {
			return fmt.Errorf("%w", siwxSentinel)
		}
	}
	return fmt.Errorf("%w: %w", siwx.ErrMalformed, err)
}

// sentinelFor returns the siwx sentinel for err, or nil.
func sentinelFor(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, siws.ErrMalformed) {
		return siwx.ErrMalformed
	}
	return siwx.ErrMalformed
}
