// Package evm provides a siwx.Verifier for the EVM namespace (CAIP-2 "eip155").
// It wraps github.com/spruceid/siwe-go for SIWE message parsing and EIP-191
// signature verification.
package evm

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"time"

	siwelib "github.com/spruceid/siwe-go"

	"github.com/anitconsultant/siwx-go/siwx"
)

type adapter struct{}

// New returns a siwx.Verifier for the "eip155" namespace.
func New() siwx.Verifier { return adapter{} }

// Namespace returns "eip155".
func (adapter) Namespace() string { return "eip155" }

// Verify parses the SIWE message, performs S3-ordered checks with Observer
// events, then verifies the EIP-191 signature.
// sig must be raw 65-byte EIP-191 signature bytes (r+s+v).
func (a adapter) Verify(ctx context.Context, msg []byte, sig []byte, opts siwx.VerifyOpts) (*siwx.Identity, error) {
	obs := opts.Observer
	attemptID := opts.AttemptID

	parsed, parseErr := siwelib.ParseMessage(string(msg))
	obs.OnParseResult(siwx.ParseResult{
		AttemptID: attemptID,
		OK:        parseErr == nil,
		ErrorIs:   mapParseErr(parseErr),
		MsgBytes:  len(msg),
	})
	if parseErr != nil {
		return nil, fmt.Errorf("%w", siwx.ErrMalformed)
	}

	now := opts.Clock.Now()

	type checkStep struct {
		name siwx.CheckName
		fn   func() error
	}
	checks := []checkStep{
		{siwx.CheckDomain, func() error {
			if opts.ExpectedDomain == "" || parsed.GetDomain() != opts.ExpectedDomain {
				return fmt.Errorf("%w", siwx.ErrDomainMismatch)
			}
			return nil
		}},
		{siwx.CheckNotBefore, func() error {
			if nb := parsed.GetNotBefore(); nb != nil {
				t, err := parseISO8601(*nb)
				if err != nil {
					return fmt.Errorf("%w", siwx.ErrMalformed)
				}
				if now.Before(t) {
					return fmt.Errorf("%w", siwx.ErrNotYetValid)
				}
			}
			return nil
		}},
		{siwx.CheckExpiry, func() error {
			if exp := parsed.GetExpirationTime(); exp != nil {
				t, err := parseISO8601(*exp)
				if err != nil {
					return fmt.Errorf("%w", siwx.ErrMalformed)
				}
				if !now.Before(t) {
					return fmt.Errorf("%w", siwx.ErrExpired)
				}
			}
			return nil
		}},
		{siwx.CheckNonce, func() error {
			// Constant-time comparison to resist timing side-channels (S8).
			if subtle.ConstantTimeCompare([]byte(parsed.GetNonce()), []byte(opts.ExpectedNonce)) != 1 {
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

	// Signature: siwe-go VerifyEIP191 expects a 0x-prefixed hex string.
	sigHex := "0x" + hex.EncodeToString(sig)
	start := time.Now()
	_, sigErr := parsed.VerifyEIP191(sigHex)
	obs.OnCheckResult(siwx.CheckResult{
		AttemptID: attemptID,
		Check:     siwx.CheckSignature,
		OK:        sigErr == nil,
		Duration:  time.Since(start),
	})
	if sigErr != nil {
		return nil, fmt.Errorf("%w", siwx.ErrBadSignature)
	}

	issuedAt, _ := parseISO8601(parsed.GetIssuedAt())
	id := &siwx.Identity{
		Account: siwx.CAIP10{
			ChainID: siwx.CAIP2{Namespace: "eip155", Reference: fmt.Sprintf("%d", parsed.GetChainID())},
			Address: parsed.GetAddress().Hex(), // preserves EIP-55 casing
		},
		Domain:   parsed.GetDomain(),
		Nonce:    parsed.GetNonce(),
		IssuedAt: issuedAt,
	}
	if exp := parsed.GetExpirationTime(); exp != nil {
		if t, err := parseISO8601(*exp); err == nil {
			id.ExpiresAt = &t
		}
	}
	return id, nil
}

func mapParseErr(err error) error {
	if err == nil {
		return nil
	}
	return siwx.ErrMalformed
}

// parseISO8601 tries common RFC 3339 / ISO 8601 layouts used by siwe-go.
func parseISO8601(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("evm: unparseable timestamp")
}
