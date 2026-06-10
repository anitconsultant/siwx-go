package siws

import (
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"time"
)

// VerifyOpts carries the relying-party expectations for one verification call.
// This is the package-local mirror; the siwx adapter maps it onto the frozen
// siwx.VerifyOpts from contracts/contracts.go.
type VerifyOpts struct {
	// ExpectedDomain is the authority the message must name. Required.
	ExpectedDomain string

	// ExpectedNonce is the server-issued nonce the message must carry.
	// Compared in constant time. Required.
	ExpectedNonce string

	// Now returns the current time for expiry / not-before checks.
	// Nil means time.Now.
	Now func() time.Time
}

func (o VerifyOpts) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// VerifyRaw parses msg and verifies that sig is a valid Ed25519 signature over
// the exact bytes of msg. It is the safe entry point: the signature covers
// whatever bytes the wallet actually received, so no re-serialization occurs.
//
// Check order (S3): domain → not-before → expiry → nonce → Ed25519.
//
// Both ExpectedDomain and ExpectedNonce must be non-empty; empty values are a
// programmer error and return ErrMalformed immediately.
func VerifyRaw(msg, sig []byte, opts VerifyOpts) (*Message, error) {
	if opts.ExpectedDomain == "" || opts.ExpectedNonce == "" {
		return nil, fmt.Errorf("verify: ExpectedDomain and ExpectedNonce are required: %w", ErrMalformed)
	}
	m, err := ParseMessage(msg)
	if err != nil {
		return nil, err
	}
	if err := checkDomain(m, opts.ExpectedDomain); err != nil {
		return nil, err
	}
	now := opts.now()
	if err := checkNotBefore(m, now); err != nil {
		return nil, err
	}
	if err := checkExpiry(m, now); err != nil {
		return nil, err
	}
	if err := checkNonce(m, opts.ExpectedNonce); err != nil {
		return nil, err
	}
	if err := checkSig(m.Address, msg, sig); err != nil {
		return nil, err
	}
	return m, nil
}

// Verify verifies sig against the re-serialized form of m (m.String()).
//
// Deprecated: prefer VerifyRaw, which verifies the exact bytes the wallet
// signed. This method re-serializes the parsed struct via String(), so if any
// timestamp or optional field was stored in a non-canonical format during
// parsing, the re-serialized bytes differ from what was signed and verification
// fails with ErrBadSignature even for a valid signature. Use VerifyRaw(rawBytes,
// sig, opts) whenever the original wire bytes are available.
func (m *Message) Verify(sig []byte, opts VerifyOpts) error {
	if opts.ExpectedDomain == "" || opts.ExpectedNonce == "" {
		return fmt.Errorf("verify: ExpectedDomain and ExpectedNonce are required: %w", ErrMalformed)
	}
	if err := checkDomain(m, opts.ExpectedDomain); err != nil {
		return err
	}
	now := opts.now()
	if err := checkNotBefore(m, now); err != nil {
		return err
	}
	if err := checkExpiry(m, now); err != nil {
		return err
	}
	if err := checkNonce(m, opts.ExpectedNonce); err != nil {
		return err
	}
	return checkSig(m.Address, []byte(m.String()), sig)
}

func checkDomain(m *Message, expected string) error {
	if expected == "" || m.Domain != expected {
		return fmt.Errorf("verify: domain mismatch: %w", ErrDomainMismatch)
	}
	return nil
}

func checkNotBefore(m *Message, now time.Time) error {
	if m.NotBefore != nil && now.Before(*m.NotBefore) {
		return fmt.Errorf("verify: message not yet valid: %w", ErrNotYetValid)
	}
	return nil
}

func checkExpiry(m *Message, now time.Time) error {
	if m.ExpirationTime != nil && !now.Before(*m.ExpirationTime) {
		return fmt.Errorf("verify: message expired: %w", ErrExpired)
	}
	return nil
}

// checkNonce compares the nonce in constant time to resist timing attacks.
// ConstantTimeCompare short-circuits on a length mismatch, leaking only the
// nonce length — never its contents. Nonces are fixed-format server-issued
// tokens, so their length is not secret; this residual channel is accepted.
func checkNonce(m *Message, expected string) error {
	if subtle.ConstantTimeCompare([]byte(m.Nonce), []byte(expected)) != 1 {
		return fmt.Errorf("verify: nonce mismatch: %w", ErrNonceMismatch)
	}
	return nil
}

func checkSig(addressBase58 string, msg, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("verify: signature must be %d bytes: %w", ed25519.SignatureSize, ErrBadSignature)
	}
	pubKeyBytes, err := DecodeBase58(addressBase58)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("verify: invalid public key: %w", ErrBadSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), msg, sig) {
		return fmt.Errorf("verify: signature invalid: %w", ErrBadSignature)
	}
	return nil
}
