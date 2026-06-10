// Package siws implements Sign-In With Solana (SIWS) message parsing and
// Ed25519 signature verification. It has no dependencies outside the standard
// library.
package siws

import "errors"

// Sentinel errors. siwx adapters wrap these so callers use errors.Is.
var (
	ErrMalformed      = errors.New("siws: malformed message")
	ErrBadSignature   = errors.New("siws: signature verification failed")
	ErrExpired        = errors.New("siws: message expired")
	ErrNotYetValid    = errors.New("siws: message not yet valid")
	ErrDomainMismatch = errors.New("siws: domain mismatch")
	ErrNonceMismatch  = errors.New("siws: nonce mismatch")
)
