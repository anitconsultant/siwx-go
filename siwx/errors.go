// Package siwx provides chain-agnostic sign-in verification per CAIP-122.
// It dispatches to per-namespace Verifier implementations via a VerifierRegistry.
package siwx

import "errors"

// Sentinel errors — frozen per contracts/contracts.go.
// Adapters translate namespace-specific errors to these so callers use errors.Is.
var (
	ErrMalformed            = errors.New("siwx: malformed message")
	ErrBadSignature         = errors.New("siwx: signature verification failed")
	ErrExpired              = errors.New("siwx: message expired")
	ErrNotYetValid          = errors.New("siwx: message not yet valid")
	ErrDomainMismatch       = errors.New("siwx: domain mismatch")
	ErrNonceMismatch        = errors.New("siwx: nonce mismatch")
	ErrUnsupportedNamespace = errors.New("siwx: unsupported namespace")
)
