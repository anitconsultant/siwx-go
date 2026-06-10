// Package contracts contains the FROZEN interface contracts for siwx-go.
//
// LAW: Copy these declarations verbatim into siwx/verifier.go and
// siwx/observer.go before any worktree begins. No track may change a
// signature here. If a contract is wrong, STOP and ask the human.
//
// JWT CLAIM SHAPE (frozen, implemented by TokenIssuer):
//
//	sub     string   canonical identity wallet as CAIP-10 (e.g. "solana:mainnet:7S3P...")
//	iss     string   hub issuer URL (e.g. "https://accounts.dapp.academy")
//	aud     []string spoke app identifiers
//	exp     int64    unix seconds
//	iat     int64    unix seconds
//	wallets []string all linked wallets as CAIP-10
package contracts

import (
	"context"
	"errors"
	"time"
)

// ---------------------------------------------------------------------------
// Sentinel errors. siws defines its own equivalents; siwx adapters translate
// so callers always branch on these via errors.Is.
// ---------------------------------------------------------------------------

var (
	ErrMalformed            = errors.New("siwx: malformed message")
	ErrBadSignature         = errors.New("siwx: signature verification failed")
	ErrExpired              = errors.New("siwx: message expired")
	ErrNotYetValid          = errors.New("siwx: message not yet valid")
	ErrDomainMismatch       = errors.New("siwx: domain mismatch")
	ErrNonceMismatch        = errors.New("siwx: nonce mismatch")
	ErrUnsupportedNamespace = errors.New("siwx: unsupported namespace")
)

// ---------------------------------------------------------------------------
// Core verification contract
// ---------------------------------------------------------------------------

// VerifyOpts carries the relying party's expectations for one verification.
type VerifyOpts struct {
	// ExpectedDomain is the RFC 4501 authority the message must name.
	// Required; empty string is a programmer error (return ErrDomainMismatch).
	ExpectedDomain string

	// ExpectedNonce is the server-issued nonce the message must carry.
	// Compared in constant time. Required.
	ExpectedNonce string

	// Observer receives lifecycle events. Nil means NopObserver.
	Observer Observer

	// Clock supplies time for expiry / not-before checks. Nil means RealClock.
	Clock Clock

	// AttemptID correlates all Observer events for this attempt.
	// Empty string: the Verifier generates one (crypto/rand, hex, 16 bytes).
	AttemptID string
}

// Identity is the verified result: who signed, for which site, when.
type Identity struct {
	// Account is the signer as CAIP-10, e.g. "solana:mainnet:7S3P..." or
	// "eip155:1:0xAb5801a7D398351b8bE11C439e05C5b3259aeC9B".
	Account CAIP10

	Domain    string
	Nonce     string
	IssuedAt  time.Time
	ExpiresAt *time.Time // nil if the message carried no Expiration Time
}

// Verifier verifies one chain namespace's sign-in payload.
// msg is the raw signed message bytes (UTF-8 text for both SIWS and SIWE).
// sig is the raw signature bytes (decoded from base58/base64/hex by the caller).
type Verifier interface {
	// Namespace returns the CAIP-2 namespace this verifier handles,
	// e.g. "solana" or "eip155".
	Namespace() string

	Verify(ctx context.Context, msg []byte, sig []byte, opts VerifyOpts) (*Identity, error)
}

// VerifierRegistry dispatches by CAIP-2 chain ID (e.g. "solana:mainnet",
// "eip155:1") to the Verifier registered for its namespace.
type VerifierRegistry interface {
	Register(v Verifier)
	// Verify routes to the namespace verifier; ErrUnsupportedNamespace if none.
	Verify(ctx context.Context, chainID CAIP2, msg []byte, sig []byte, opts VerifyOpts) (*Identity, error)
}

// ---------------------------------------------------------------------------
// CAIP types (implemented in siwx/caip.go; shapes frozen)
// ---------------------------------------------------------------------------

// CAIP2 is a chain ID: namespace + ":" + reference, e.g. "solana:mainnet".
type CAIP2 struct {
	Namespace string // [-a-z0-9]{3,8}
	Reference string // [-_a-zA-Z0-9]{1,32}
}

// CAIP10 is an account ID: CAIP2 + ":" + address.
type CAIP10 struct {
	ChainID CAIP2
	Address string
}

// ---------------------------------------------------------------------------
// Observer: the only window into the library. Identifiers and verdicts ONLY.
// Never message text, never signature bytes, never key material.
// ---------------------------------------------------------------------------

type CheckName string

const (
	CheckDomain    CheckName = "domain"
	CheckNotBefore CheckName = "not_before"
	CheckExpiry    CheckName = "expiry"
	CheckNonce     CheckName = "nonce"
	CheckSignature CheckName = "signature"
)

type VerifyAttempt struct {
	AttemptID string
	Namespace string // CAIP-2 namespace
	Domain    string // expected domain from opts
	Account   string // CAIP-10 string; empty until parse succeeds
}

type ParseResult struct {
	AttemptID string
	OK        bool
	ErrorIs   error // sentinel (ErrMalformed) or nil
	MsgBytes  int
}

type CheckResult struct {
	AttemptID string
	Check     CheckName
	OK        bool
	Duration  time.Duration
}

type VerifyResult struct {
	AttemptID string
	OK        bool
	ErrorIs   error // terminal sentinel or nil
	Namespace string
	Duration  time.Duration
}

// Observer receives verification lifecycle events. Implementations must be
// safe for concurrent use and must not block (fire-and-forget semantics;
// heavy work goes in the implementation's own goroutine/buffer).
type Observer interface {
	OnVerifyAttempt(e VerifyAttempt)
	OnParseResult(e ParseResult)
	OnCheckResult(e CheckResult)
	OnVerifyResult(e VerifyResult)
}

// NopObserver and MultiObserver(...Observer) ship in siwx/observer.go.

// ---------------------------------------------------------------------------
// Pluggable infrastructure seams (hub uses these; library never does)
// ---------------------------------------------------------------------------

type Clock interface {
	Now() time.Time
}

// NonceStore issues single-use nonces. Burn returns ErrNonceMismatch if the
// nonce is unknown, expired, or already burned.
type NonceStore interface {
	Issue(ctx context.Context, ttl time.Duration) (nonce string, err error)
	Burn(ctx context.Context, nonce string) error
}

// IdentityStore maps wallets to identities. First wallet creates; later
// wallets link (only while the caller holds a valid session — enforced by
// the hub handler, not the store).
type IdentityStore interface {
	UpsertByWallet(ctx context.Context, w CAIP10) (identityID string, created bool, err error)
	LinkWallet(ctx context.Context, identityID string, w CAIP10) error
	Wallets(ctx context.Context, identityID string) ([]CAIP10, error)
}

// TokenIssuer mints the session credential for a verified identity.
type TokenIssuer interface {
	Issue(ctx context.Context, identityID string, wallets []CAIP10) (token string, err error)
	// JWKS returns the JSON Web Key Set document for spoke validation.
	JWKS(ctx context.Context) ([]byte, error)
}

// SignatureScheme abstracts the raw crypto under a Verifier so future curves
// slot in without touching parsers.
type SignatureScheme interface {
	// Name, e.g. "ed25519" or "secp256k1".
	Name() string
	// Verify reports whether sig is a valid signature of msg under pubKey.
	Verify(pubKey, msg, sig []byte) bool
}
