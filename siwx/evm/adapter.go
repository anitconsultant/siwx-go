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

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	siwelib "github.com/spruceid/siwe-go"

	"github.com/anitconsultant/siwx-go/siwx"
)

var (
	erc1271MagicValue = []byte{0x16, 0x26, 0xba, 0x7e}
	erc1271Selector   = []byte{0x16, 0x26, 0xba, 0x7e}
	erc6492Magic      = common.FromHex("0x6492649264926492649264926492649264926492649264926492649264926492")
)

// ChainClient is the minimal chain access needed for ERC-1271 validation.
type ChainClient interface {
	CallContract(ctx context.Context, to common.Address, data []byte) ([]byte, error)
	CodeAt(ctx context.Context, addr common.Address) ([]byte, error)
}

// Resolver maps a CAIP-2 chain id string (e.g. "eip155:1") to a ChainClient.
type Resolver interface {
	ClientFor(chainID string) (ChainClient, bool)
}

// Option configures the EVM adapter.
type Option func(*adapter)

type adapter struct {
	resolver Resolver
}

// WithChainClient enables opt-in chain access for ERC-1271 contract wallets.
func WithChainClient(r Resolver) Option {
	return func(a *adapter) {
		a.resolver = r
	}
}

// New returns a siwx.Verifier for the "eip155" namespace.
func New(opts ...Option) siwx.Verifier {
	a := &adapter{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

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

	start := time.Now()
	sigErr := a.verifySignature(ctx, parsed, sig)
	obs.OnCheckResult(siwx.CheckResult{
		AttemptID: attemptID,
		Check:     siwx.CheckSignature,
		OK:        sigErr == nil,
		Duration:  time.Since(start),
	})
	if sigErr != nil {
		return nil, sigErr
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

func (a adapter) verifySignature(ctx context.Context, parsed *siwelib.Message, sig []byte) error {
	hash := accounts.TextHash([]byte(parsed.String()))

	// Resolve the opt-in chain client for this message's chain, if any.
	var client ChainClient
	if a.resolver != nil {
		client, _ = a.resolver.ClientFor(fmt.Sprintf("eip155:%d", parsed.GetChainID()))
	}

	// ERC-6492 (counterfactual / wrapped) signatures must be validated deployless
	// on-chain; the universal validator handles every case, so route them whole.
	// Without a deployless-capable client we cannot validate — return a clear
	// error rather than a silent false negative.
	if hasERC6492Suffix(sig) {
		dc, ok := client.(DeploylessCaller)
		if !ok {
			return fmt.Errorf("evm: ERC-6492 signature needs a deployless-capable chain client: %w", siwx.ErrContractWalletUnsupported)
		}
		return validateERC6492(ctx, dc, parsed.GetAddress(), hash, sig)
	}

	// No client configured (or none for this chain): EOA-only, network-free.
	if client == nil {
		return verifyEIP191(parsed, sig)
	}

	addr := parsed.GetAddress()
	code, err := client.CodeAt(ctx, addr)
	if err != nil {
		return fmt.Errorf("evm: code lookup failed: %w: %w", siwx.ErrRPC, err)
	}
	if len(code) == 0 {
		return verifyEIP191(parsed, sig)
	}

	ret, err := client.CallContract(ctx, addr, erc1271Calldata(hash, sig))
	if err != nil {
		return fmt.Errorf("evm: contract signature validation rpc failed: %w: %w", siwx.ErrRPC, err)
	}
	if len(ret) >= len(erc1271MagicValue) && subtle.ConstantTimeCompare(ret[:4], erc1271MagicValue) == 1 {
		return nil
	}
	return fmt.Errorf("evm: ERC-1271 isValidSignature returned invalid magic value: %w", siwx.ErrContractValidationFailed)
}

func verifyEIP191(parsed *siwelib.Message, sig []byte) error {
	// siwe-go VerifyEIP191 expects a 0x-prefixed hex string.
	sigHex := "0x" + hex.EncodeToString(sig)
	if _, err := parsed.VerifyEIP191(sigHex); err != nil {
		return fmt.Errorf("%w", siwx.ErrBadSignature)
	}
	return nil
}

func hasERC6492Suffix(sig []byte) bool {
	return len(sig) >= len(erc6492Magic) &&
		subtle.ConstantTimeCompare(sig[len(sig)-len(erc6492Magic):], erc6492Magic) == 1
}

func erc1271Calldata(hash []byte, sig []byte) []byte {
	paddedSigLen := ((len(sig) + 31) / 32) * 32
	data := make([]byte, 0, len(erc1271Selector)+32+32+32+paddedSigLen)
	data = append(data, erc1271Selector...)
	data = append(data, rightSizedWord(hash)...)
	data = append(data, uint256Word(64)...)
	data = append(data, uint256Word(len(sig))...)
	data = append(data, sig...)
	if pad := paddedSigLen - len(sig); pad > 0 {
		data = append(data, make([]byte, pad)...)
	}
	return data
}

func rightSizedWord(b []byte) []byte {
	word := make([]byte, 32)
	copy(word, b)
	return word
}

func uint256Word(n int) []byte {
	word := make([]byte, 32)
	word[31] = byte(n)
	word[30] = byte(n >> 8)
	word[29] = byte(n >> 16)
	word[28] = byte(n >> 24)
	return word
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
