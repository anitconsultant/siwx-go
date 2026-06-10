# WT-A — siws core package

Branch: `feat/siws-core` · Worktree: `../siwx-go-wt-a` · Depends on: nothing
Read SPEC.md sections 4, 5, 6 before writing code.

## Deliverable

Package `siws`: parse and verify Sign-In with Solana messages with ZERO
dependencies beyond the Go standard library. Vendored base58 included.
Authority: Phantom's SIWS spec (EIP-4361-derived ABNF, Solana namespace
CAIP-122 profile at https://namespaces.chainagnostic.org/solana/caip122).

## Files

### siws/message.go
`Message` struct with fields: Domain, Address (base58 string), Statement
(optional), URI, Version (must be "1"), ChainID (default "mainnet"), Nonce,
IssuedAt (time.Time), ExpirationTime (*time.Time), NotBefore (*time.Time),
RequestID (optional string), Resources ([]string, optional).
`(m *Message) String() string` serializes to the exact ABNF text:

```
${domain} wants you to sign in with your Solana account:
${address}

${statement}

URI: ${uri}
Version: ${version}
Chain ID: ${chain-id}
Nonce: ${nonce}
Issued At: ${issued-at}
Expiration Time: ${expiration-time}   (only if set)
Not Before: ${not-before}             (only if set)
Request ID: ${request-id}             (only if set)
Resources:                            (only if non-empty)
- ${resources[0]}
- ${resources[1]}
```

Statement block (line + blank line) appears only when Statement != "".
Timestamps serialize as RFC 3339 with milliseconds and Z (match vectors.json:
`2026-06-09T12:00:00.000Z`). Parse must accept any valid RFC 3339.

### siws/parse.go
`ParseMessage(b []byte) (*Message, error)`. Line-oriented strict parser:
- Field order exactly as above; unknown lines or out-of-order fields => ErrMalformed.
- Address line must be non-empty, base58 alphabet, decode to exactly 32 bytes.
- Nonce: 8+ alphanumeric chars.
- Never panic on any input (fuzzed by WT-D). No regexp catastrophes: use
  manual line scanning, not nested regex.
- Wrap all failures as `fmt.Errorf("...: %w", ErrMalformed)` with a message
  naming the offending FIELD, never echoing its content (S4).

### siws/verify.go
```go
type VerifyOpts struct {            // package-local mirror; siwx adapter maps onto frozen siwx.VerifyOpts
    ExpectedDomain string
    ExpectedNonce  string
    Now            func() time.Time // nil => time.Now
}
func (m *Message) Verify(sig []byte, opts VerifyOpts) error
func VerifyRaw(msg, sig []byte, opts VerifyOpts) (*Message, error) // parse + verify
```
Check order (S3): domain -> not-before -> expiry -> nonce (constant-time,
crypto/subtle) -> Ed25519 signature over the EXACT raw message bytes given to
VerifyRaw (for Verify on a parsed Message, sign over m.String() bytes — document
that VerifyRaw is the safe entry point because it verifies the bytes that were
actually signed). Signature: len must be 64; pubkey from base58 Address, len 32;
`crypto/ed25519.Verify` only. Return package sentinels (errors.go) wrapped with
field context.

### siws/errors.go
Package sentinels mirroring the frozen names: ErrMalformed, ErrBadSignature,
ErrExpired, ErrNotYetValid, ErrDomainMismatch, ErrNonceMismatch.

### siws/base58.go
Vendored Bitcoin-alphabet base58 Decode/Encode. Reject any rune outside the
alphabet. Include the alphabet as a const. ~60 lines. Unit-test against the
addresses in internal/testvectors/vectors.json.

## Tests (in-package; WT-D owns cross-cutting harnesses)

- Table-driven parse tests: every field valid/missing/malformed/out-of-order,
  statement present/absent, all optional fields, CRLF input (reject), trailing
  newline handling (document the choice), empty input, huge input (1MB line).
- Round-trip: for each valid vector message, Parse(String(Parse(msg))) == Parse(msg).
- Verify tests using vectors.json via a relative read of
  `../internal/testvectors/vectors.json` (WT-D will replace with the shared loader;
  keep your loader tiny and local for now).
- Negative crypto: 31/63/65-byte sigs, zero pubkey, flipped sig bit, flipped msg bit.
- Coverage >= 95% lines on the package.

## Definition of done
- [ ] `go test -race ./siws/...` green; coverage >= 95%.
- [ ] `gofmt -l`, `go vet`, `staticcheck` clean.
- [ ] No import outside stdlib in siws/ (CI enforces; verify with `go list -deps`).
- [ ] All vectors.json cases pass with frozen clock at referenceTime.
- [ ] Every exported symbol has a doc comment.
- [ ] Conventional Commits; squash-merge PR titled `feat(siws): zero-dependency SIWS parser and verifier`.
