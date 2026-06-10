# WT-B — siwx CAIP-122 layer + adapters

Branch: `feat/siwx-layer` · Worktree: `../siwx-go-wt-b` · Depends on: frozen contracts only
Read SPEC.md sections 4, 5, 9. Copy contracts/contracts.go content into
siwx/verifier.go + siwx/observer.go FIRST (split sensibly, keep signatures verbatim,
change package name to siwx).

## Deliverable

Package `siwx`: the chain-agnostic layer. Plus `siwx/solana` and `siwx/evm`
adapters. Until WT-A merges (sync point 1), build `siwx/solana` against the
contract using a stub that returns ErrUnsupportedNamespace, with the real wiring
behind a `//go:build`-free TODO clearly marked; tests for it are written but
skipped with `t.Skip("pending sync point 1")`. Everything else is fully real.

## Files

### siwx/caip.go
CAIP2 / CAIP10 per frozen shapes. `ParseCAIP2(string)`, `ParseCAIP10(string)`,
`String()` methods. Validation per the CAIP specs:
- namespace: `[-a-z0-9]{3,8}`
- reference: `[-_a-zA-Z0-9]{1,32}`
- address: `[-.%a-zA-Z0-9]{1,128}`
Reject anything else with ErrMalformed wrapping. For eip155 addresses, do NOT
lowercase; preserve EIP-55 casing as given.

### siwx/observer.go
Frozen Observer + event structs + `NopObserver{}` + `MultiObserver(...Observer) Observer`
(fans out in order; never panics if an element panics — recover and continue,
this is an observability path, S5 note: it must not take the auth path down).

### siwx/registry.go
`NewRegistry(opts ...RegistryOption) VerifierRegistry`. Map namespace -> Verifier,
mutex-guarded, Register replaces silently (document). Verify():
1. emit OnVerifyAttempt (attemptID generated here if empty — crypto/rand 16 bytes hex)
2. dispatch by chainID.Namespace; missing => OnVerifyResult fail + ErrUnsupportedNamespace
3. delegate to the namespace Verifier, passing opts through (with the generated
   AttemptID and defaulted Observer/Clock so adapters never nil-check).

### siwx/errors.go
The frozen sentinels, verbatim.

### siwx/solana/adapter.go
`New() siwx.Verifier` — Namespace() "solana". Verify():
- emit OnParseResult / OnCheckResult / OnVerifyResult per S3 order by calling
  into `siws` (sync point 1 wiring: siws.VerifyRaw with a thin callback or by
  performing the checks here using siws primitives — choose whichever keeps
  event emission in ONE place; document the choice).
- map siws sentinels -> siwx sentinels (errors.Is must work on BOTH).
- build Identity: Account = CAIP10{solana:<chainID from message>:<address>}.

### siwx/evm/adapter.go
`New() siwx.Verifier` — Namespace() "eip155". Wraps `github.com/spruceid/siwe-go`:
- ParseMessage, then perform domain / time / nonce checks YOURSELF in S3 order
  (do not rely on siwe-go option soup) emitting OnCheckResult per check, then
  signature via message.VerifyEIP191.
- sig comes in as raw bytes; siwe-go expects hex string — adapt at the boundary.
- Account = CAIP10{eip155:<message chain id>:<EIP-55 address>}.
- Map siwe-go errors to siwx sentinels; unknown errors wrap ErrBadSignature or
  ErrMalformed by failure phase, never leak siwe-go types into the API.

## Tests
- caip: table-driven parse/validate/round-trip, fuzz seed corpus strings.
- registry: dispatch, unknown namespace, attemptID generation + propagation
  (use a recording Observer; assert all events share one attemptID, in order:
  Attempt -> Parse -> Check* -> Result).
- evm adapter: generate a secp256k1 key with go-ethereum's crypto package
  (already a transitive dep of siwe-go), sign a SIWE message, verify happy path +
  every failure class. Frozen clock.
- solana adapter: full test file written against vectors.json, `t.Skip` until
  sync point 1; un-skip in the sync-point-1 commit.
- MultiObserver: fan-out order, panic isolation.
- Coverage >= 90%.

## Definition of done
- [ ] Frozen contracts verbatim; `git diff` against contracts/contracts.go shows
      only package-name and file-split changes.
- [ ] go.mod gains ONLY spruceid/siwe-go (+ its transitive deps) — confirm siws/
      remains dep-free by `go list -deps ./siws`.
- [ ] All non-skipped tests green with -race; events ordering test passes.
- [ ] Sync point 1 commit: wire solana adapter, un-skip, vectors pass.
- [ ] PR: `feat(siwx): CAIP-122 verification layer with solana and evm adapters`.
