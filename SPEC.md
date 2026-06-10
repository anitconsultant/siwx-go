# siwx-go Build Specification

Module: `github.com/anitconsultant/siwx-go`
License: Dual Apache-2.0 / MIT
Target model: Claude Sonnet 4.6 (Opus-class review pass on `siws/` at the end)
Spec version: 1.0 — 2026-06-09

---

## 1. Mission

Build the missing Go authentication library for the Solana ecosystem:

1. `siws` — a pure, zero-dependency (stdlib + vendored base58 only) implementation of
   Sign-In with Solana message parsing and Ed25519 signature verification, pinned to
   Phantom's published SIWS spec (https://github.com/phantom/sign-in-with-solana).
2. `siwx` — a chain-agnostic CAIP-122 verification layer with pluggable per-chain
   adapters (`siwx/solana` wrapping `siws`, `siwx/evm` wrapping
   `github.com/spruceid/siwe-go`).
3. A runnable example: a mock SSO hub (Gin) + JWT middleware + a single demo web page
   with Phantom and MetaMask sign-in and a `<siwx-progress>` stepper component.

Quality bar: this is a security artifact. Fuzz-tested, invariant-tested,
threat-modeled, CI-gated. It will be submitted for a Solana Foundation grant and
cited in Staff-level interviews. Every shortcut shows.

## 2. Non-goals (explicitly OUT of scope)

- No real OIDC server (no Hydra, no Keycloak). The hub mints JWTs from one
  hardcoded test key behind a `TokenIssuer` interface.
- No persistence. Nonce and identity stores are in-memory behind interfaces.
- No .NET middleware. Go middleware only.
- No passkeys / WebAuthn.
- No logging inside `siws/` or `siwx/`. Libraries report (errors + Observer),
  applications record. The hub demonstrates recording.
- No chains beyond Solana and EVM. The registry makes more chains a new package,
  not a modification.

## 3. Repository layout

```
siwx-go/
├── go.mod                      module github.com/anitconsultant/siwx-go
├── LICENSE-APACHE
├── LICENSE-MIT
├── README.md                   quickstart, badges, install, grant-ready
├── CONTRIBUTING.md
├── CODEOWNERS
├── siws/                       WT-A
│   ├── message.go              Message struct, fields, String() serializer
│   ├── parse.go                ABNF parser (Phantom SIWS grammar)
│   ├── verify.go               Ed25519 verification + time/domain/nonce checks
│   ├── errors.go               sentinel error taxonomy (package-local)
│   ├── base58.go               vendored base58 (btc alphabet), no external dep
│   └── *_test.go
├── siwx/                       WT-B
│   ├── verifier.go             FROZEN contracts (copy from contracts/)
│   ├── registry.go             CAIP-2 namespace -> Verifier dispatch
│   ├── caip.go                 CAIP-2 / CAIP-10 types, parse, validate, String()
│   ├── observer.go             Observer iface, NopObserver, MultiObserver
│   ├── errors.go               shared sentinel errors (siws errors map onto these)
│   ├── solana/adapter.go       wraps ../../siws
│   ├── evm/adapter.go          wraps spruceid/siwe-go
│   └── *_test.go
├── examples/                   WT-C
│   ├── hub/
│   │   ├── main.go             Gin server wiring
│   │   ├── handlers.go         /auth/nonce, /auth/verify, /auth/link, /.well-known/jwks.json
│   │   ├── stores.go           in-memory NonceStore, IdentityStore (interface impls)
│   │   ├── issuer.go           mock TokenIssuer (RS256, hardcoded TEST key)
│   │   ├── observe.go          slog Observer impl + Prometheus-style counters
│   │   └── problems.go         RFC 7807 problem-details responses
│   ├── middleware/
│   │   ├── jwt.go              JWKS-validating Gin middleware
│   │   └── demo.go             one protected endpoint using it
│   └── web/
│       ├── index.html          Phantom + MetaMask sign-in buttons
│       ├── siwx-progress.js    <siwx-progress> web component (stepper)
│       └── app.js              nonce -> sign -> verify -> token flow
├── internal/testvectors/       PROVIDED — do not regenerate
│   └── vectors.json
├── docs/
│   ├── THREAT_MODEL.md         WT-D fills the provided skeleton
│   └── SECURITY.md             disclosure policy (provided)
├── .github/
│   ├── workflows/ci.yml        provided, WT-D may extend
│   ├── workflows/release.yml   WT-D: goreleaser/release-please
│   └── dependabot.yml
└── tasks/                      the four work orders (this kit)
```

## 4. Frozen contracts

The file `contracts/contracts.go` in this kit is LAW. Copy its contents into
`siwx/verifier.go` and `siwx/observer.go` verbatim before any track starts.
No track may alter a frozen signature. If a contract proves wrong, STOP and
surface the conflict to the human rather than silently adapting.

Frozen items (full Go in contracts/contracts.go):

1. `Verifier` interface
2. `VerifyOpts` struct
3. `Identity` struct
4. `Observer` interface (4 methods) + `CheckName` constants
5. `NonceStore`, `IdentityStore`, `TokenIssuer`, `Clock` interfaces
6. `SignatureScheme` interface
7. Sentinel errors: `ErrMalformed`, `ErrBadSignature`, `ErrExpired`,
   `ErrNotYetValid`, `ErrDomainMismatch`, `ErrNonceMismatch`,
   `ErrUnsupportedNamespace`
8. JWT claim shape (documented in contracts/contracts.go comments):
   `sub` = canonical CAIP-10, `iss`, `aud`, `exp`, `iat`, `wallets` []string CAIP-10

## 5. Security requirements (apply to WT-A and WT-B)

- S1. Parser must never panic on any input. Enforced by fuzzing (WT-D).
- S2. All time checks go through the injected `Clock`. `time.Now()` is forbidden
  outside `RealClock`.
- S3. Check order in `Verify`: parse -> domain -> not-before -> expiry -> nonce ->
  signature. Signature verification runs LAST (cheapest rejections first).
  Every check emits `OnCheckResult` whether it passes or fails; verification
  stops at the first failure.
- S4. Error messages must be safe to log verbatim: name the failed check, never
  echo attacker-controlled message content, never include key or signature bytes.
- S5. Observer payloads carry identifiers and verdicts only — never message text,
  never signature bytes (documented in THREAT_MODEL.md).
- S6. Ed25519: reject signatures != 64 bytes and public keys != 32 bytes before
  calling crypto. Use `crypto/ed25519.Verify` only.
- S7. Base58: reject non-alphabet characters; decoded pubkey must be exactly 32 bytes.
- S8. Constant-time comparison (`crypto/subtle`) for nonce equality.
- S9. ParseMessage enforces field order per the ABNF. Unknown trailing lines = ErrMalformed.
- S10. `String()` round-trip: `Parse(m.String())` must equal `m` (fuzz property).

## 6. Test vectors

`internal/testvectors/vectors.json` ships in this kit with REAL Ed25519 keys and
signatures (test-only keys; reference time 2026-06-09T12:00:00Z). Every track that
verifies messages MUST consume these vectors. WT-D owns the loader
(`internal/testvectors/load.go`) and the conformance test that runs all of them.
Valid vectors must verify; invalid vectors must fail with `errors.Is` matching
their `expectedError`. Use a frozen `Clock` set to `referenceTime`.

## 7. Worktree plan

| Track | Branch            | Work order            | Starts | Blocks on |
|-------|-------------------|-----------------------|--------|-----------|
| WT-A  | feat/siws-core    | tasks/WT-A-siws-core.md   | now | nothing |
| WT-B  | feat/siwx-layer   | tasks/WT-B-siwx-layer.md  | now | contracts only |
| WT-C  | feat/mock-hub     | tasks/WT-C-mock-hub.md    | now | contracts only |
| WT-D  | feat/test-harness | tasks/WT-D-test-harness.md| now | contracts only |

Sync point 1: WT-A merges to main -> WT-B rebases and wires `siwx/solana` to the
real `siws` (the adapter is written against the contract from day 0; this is
about an hour of glue + un-skipping tests).

Sync point 2: all of A/B/D merged -> WT-C swaps its stubbed Verifier for the real
registry and runs the E2E harness.

Merge order: A -> B -> D -> C. One squash-merged PR per track. CI must be green
before merge. `scripts/worktrees.sh` sets up the four worktrees.

## 8. Versioning, CI/CD, governance

- SemVer via git tags. First release `v0.1.0`. Do NOT tag v1.0.0 in this build.
- Conventional Commits for every commit (`feat:`, `fix:`, `test:`, `docs:`, `ci:`).
- CI (provided ci.yml): gofmt check, go vet, staticcheck, govulncheck,
  `go test -race ./...`, coverage gate (>= 95% on siws/, >= 90% on siwx/),
  60s fuzz smoke per fuzz target, apidiff job (informational until v1).
- OS matrix: ubuntu-latest, macos-latest, windows-latest. Go: two latest minors.
- release.yml: tag-driven, goreleaser or release-please, changelog from commits.
- dependabot.yml: gomod + github-actions, weekly.
- Every exported symbol gets a doc comment (godoc-ready; pkg.go.dev renders it).
- SECURITY.md (provided) is the disclosure policy. Do not weaken it.

## 9. Error handling & observability philosophy

Libraries report, applications record.

- `siws/` and `siwx/` never import a logger, never print, never expose a log switch.
- They report through (a) the sentinel error taxonomy with `%w` wrapping so callers
  branch on `errors.Is`, and (b) the `Observer` hook (no-op by default).
- The hub (`examples/hub`) is the exemplar of recording: `log/slog` JSON handler,
  request IDs, an Observer implementation that logs every event and increments
  in-memory Prometheus-style counters exposed at `/metrics` (plain text is fine),
  and RFC 7807 problem-details for HTTP errors (internal detail logged, generic
  detail returned).
- Event trail: the verify endpoint returns `checks: [{name, ok, ms}]` assembled
  from Observer events for the attempt, in emission order. This powers the
  `<siwx-progress>` stepper.

## 10. Definition of done (whole repo)

- [ ] All four PRs merged in order; CI green on main.
- [ ] `go test ./...` passes with `-race`; coverage gates met.
- [ ] All fuzz targets run clean for 60s each in CI; corpus seeds committed.
- [ ] Conformance test consumes every vector in vectors.json and passes.
- [ ] E2E harness: nonce -> sign (test keypair) -> verify -> JWT -> middleware
      accepts -> replay of same message+sig rejected with ErrNonceMismatch.
- [ ] `examples/web/index.html` works by hand with Phantom AND MetaMask against
      the running hub (human verifies; document steps in examples/web/README.md).
- [ ] THREAT_MODEL.md complete per its skeleton; SECURITY.md untouched or stronger.
- [ ] README.md: badges (CI, coverage, Go Report Card, pkg.go.dev), install
      one-liner, 20-line quickstart for siws-only and siwx usage, zero-dep
      statement for siws, link to threat model.
- [ ] Tag v0.1.0 ONLY after the human reviews the Opus-pass findings on siws/.

## 11. Model & review routing

Build all tracks with Sonnet 4.6. After merge, run one focused review pass with
an Opus-class model over: `siws/parse.go`, `siws/verify.go`, `siws/base58.go`,
and the invariant suite. The review prompt is in tasks/REVIEW-PASS.md.
