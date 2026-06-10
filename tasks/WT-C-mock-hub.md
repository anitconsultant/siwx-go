# WT-C — mock hub, middleware, demo web page

Branch: `feat/mock-hub` · Worktree: `../siwx-go-wt-c` · Depends on: frozen contracts only
Read SPEC.md sections 2, 4, 9. Until sync point 2, compile against a local
`stubVerifierRegistry` that approves a hardcoded test vector; swap for the real
registry in the sync-point-2 commit.

## Deliverable

`examples/hub` (Gin), `examples/middleware`, `examples/web`. This is the
EXEMPLAR of "applications record": slog, metrics, problem-details, and the
`<siwx-progress>` stepper. It is also the grant-application screenshot.

## Hub endpoints

| Method | Path | Behavior |
|---|---|---|
| GET  | /auth/nonce | NonceStore.Issue(ttl=10m) -> `{"nonce": "..."}` |
| POST | /auth/verify | body: `{message(b64), signature(b64), chainId("solana:mainnet" etc.)}` -> verify via registry -> NonceStore.Burn -> IdentityStore.Upsert -> TokenIssuer.Issue -> `{"token": "...", "identityId": "...", "checks": [{name, ok, ms}...]}` |
| POST | /auth/link | requires Bearer token; same body; links wallet to the session identity |
| GET  | /.well-known/jwks.json | TokenIssuer.JWKS() |
| GET  | /metrics | plain-text counters |
| GET  | /healthz | 200 ok |
| GET  | / | serves examples/web statically |

## Files

### examples/hub/stores.go
In-memory NonceStore (map + per-entry expiry, swept lazily on Issue/Burn;
single-use enforced — Burn deletes; second Burn => ErrNonceMismatch) and
IdentityStore (maps walletCAIP10 -> identityID, identityID -> []wallets).
Mutex-guarded. Both implement the frozen interfaces EXACTLY so Redis/Postgres
swap in later via DI.

### examples/hub/issuer.go
Mock TokenIssuer: RS256 (github.com/golang-jwt/jwt/v5), one keypair GENERATED
AT STARTUP (never committed), kid = "mock-1", claims per the frozen JWT shape,
exp = 1h. JWKS() serves the public key. File-top comment: NOT FOR PRODUCTION.

### examples/hub/observe.go
`Recorder` implementing siwx.Observer:
- logs every event via slog (JSON handler) with attemptID, plus request ID
  from Gin context where available
- counters: verify_attempts_total, verify_failures_total{reason}, checks_failed_total{check},
  nonces_issued_total, nonces_burned_total, tokens_issued_total — rendered at /metrics
- buffers per-attempt CheckResult events (bounded map keyed by attemptID,
  evicted on VerifyResult) so handlers can return the `checks` trail.
NEVER stores message text or signature bytes (S5).

### examples/hub/problems.go
RFC 7807 responses: type (a docs URL slug per sentinel), title, status, detail
(GENERIC: "nonce check failed" — internal specifics go to slog only), instance
(request ID). Map: ErrMalformed->400, ErrDomainMismatch/ErrNonceMismatch/
ErrExpired/ErrNotYetValid/ErrBadSignature->401, ErrUnsupportedNamespace->422.

### examples/middleware/jwt.go
Gin middleware: fetch JWKS from a configured URL once + refresh on unknown kid,
validate RS256 token (exp, iss, aud), inject identityID + wallets into context.
demo.go: GET /me returns the claims — the "ride accepts the wristband" proof.

### examples/web/
- index.html: two buttons (Phantom, MetaMask), the stepper, minimal clean CSS.
- app.js: nonce -> wallet sign -> POST verify -> render token + decoded claims.
  Phantom: `window.phantom.solana.signIn({domain, nonce, statement})` ->
  signedMessage/signature are byte arrays -> base64. chainId "solana:mainnet".
  MetaMask: build the EIP-4361 message string client-side (domain, address from
  eth_requestAccounts, nonce, issuedAt now, expirationTime +10m, chainId 1),
  `personal_sign` -> hex sig -> convert to base64 of raw bytes. chainId "eip155:1".
- siwx-progress.js: framework-agnostic Web Component `<siwx-progress>`:
  attribute/property `steps` = JSON array [{id, label, state: pending|active|done|failed, subchecks?: [{name, ok, ms}]}].
  Renders the stepper from the conversation mock: dimmed pending, spinner active,
  check done, red failed with the error class name. Steps 1-2 driven by app.js
  (wallet events); steps 3-5 animated in sequence from the verify response's
  `checks` trail (with ~150ms stagger so humans see it). No framework, no deps.
- README.md: how to run hub + open page + hand-test with both wallet extensions,
  with the httpOnly-cookie note for production.

## Tests
- httptest E2E (Go): full flow with a test Ed25519 keypair signing a SIWS message
  (use siws.Message.String() after sync point 2; before it, the stub) ->
  token -> middleware /me 200 -> REPLAY same message+sig -> 401 problem-details
  with nonce reason; second flow for EVM with a generated secp256k1 key.
- stores: nonce single-use, expiry honored with frozen clock; identity upsert/link.
- issuer/middleware: bad sig, expired token, wrong aud, unknown kid refresh path.
- problems: each sentinel maps to documented status + generic detail.
- Front-end: keep JS dependency-free; correctness is covered by the Go E2E plus
  the documented manual wallet test (DoD item).

## Definition of done
- [ ] `go run ./examples/hub` serves everything; flow works by hand with Phantom
      and MetaMask (document evidence in examples/web/README.md).
- [ ] E2E tests green with -race; replay rejection proven.
- [ ] slog output line per Observer event with shared attemptID; /metrics moves.
- [ ] checks trail in verify response matches Observer emission order (assert in E2E).
- [ ] PR: `feat(examples): mock SSO hub, JWT middleware, wallet demo with progress stepper`.
