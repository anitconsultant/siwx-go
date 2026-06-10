# Security Review Pass — pre-v0.1.0

**Date:** 2026-06-10
**Scope:** `tasks/REVIEW-PASS.md` (siws/parse.go, siws/verify.go, siws/base58.go,
internal/invariants, siwx/evm/adapter.go) plus the hub integration that exercises them.
**Mode:** read-only. Findings only; fixes go through normal PRs.
**Baseline:** all tests green; `go vet` clean; siwe-go v0.2.1.

Tag v0.1.0 only after every **Critical/High** finding is dispositioned. This pass
found **no Critical or High** findings. Two **Medium** findings are recommended for
disposition before the tag.

---

## Findings

### M1 — Medium — Hub passes the message's own nonce as `ExpectedNonce`, making the in-library nonce check tautological — ✅ FIXED
**File:** `examples/hub/handlers.go:104,120` (and `:192,204` for `/auth/link`)

**Resolution (2026-06-10):** the nonce is now bound to the client via an HttpOnly,
`SameSite=Lax` cookie set by `GET /auth/nonce`; `postVerify`/`postLink` read the
expected nonce from that cookie — a channel the server controls — instead of
re-deriving it from the message body. The in-library `ExpectedNonce` comparison is now
load-bearing: a message carrying any nonce other than the client's cookie-bound nonce
is rejected by the verifier itself, not only by `Burn`. Same-origin `fetch` sends the
cookie automatically, so no frontend change was needed. Tests:
`TestVerifyRejectsMissingNonceCookie`, `TestVerifyCookieNonceMustMatchMessage`
(plus the existing happy-path/replay tests, updated to carry the cookie). This change
also resolves **I5** — `/auth/link` now uses the request context instead of
`context.Background()`.

The hub extracts the nonce from the attacker-controlled message and then passes that
same value as `VerifyOpts.ExpectedNonce`:

```go
nonce := extractNonce(msg)          // nonce taken FROM the message
...
if err := h.nonces.Burn(ctx, nonce); err != nil { ... }   // the real gate
...
opts := siwx.VerifyOpts{ ExpectedNonce: nonce, ... }       // message-nonce vs itself
```

The adapter then compares `parsed.Nonce == ExpectedNonce` — i.e. the message's nonce
against itself — which always passes. The constant-time nonce comparison in the
library (the S8 protection) is therefore **inert in this integration**.

**Not currently exploitable:** anti-replay still holds because `NonceStore.Burn`
rejects any nonce that was not server-issued or was already used. An attacker cannot
forge a nonce because `Burn` fails closed. The risk is latent: the library-level
defense is silently doing nothing, so a future refactor that weakened or removed
`Burn` would remove *all* nonce protection with no failing test.

**Suggested test:** an integration test that submits a validly signed message whose
nonce was **never issued** by the server, asserting a 401 `nonce-check-failed`. Then a
second test that monkeypatches/bypasses `Burn` and asserts the request is *still*
rejected — proving the library nonce check is load-bearing rather than tautological.

**Suggested direction (for the fix PR):** the server should compare the message nonce
against the value it actually issued, not re-derive "expected" from the message. In
this stateless-per-nonce demo, document explicitly that `Burn` is the sole anti-replay
authority and that `ExpectedNonce` is intentionally redundant.

---

### M2 — Medium — Unbounded input reaches an O(n²) base58 decoder (CPU DoS) — ✅ FIXED
**File:** `examples/hub/handlers.go` (no `http.MaxBytesReader`), `siws/base58.go:28`, `siws/parse.go`

**Resolution (2026-06-10):** three-layer length bound implemented and tested —
`limitBody` middleware (8 KiB) in `examples/hub/main.go`, `maxBase58Len` (128) guard in
`siws/base58.go`, and `maxMessageBytes` (8 KiB) guard in `siws/parse.go`. Tests:
`TestDecodeBase58RejectsOverlongInput`, `TestParseMessageRejectsOversizedInput`,
`TestVerifyRejectsOversizedBody`. The decoder algorithm was intentionally left
unchanged (see rationale below).

The hub never bounds the request body (no `http.MaxBytesReader`, no gin body limit),
and `DecodeBase58` accumulates into a `big.Int` with a multiply-add per character —
**O(n²)** in the length of the address line. A single unauthenticated `POST /auth/verify`
with a multi-megabyte "address" line forces large `big.Int` work before any check runs
(the address is decoded in `parse.go` during `ParseMessage`, ahead of domain/nonce/sig).

**Impact:** unauthenticated CPU exhaustion. Reachable on the public verify endpoint.

**The remedy is to bound the input, not to speed up the decoder.** Base-58 → base-256
conversion has no linear schoolbook algorithm; both the `big.Int` form and the classic
byte-buffer form are O(n²) (the byte-buffer form only improves the constant). A truly
subquadratic decoder (GMP-style divide-and-conquer) is wildly disproportionate for a
44-character public key and would add real risk to a key-decoding primitive — **do not
replace the algorithm.** Legitimate input is tiny and fixed: a 32-byte Solana key is
≤ 44 base58 chars and an SIWS/SIWE message is < 1 KB, so a length cap makes the
asymptotic class irrelevant (O(n²) on n ≤ 44 is ~2k word-ops).

**Suggested test:** a handler test posting a ~5 MB message and asserting a fast
400/413 (bounded latency); unit tests that `DecodeBase58` of an over-long string and
`ParseMessage` of an over-long message both return `ErrMalformed` immediately.

**Suggested direction (three layers, cheapest first):**
1. **Edge:** wrap the request body with `http.MaxBytesReader` (8 KB) in the hub.
2. **Library decoder:** reject `len(s) > maxBase58Len` at the top of `DecodeBase58`.
3. **Parser:** reject `len(b) > maxMessageBytes` at the top of `ParseMessage`, so the
   library is safe regardless of caller.

---

### L1 — Low — `ParseMessage` strips *all* trailing newlines, but the comment says "single"
**File:** `siws/parse.go:23`

```go
// Trim a single trailing newline if present...
b = bytes.TrimRight(b, "\n")   // actually removes ALL trailing '\n'
```

No security impact — `VerifyRaw` verifies the exact wire bytes, so parser leniency here
cannot create a sign-what-you-see mismatch. Correctness/clarity only.

**Suggested test:** `ParseMessage` on a message with two trailing `\n` should either be
rejected or documented as accepted; pin the chosen behavior.

---

### L2 — Low — Optional trailer fields accepted in any order
**File:** `siws/parse.go` (optional-field loop)

`Expiration Time`, `Not Before`, `Request ID`, `Resources` are matched in a `switch`
that accepts them in **any** order (duplicates are rejected, ordering is not enforced).
The SIWS/EIP-4361 ABNF fixes their order. Fail-safe (a reordered message still parses to
the same fields and the signature still binds the exact bytes), but it is a
spec-strictness gap.

**Suggested test:** a vector with `Not Before` before `Expiration Time` — decide whether
that should parse; assert the decision.

---

### L3 — Low — EVM time checks use the injected clock; siwe-go's would not
**File:** `siwx/evm/adapter.go:107`

Our `CheckNotBefore`/`CheckExpiry` use `opts.Clock` (injectable, testable). We call
`siwe-go`'s `VerifyEIP191`, which in v0.2.1 is signature-only, so there is no competing
time source today. If a future siwe-go made `VerifyEIP191` perform internal time checks,
those would use the system clock and diverge from the Observer-reported result.

**Suggested test:** pin siwe-go behavior with a test that verifies an *expired* EVM
message fails via our `CheckExpiry` (ErrExpired) and not via the signature step, using a
frozen clock — so a future lib change that moves the check is caught.

---

### L4 — Low — Invariant suite exercises only the Solana adapter
**File:** `internal/invariants/invariants_test.go:169-182`

`runWithObserver` registers only `solanadapter`. The S3 security invariants and S5
no-leak invariants are proven for Solana but **not** for EVM at the siwx layer; EVM
relies on `siwx/evm/adapter_test.go`. Review item 5 (EVM error-mapping completeness) is
not covered by an invariant.

**Suggested test:** parametrize the invariants over both adapters, or add an EVM mirror
of `TestInvariantWrongKeyNeverVerifies` and `TestInvariantExpiredNeverVerifies`.

---

### Info

- **I1** `invariants_test.go:314` — `TestInvariantS4ErrorTextNeverEchoesInput` has an
  `if err == nil { return }` early-pass. Currently unreachable (the all-zero 64-byte sig
  forces a failure), but it is a latent vacuous escape: if a future change made these
  inputs verify, the test would pass without asserting anything.
- **I2** `invariants_test.go:239-245` — `TestInvariantObserverNoSensitiveData` runs
  `bytes.Contains` against string fields (`Namespace == "solana"`) that can never hold a
  64-byte signature; the assertion is structurally tautological. The real guarantee is
  that the event structs carry no raw-byte fields. `_ = sigStr` is dead.
- **I3** `siws/verify.go:118` — `ConstantTimeCompare` returns early on length mismatch,
  leaking nonce *length* via timing. Negligible (nonce length is not secret).
- **I4** `siws/verify.go:76` — deprecated `Message.Verify()` re-serializes via `String()`
  and is exported; a careless caller could verify against non-wire bytes. Clearly
  documented as deprecated; consider unexporting or removing before v1.0.
- **I5** `examples/hub/handlers.go` — `/auth/link` calls `registry.Verify` with
  `context.Background()` rather than the request context, dropping cancellation/deadline.

---

## Confirmed correct (no action)

- **Check order (S3)** is correct in both adapters: domain → not-before → expiry → nonce
  → signature.
- **Exact length enforcement before `ed25519.Verify`**: 64-byte signature and 32-byte
  public key are both checked first — no panic path into `ed25519.Verify`.
- **base58**: non-ASCII and out-of-alphabet characters rejected; leading zeros preserved;
  empty input degrades safely and is rejected by the 32-byte caller checks.
- **CRLF** is rejected wholesale (`bytes.ContainsRune(b, '\r')`) — no CRLF smuggling.
- **Unicode in domain/statement** fails closed: the domain is compared to
  `ExpectedDomain` byte-for-byte, so a homoglyph domain cannot satisfy the check.
- **VerifyRaw verifies the exact wire bytes** (no re-serialization), so parser leniency
  (L1/L2) cannot produce a signature over bytes that differ from what was displayed.
- **EVM error mapping** (review item 5): parse → `ErrMalformed`, domain →
  `ErrDomainMismatch`, time → `ErrNotYetValid`/`ErrExpired`, nonce → `ErrNonceMismatch`
  (constant-time), signature → `ErrBadSignature`. No siwe-go failure path maps to success
  or to the wrong sentinel; `VerifyEIP191` recovers and compares the signer address, so a
  wrong-key signature fails closed.
- The recent **optional Chain ID** change (`siws/parse.go`) preserves field ordering: an
  out-of-order `Chain ID` line is still rejected as malformed, and absence defaults to
  `mainnet` per SIP-12.
- A positive control exists (`siws/siws_test.go:230`, `VerifyRaw` valid msg+sig → nil),
  so the "NeverVerifies" invariants are not globally vacuous.

---

## Disposition for v0.1.0

No Critical/High → **the tag is not blocked.** Both Mediums are now **fixed and tested**:
**M1** (nonce bound to the client via cookie; in-library check is load-bearing) and
**M2** (three-layer input length bound). **I5** was fixed alongside M1. The remaining
Low/Info items are non-blocking and can be tracked as follow-ups. **Cleared for v0.1.0.**
