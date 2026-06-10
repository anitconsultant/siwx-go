# Threat Model — siwx-go

## 1. Assets

| Asset | Description | Sensitivity |
|---|---|---|
| User identity binding | The mapping of a wallet address to a session | Critical — forgery bypasses auth entirely |
| Session issuance authority | The hub's ability to issue JWT access tokens | Critical — compromise grants attacker access to all spokes |
| Nonce store integrity | Server-managed single-use nonces | High — replay attacks require nonce reuse |
| Private key material | Ed25519 / secp256k1 keys held in user wallets | Out of scope (not held by this library) |

## 2. Trust boundaries

```
[User wallet]  <--sign-->  [Browser / dApp frontend]
                                    |
                              (message + sig)
                                    |
                              [siwx-go Hub]  <-- this library's verification boundary
                               /        \
                  [JWT access token]    [Spoke APIs]
```

Boundaries:
- **Wallet → Frontend**: HTTPS + wallet extension RPC. Library does not own this boundary.
- **Frontend → Hub**: HTTPS POST carrying raw message bytes and signature bytes. The library receives these at `registry.Verify`. Anything arriving here could be attacker-controlled.
- **Hub → Spokes**: JWT bearer tokens. Spoke validation is outside this library's scope; examples/middleware provides a reference implementation.

## 3. Attacker capabilities assumed

| Attacker | Capability |
|---|---|
| Network observer | Can read all cleartext traffic |
| Replay attacker | Replays a previously captured valid (message, signature) pair |
| Phishing operator | Runs a look-alike site; users sign messages with their wallet on the phishing site |
| Malformed-input fuzzer | Sends arbitrary byte sequences as message or signature |
| Compromised nonce store | Attempts to reuse a consumed nonce |

## 4. Controls and what each defeats

| Control | Defeats | Proven by (test) |
|---|---|---|
| Server-issued single-use nonce | Replay attacks — stale signatures are rejected | `TestInvariantWrongNonceNeverVerifies`, `TestSIWSInvalidVectors/tampered_nonce` |
| Domain binding check | Phishing relay — messages signed for attacker's domain rejected by victim's hub | `TestInvariantWrongDomainNeverVerifies`, `TestSIWSInvalidVectors/domain_mismatch_check` |
| Expiry / Not Before windows | Stale capture — captured messages expire; future-dated messages rejected before valid | `TestInvariantExpiredNeverVerifies`, `TestInvariantFutureNotBeforeNeverVerifies` |
| Ed25519 / EIP-191 signature | Forgery, tamper — any bit change in message or wrong key fails | `TestInvariantFlippedBitNeverVerifies`, `TestInvariantWrongKeyNeverVerifies` |
| S3 check order (domain→nb→expiry→nonce→sig) | Ensures cheap checks gate expensive cryptography | `TestSolanaAdapterObserverEventOrder` |
| Constant-time nonce comparison | Timing side-channel on nonce check | `verify.go:checkNonce` (crypto/subtle) |

## 5. Logging and observability rules

### S4 — Error text safe to log verbatim

Error messages name the offending *field*, never the *value*. For example:

- `"siws: domain mismatch"` — not `"domain 'evil.com' ≠ 'dapp.academy'"`
- `"siws: nonce mismatch"` — not `"nonce 'abc' ≠ 'xyz'"`
- `"siws: malformed message"` — not the raw malformed bytes

This ensures log output cannot be used to exfiltrate partial secrets and is safe to forward to error aggregation pipelines without redaction.

### S5 — Observer carries identifiers and verdicts only

The `Observer` interface events (`VerifyAttempt`, `ParseResult`, `CheckResult`, `VerifyResult`) are designed to carry:

- **Identifiers**: `AttemptID`, `Namespace`, `Account` (CAIP-10 string — a public identifier)
- **Verdicts**: `OK bool`, `ErrorIs error` (sentinel reference, not message text), `Check CheckName`
- **Metrics**: `Duration time.Duration`, `MsgBytes int` (byte count, not content)

They must **never** carry: raw message bytes, signature bytes, private key material, nonce values, or raw error strings from external libraries.

Invariant asserted by: `TestInvariantObserverNoSensitiveData`, `TestInvariantObserverEventOrdering`, `TestInvariantAttemptIDConsistent`

## 6. Non-goals / residual risks

| Risk | Reason not mitigated here |
|---|---|
| Look-alike domain approved by user | Wallet UI responsibility; library sees only the domain in the signed message |
| Compromised wallet / private key | Key material is out of scope; library cannot validate key provenance |
| XSS on relying party site stealing bearer token | Hub/spoke transport security; JWT TTL and HttpOnly cookies mitigate this at the infrastructure layer |
| Mock issuer in `examples/` | Examples are explicitly demo-grade; the hub in `examples/hub` uses a hardcoded key and is not production-ready |
| Nonce store race conditions | Nonce persistence and single-use enforcement is the caller's responsibility; siwx-go does not manage the nonce store |
