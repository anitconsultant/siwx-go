# Threat Model — siwx-go (SKELETON: WT-D completes every section)

## 1. Assets
<!-- user identity binding, session issuance authority, nonce store integrity -->

## 2. Trust boundaries
<!-- wallet <-> browser <-> hub <-> spoke apps; what crosses each boundary -->

## 3. Attacker capabilities assumed
<!-- network observer, message replayer, phishing-site operator, malformed-input fuzzer -->

## 4. Controls and what each defeats
| Control | Defeats | Proven by (test) |
|---|---|---|
| Server-issued single-use nonce | replay | |
| Domain binding check | phishing relay | |
| Expiry / Not Before windows | stale capture | |
| Ed25519 / EIP-191 signature | forgery, tamper | |
| JWT aud + iss validation (hub/spokes) | confused deputy | |

## 5. Logging and observability rules
<!-- S4: error text safe to log verbatim; S5: Observer carries identifiers and
verdicts only — never message text, signature bytes, or key material. State both
as invariants and link the asserting tests. -->

## 6. Non-goals / residual risks
<!-- lookalike domains a wallet user approves; compromised wallet/private key;
XSS on the relying site stealing the bearer token; mock issuer in examples/ -->
