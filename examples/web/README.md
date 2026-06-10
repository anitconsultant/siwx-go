# siwx-go Demo Hub

A minimal Sign-In With X demo server. Supports Phantom (Solana) and MetaMask (Ethereum).

## Run

```bash
# From the repo root:
go run ./examples/hub
```

Defaults: domain `localhost:8081` (from `SIWX_DOMAIN=localhost` + `SIWX_PORT=8081`).

Open http://localhost:8081 in a browser.

To change any setting, copy [`.env.example`](../../.env.example) to `.env` in the
repo root and edit it — the hub loads `.env` at startup. Real environment
variables always override `.env` values.

## Manual wallet test

### Phantom (Solana)

1. Install the [Phantom browser extension](https://phantom.app).
2. Create or import a wallet (devnet is fine for testing).
3. Open http://localhost:8081, click **Sign in with Phantom (Solana)**.
4. Phantom prompts with the SIWS message — click **Sign**.
5. The stepper animates through: nonce → wallet sign → verify → token → linked.
6. The token prefix is shown at the bottom of the card.

### MetaMask (Ethereum)

1. Install [MetaMask](https://metamask.io).
2. Open http://localhost:8081, click **Sign in with MetaMask (Ethereum)**.
3. MetaMask prompts for account access — approve.
4. MetaMask prompts to sign the EIP-4361 message — click **Sign**.
5. Same stepper flow as above.

### Replay test

After a successful sign-in, click the same button again without fetching a new
nonce. The request is rejected with a 401 nonce-check-failed problem-detail
(the nonce was burned on first use).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /auth/nonce | Issue a single-use nonce (10 min TTL) |
| GET | /config | Demo display config the frontend uses to build the sign-in message |
| POST | /auth/verify | Verify wallet signature → JWT |
| POST | /auth/link | Link additional wallet to existing session |
| GET | /.well-known/jwks.json | RS256 public key for spoke validation |
| GET | /metrics | Prometheus-style plain-text counters |
| GET | /healthz | Liveness probe |
| GET | /me | Protected demo endpoint (requires Bearer token) |

## Configuration

All settings are environment-driven (single source of truth). Set them as real
environment variables or via a `.env` file in the repo root — see
[`.env.example`](../../.env.example) for the full annotated list. Real
environment variables override `.env`.

| Env var | Default | Description |
|---------|---------|-------------|
| `SIWX_DOMAIN` | `localhost` | Hostname (no port) used in the sign-in domain |
| `SIWX_PORT` | `8081` | Port; combined with `SIWX_DOMAIN` into the authority |
| `SIWX_ADDR` | `:<SIWX_PORT>` | Listen address |
| `SIWX_JWKS_URL` | `http://localhost:<port>/.well-known/jwks.json` | JWKS URL for JWT middleware |
| `SIWX_ISSUER_URL` | `https://accounts.example.local` | JWT `iss` claim |
| `SIWX_AUDIENCE` | `siwx-go-demo` | JWT `aud` claim |
| `SIWX_STATEMENT` | `Sign in to siwx-go demo` | Statement shown in the wallet prompt |
| `SIWX_SOLANA_CHAIN` | `mainnet` | Solana cluster in the SIWS `Chain ID` field |
| `SIWX_SESSION_TTL_MIN` | `10` | Sign-in message validity window, in minutes |

The frontend reads `SIWX_STATEMENT`, `SIWX_SOLANA_CHAIN`, and
`SIWX_SESSION_TTL_MIN` from `GET /config` rather than hard-coding them, so a
change to `.env` takes effect on the next page load with no code edits.

## Production note

This hub uses an RSA key generated at startup — it is **not** suitable for
production. For production: use a KMS-backed key, replace the in-memory stores
with Redis (NonceStore) and PostgreSQL (IdentityStore), and set `SIWX_DOMAIN`
to your actual domain.
