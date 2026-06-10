# siwx-go

[![CI](https://github.com/anitconsultant/siwx-go/actions/workflows/ci.yml/badge.svg)](https://github.com/anitconsultant/siwx-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/anitconsultant/siwx-go)](https://goreportcard.com/report/github.com/anitconsultant/siwx-go)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/anitconsultant/siwx-go.svg)](https://pkg.go.dev/github.com/anitconsultant/siwx-go)
[![License: Apache-2.0 / MIT](https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-blue.svg)](LICENSE-APACHE)

Go library for **Sign-In With X** — chain-agnostic wallet authentication following [CAIP-122](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md).

- **`siws`** — zero-dependency, stdlib-only SIWS parser and Ed25519 verifier for Solana ([Phantom SIWS spec](https://github.com/phantom/sign-in-with-solana)).
- **`siwx`** — CAIP-122 dispatch layer with pluggable per-chain adapters (`siwx/solana`, `siwx/evm`).
- **`examples/hub`** — runnable mock SSO hub (Gin + JWT) with Phantom and MetaMask demo.

Zero external dependencies in `siws/`. Fuzz-tested, invariant-tested, threat-modeled.

---

## Install

```bash
go get github.com/anitconsultant/siwx-go
```

Requires Go 1.24+.

---

## Quickstart — `siws` only (Solana, zero deps)

```go
import "github.com/anitconsultant/siwx-go/siws"

// Parse the SIWS message text.
msg, err := siws.ParseMessage(rawMessageString)
if err != nil {
    // errors.Is(err, siws.ErrMalformed) for parse failures
    return err
}

// Verify the Ed25519 signature.
// pubKey is the base58-encoded wallet address from the message.
err = siws.Verify(msg, signatureBytes, siws.VerifyOpts{
    Domain:    "dapp.example.com",
    Nonce:     expectedNonce,
    Timestamp: time.Now(),
})
// errors.Is(err, siws.ErrBadSignature) — wrong key or tampered message
// errors.Is(err, siws.ErrExpired)      — message past ExpirationTime
// errors.Is(err, siws.ErrNonceMismatch)— replay attempt
```

---

## Quickstart — `siwx` (chain-agnostic, Solana + EVM)

```go
import (
    "github.com/anitconsultant/siwx-go/siwx"
    "github.com/anitconsultant/siwx-go/siwx/solana"
    "github.com/anitconsultant/siwx-go/siwx/evm"
)

// Build the registry once at startup.
reg := siwx.NewRegistry()
reg.Register(solana.New())
reg.Register(evm.New())

// At request time:
identity, err := reg.Verify(ctx, siwx.VerifyRequest{
    ChainID:   "solana:mainnet",           // or "eip155:1"
    Message:   rawMessageBytes,
    Signature: signatureBytes,
    Opts: siwx.VerifyOpts{
        Domain:    r.Host,
        Nonce:     consumedNonce,
        Timestamp: time.Now(),
        Observer:  obs,                    // optional; siwx.NopObserver{} by default
    },
})
// identity.Account is the verified CAIP-10 address, e.g.
// "solana:mainnet:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
// "eip155:1:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"
```

---

## Run the demo hub

```bash
go run ./examples/hub
# Open http://localhost:8081 in a browser with Phantom or MetaMask installed.
```

Configuration is environment-driven: copy [`.env.example`](.env.example) to
`.env` and edit it (the hub loads `.env` at startup), or set the `SIWX_*`
variables directly. See [`examples/web/README.md`](examples/web/README.md) for
the full config table and the manual wallet test walkthrough.

---

## Security

`siws/` enforces:
- Check order: parse → domain → not-before → expiry → nonce → signature (cheapest first).
- Constant-time nonce comparison (`crypto/subtle`).
- Signature verification runs last; rejected messages never reach `ed25519.Verify`.
- No logging of attacker-controlled data; error messages name fields, never values.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full threat model and [`docs/SECURITY.md`](docs/SECURITY.md) for the vulnerability disclosure policy.

---

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT). You may choose either license.
