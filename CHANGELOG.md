# Changelog

All notable changes to **siwx-go** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pull a specific version into your project with a version-pinned `go get`:

```bash
go get github.com/anitconsultant/siwx-go@v0.5.0
```

## [0.5.0] - 2026-06-29

### Added

- **ERC-6492 — counterfactual (not-yet-deployed) smart-contract wallet
  signatures.** With a deployless-capable chain client, the EVM adapter now
  validates `0x6492…`-wrapped signatures in a single `eth_call`, using the
  reference `ValidateSigOffchain` universal validator (works whether or not the
  wallet is deployed, and never deploys it).
- New **optional** interface `evm.DeploylessCaller` (`CallContractCreation`).
  A `ChainClient` opts into ERC-6492 by also implementing it; `evmrpc` does so
  out of the box.

### Notes

- **Backward compatible.** `ChainClient` is unchanged, so existing
  implementations keep working. Without a deployless-capable client, an
  ERC-6492 signature returns `ErrContractWalletUnsupported` (never a silent
  false negative).
- The embedded validator bytecode is compiled verbatim from the ERC-6492
  reference (solc 0.8.24; provenance in `siwx/evm/testdata/README.md`) and is
  verified end-to-end against a real EVM (anvil) in CI.
- Verifier order with a client configured: **ERC-6492 → ERC-1271 → EOA**.

## [0.4.0] - 2026-06-29

### Added

- **ERC-1271 — deployed smart-contract wallet signatures** (Safe, Argent,
  ERC-4337 accounts). Opt in with `evm.New(evm.WithChainClient(resolver))`.
- New sub-package `siwx/evm/evmrpc` with `NewResolver(map[string]string)` — a
  caller-supplied, RPC-backed `Resolver` (no RPC URLs are shipped in the
  library).
- New sentinel errors: `ErrContractValidationFailed`,
  `ErrContractWalletUnsupported`, `ErrRPC`.
- Runnable browser demo of ERC-1271 sign-in in the example hub
  (`SIWX_EVM_CONTRACT_DEMO`, on by default).

### Notes

- **Backward compatible.** No-arg `evm.New()` is unchanged — EOA-only and
  network-free. No new mandatory dependency for EOA-only users (the core `evm`
  package never imports an RPC client).

## [0.3.0] - 2026-06-22

### Added

- Documentation of the identity model — what identifies the signed-in user
  (`siwx.Identity`, JWT claims, the verify response).

## [0.2.0] - 2026-06-10

### Added

- `GET /config` endpoint and `SIWX_*` environment configuration for the demo
  hub (single source of truth, no hard-coded demo values).

### Security

- **M1** — bind the nonce to the client via an HttpOnly cookie so the
  in-library `ExpectedNonce` check is load-bearing (was tautological).
- **M2** — bound request input to stop an O(n²) base58 CPU-DoS.

## [0.1.0] - 2026-06-10

### Added

- Initial release: CAIP-122 "Sign-In With X" verification.
  - `siws` — zero-dependency Solana (SIWS) parser + Ed25519 verifier.
  - `siwx` — chain-agnostic registry with Solana and EVM (EOA) adapters.
  - Example SSO hub, JWT middleware, and browser demo.

[0.5.0]: https://github.com/anitconsultant/siwx-go/releases/tag/v0.5.0
[0.4.0]: https://github.com/anitconsultant/siwx-go/releases/tag/v0.4.0
[0.3.0]: https://github.com/anitconsultant/siwx-go/releases/tag/v0.3.0
[0.2.0]: https://github.com/anitconsultant/siwx-go/releases/tag/v0.2.0
[0.1.0]: https://github.com/anitconsultant/siwx-go/releases/tag/v0.1.0
