# ERC-6492 validator bytecode — provenance & regeneration

`../erc6492_validator_bytecode.hex` is the **creation bytecode** of the ERC-6492
reference `ValidateSigOffchain` helper, embedded (via `//go:embed`) and used by
the adapter to validate counterfactual signatures deployless in a single
`eth_call`.

## Source

`UniversalSigValidator.sol` here is the **verbatim** "Reference Implementation"
from ERC-6492, copied from
<https://github.com/ethereum/ERCs/blob/master/ERCS/erc-6492.md>, with only an
`SPDX-License-Identifier` and a `pragma` prepended. It defines both
`UniversalSigValidator` and the `ValidateSigOffchain` deployless helper.

`TestWallet.sol` is **test-only** scaffolding (a minimal 1-of-1 ERC-1271 wallet
and a CREATE2 factory) used by the `anvil`-gated integration test to mint a
genuine counterfactual signature. Its compiled factory bytecode is
`test_factory_bytecode.hex`.

## Compiler settings (must match to reproduce the bytes)

- solc **0.8.24**
- optimizer **enabled**, **200** runs
- `evm_version = paris`

## Regenerate

```sh
cd siwx/evm/testdata
forge build \
  --use 0.8.24 --optimize --optimizer-runs 200 --evm-version paris \
  --contracts . --out /tmp/erc6492-out

jq -r '.bytecode.object' /tmp/erc6492-out/UniversalSigValidator.sol/ValidateSigOffchain.json \
  > ../erc6492_validator_bytecode.hex
jq -r '.bytecode.object' /tmp/erc6492-out/TestWallet.sol/TestFactory.json \
  > test_factory_bytecode.hex
```

## Verification

The embedded bytecode is **not trusted blindly**: `erc6492_anvil_test.go`
(build tag `anvil`) runs the full library path against a real EVM and asserts
that an owner-signed counterfactual signature verifies while a stranger's is
rejected — and that the wallet is never actually deployed.

```sh
anvil --silent &
SIWX_ANVIL_RPC=http://localhost:8545 go test -tags anvil ./siwx/evm/ -run Anvil -v
```
