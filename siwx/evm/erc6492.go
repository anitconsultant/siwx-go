package evm

import (
	"context"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"github.com/anitconsultant/siwx-go/siwx"
)

// DeploylessCaller is an optional capability a ChainClient may implement to
// support ERC-6492 (counterfactual / not-yet-deployed contract wallet)
// signatures. It performs an eth_call against a contract *creation* (the call's
// "to" is nil), which is how ERC-6492 off-chain validation deploys the
// universal validator and runs it in a single call without persisting state.
//
// A ChainClient that does not implement this returns ErrContractWalletUnsupported
// for ERC-6492-wrapped signatures, so they never silently false-negative.
type DeploylessCaller interface {
	CallContractCreation(ctx context.Context, data []byte) ([]byte, error)
}

// validateSigOffchainHex is the creation bytecode of the ERC-6492 reference
// `ValidateSigOffchain` helper contract (which itself deploys and invokes the
// reference `UniversalSigValidator`).
//
// Provenance: compiled verbatim from the ERC-6492 "Reference Implementation"
// (https://github.com/ethereum/ERCs/blob/master/ERCS/erc-6492.md), kept under
// testdata/UniversalSigValidator.sol, with solc 0.8.24, optimizer enabled
// (200 runs), evm_version=paris. To regenerate, see testdata/README.md. The
// bytecode is verified end-to-end against a real EVM by the anvil-gated
// integration test (erc6492_anvil_test.go).
//
//go:embed erc6492_validator_bytecode.hex
var validateSigOffchainHex string

var validateSigOffchainCode = mustDecodeHex(validateSigOffchainHex)

func mustDecodeHex(s string) []byte {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("evm: invalid embedded ERC-6492 validator bytecode: " + err.Error())
	}
	return b
}

// deploylessArgs is the constructor signature of ValidateSigOffchain:
// (address signer, bytes32 hash, bytes signature).
var deploylessArgs = abi.Arguments{
	{Type: mustABIType("address")},
	{Type: mustABIType("bytes32")},
	{Type: mustABIType("bytes")},
}

func mustABIType(s string) abi.Type {
	t, err := abi.NewType(s, "", nil)
	if err != nil {
		panic("evm: " + err.Error())
	}
	return t
}

// validateERC6492 validates a (possibly 6492-wrapped) signature deployless, per
// ERC-6492 off-chain validation: eth_call a creation of ValidateSigOffchain with
// the constructor args, and treat a single returned byte 0x01 as valid. The
// universal validator handles all cases — counterfactual, deployed-wrapped,
// plain ERC-1271, and ecrecover — so 6492-suffixed signatures route here whole.
func validateERC6492(ctx context.Context, dc DeploylessCaller, signer common.Address, hash, wrappedSig []byte) error {
	var h [32]byte
	copy(h[:], hash)
	encoded, err := deploylessArgs.Pack(signer, h, wrappedSig)
	if err != nil {
		return fmt.Errorf("evm: encode ERC-6492 validation call: %w", siwx.ErrContractValidationFailed)
	}
	data := make([]byte, 0, len(validateSigOffchainCode)+len(encoded))
	data = append(data, validateSigOffchainCode...)
	data = append(data, encoded...)

	ret, err := dc.CallContractCreation(ctx, data)
	if err != nil {
		return fmt.Errorf("evm: ERC-6492 deployless validation rpc failed: %w: %w", siwx.ErrRPC, err)
	}
	if len(ret) == 1 && ret[0] == 0x01 {
		return nil
	}
	return fmt.Errorf("evm: ERC-6492 signature invalid: %w", siwx.ErrContractValidationFailed)
}
