package main

import (
	"context"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	evmadapter "github.com/anitconsultant/siwx-go/siwx/evm"
)

// demoContractWallets is an in-process, simulated chain that demonstrates the
// library's ERC-1271 verification path WITHOUT a real RPC or deployed contract.
//
// It models a 1-of-1 smart-contract wallet (like a minimal Safe) whose sole
// owner is an EOA. Each owner gets a deterministic demo wallet address. The
// wallet's isValidSignature(hash, sig) returns the ERC-1271 magic value
// 0x1626ba7e iff the signature recovers to the registered owner — exactly the
// ownership check a real contract wallet performs on-chain.
//
// It satisfies evm.Resolver and evm.ChainClient, so it can be injected via
// evm.WithChainClient just like the production evmrpc resolver would be.
type demoContractWallets struct {
	mu     sync.RWMutex
	owners map[common.Address]common.Address // contract wallet -> owner EOA
}

func newDemoContractWallets() *demoContractWallets {
	return &demoContractWallets{owners: make(map[common.Address]common.Address)}
}

// Register derives the demo contract-wallet address for owner, records the
// ownership, and returns the wallet address (EIP-55 checksummed via .Hex()).
func (d *demoContractWallets) Register(owner common.Address) common.Address {
	wallet := deriveWallet(owner)
	d.mu.Lock()
	d.owners[wallet] = owner
	d.mu.Unlock()
	return wallet
}

// deriveWallet maps an owner EOA to a stable, unique demo wallet address. This
// stands in for the deterministic deploy address (e.g. CREATE2) a real account
// factory would produce.
func deriveWallet(owner common.Address) common.Address {
	h := ethcrypto.Keccak256([]byte("siwx-go-demo-1271:"), owner.Bytes())
	return common.BytesToAddress(h[12:])
}

// ClientFor satisfies evm.Resolver: the demo chain answers for every eip155
// chain id, so the demo works regardless of the wallet's reported network.
func (d *demoContractWallets) ClientFor(chainID string) (evmadapter.ChainClient, bool) {
	if !strings.HasPrefix(chainID, "eip155:") {
		return nil, false
	}
	return d, true
}

// demoContractCode is any non-empty bytecode; the adapter only checks len > 0
// to decide an address is a contract (and take the ERC-1271 path).
var demoContractCode = []byte{0x60, 0x80, 0x60, 0x40, 0x52}

// erc1271MagicValue is bytes4(keccak256("isValidSignature(bytes32,bytes)")).
var erc1271MagicValue = []byte{0x16, 0x26, 0xba, 0x7e}

// CodeAt reports a registered demo wallet as having code (-> ERC-1271 path) and
// every other address as codeless (-> the adapter's normal EOA ecrecover path,
// so ordinary MetaMask sign-in is unaffected).
func (d *demoContractWallets) CodeAt(_ context.Context, addr common.Address) ([]byte, error) {
	d.mu.RLock()
	_, ok := d.owners[addr]
	d.mu.RUnlock()
	if ok {
		return demoContractCode, nil
	}
	return nil, nil
}

// CallContract simulates the wallet's isValidSignature(bytes32 hash, bytes sig).
// Calldata layout: selector(4) | hash(32) | offset(32) | sigLen(32) | sig(...).
// It returns the magic value left-aligned in a 32-byte word iff the signature
// recovers to this wallet's owner; otherwise a zero word (rejection).
func (d *demoContractWallets) CallContract(_ context.Context, to common.Address, data []byte) ([]byte, error) {
	const headLen = 4 + 32 + 32 + 32 // selector + hash + offset + length
	zero := make([]byte, 32)
	if len(data) < headLen {
		return zero, nil
	}
	hash := data[4:36]
	sigLen := int(new(big.Int).SetBytes(data[68:100]).Int64())
	if sigLen <= 0 || headLen+sigLen > len(data) {
		return zero, nil
	}
	sig := make([]byte, sigLen)
	copy(sig, data[headLen:headLen+sigLen])

	// go-ethereum's recovery wants v in {0,1}; personal_sign emits {27,28}.
	if len(sig) == 65 && sig[64] >= 27 {
		sig[64] -= 27
	}
	pub, err := ethcrypto.SigToPub(hash, sig)
	if err != nil {
		return zero, nil
	}
	signer := ethcrypto.PubkeyToAddress(*pub)

	d.mu.RLock()
	owner, ok := d.owners[to]
	d.mu.RUnlock()
	if ok && signer == owner {
		out := make([]byte, 32)
		copy(out, erc1271MagicValue)
		return out, nil
	}
	return zero, nil
}
