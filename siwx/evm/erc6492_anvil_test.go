//go:build anvil

// Package evm anvil integration test for ERC-6492 counterfactual validation.
//
// Excluded from the normal build (and the CI coverage/race matrix) by the
// `anvil` build tag. It runs the FULL library path — evmrpc resolver ->
// adapter.Verify -> embedded ValidateSigOffchain bytecode -> deployless eth_call
// — against a real EVM, proving the embedded bytecode actually validates a
// genuine counterfactual (not-yet-deployed) ERC-6492 signature.
//
// Run:
//
//	anvil --silent &                  # or any dev node
//	SIWX_ANVIL_RPC=http://localhost:8545 go test -tags anvil ./siwx/evm/ -run Anvil -v
//
// Skips (not fails) when SIWX_ANVIL_RPC is unset.
package evm_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	siwelib "github.com/spruceid/siwe-go"

	"github.com/anitconsultant/siwx-go/siwx"
	evmadapter "github.com/anitconsultant/siwx-go/siwx/evm"
	"github.com/anitconsultant/siwx-go/siwx/evm/evmrpc"
)

// anvil dev account 0 (well-known, funded; safe to hardcode for a local test).
const anvilDevKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

const erc6492Magic = "6492649264926492649264926492649264926492649264926492649264926492"

func abiType(t *testing.T, s string) abi.Type {
	t.Helper()
	ty, err := abi.NewType(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return ty
}

func TestAnvilERC6492Counterfactual(t *testing.T) {
	rpc := os.Getenv("SIWX_ANVIL_RPC")
	if rpc == "" {
		t.Skip("set SIWX_ANVIL_RPC to a running dev node (e.g. anvil) to run this test")
	}
	ctx := context.Background()
	cl, err := ethclient.Dial(rpc)
	if err != nil {
		t.Fatalf("dial %s: %v", rpc, err)
	}
	chainID, err := cl.ChainID(ctx)
	if err != nil {
		t.Fatalf("chainid: %v", err)
	}

	// Deploy the CREATE2 factory (compiled bytecode under testdata/).
	factoryCode := mustReadHexFile(t, "testdata/test_factory_bytecode.hex")
	factory := deployContract(t, ctx, cl, chainID, factoryCode)

	factoryABI, err := abi.JSON(strings.NewReader(`[
		{"type":"function","name":"deploy","inputs":[{"type":"address"},{"type":"bytes32"}],"outputs":[{"type":"address"}],"stateMutability":"nonpayable"},
		{"type":"function","name":"initCodeHash","inputs":[{"type":"address"}],"outputs":[{"type":"bytes32"}],"stateMutability":"pure"}
	]`))
	if err != nil {
		t.Fatal(err)
	}

	ownerKey, _ := ethcrypto.GenerateKey()
	owner := ethcrypto.PubkeyToAddress(ownerKey.PublicKey)
	var salt [32]byte

	// Counterfactual wallet address (NOT deployed).
	ichCall, _ := factoryABI.Pack("initCodeHash", owner)
	ret, err := cl.CallContract(ctx, ethereum.CallMsg{To: &factory, Data: ichCall}, nil)
	if err != nil {
		t.Fatalf("initCodeHash: %v", err)
	}
	var initCodeHash [32]byte
	copy(initCodeHash[:], ret)
	wallet := create2(factory, salt, initCodeHash)

	if code, _ := cl.CodeAt(ctx, wallet, nil); len(code) != 0 {
		t.Fatalf("wallet should be counterfactual (no code), got %d bytes", len(code))
	}

	// Build a SIWE message naming the counterfactual wallet, on anvil's chain.
	nonce := siwelib.GenerateNonce()
	exp := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	siweMsg, err := siwelib.InitMessage("dapp.academy", wallet.Hex(), "https://dapp.academy/login", nonce, map[string]interface{}{
		"chainId":        int(chainID.Int64()),
		"expirationTime": exp,
	})
	if err != nil {
		t.Fatalf("InitMessage: %v", err)
	}
	msg := []byte(siweMsg.String())
	hash := accounts.TextHash(msg)

	factoryCalldata, _ := factoryABI.Pack("deploy", owner, salt)
	resolver := evmrpc.NewResolver(map[string]string{fmt.Sprintf("eip155:%d", chainID): rpc})
	v := evmadapter.New(evmadapter.WithChainClient(resolver))
	caip2, _ := siwx.ParseCAIP2(fmt.Sprintf("eip155:%d", chainID))
	opts := siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          siwx.RealClock{},
	}
	reg := siwx.NewRegistry()
	reg.Register(v)

	t.Run("owner-signed counterfactual verifies", func(t *testing.T) {
		wrapped := wrap6492(t, factory, factoryCalldata, signDigest(t, ownerKey, hash))
		id, err := reg.Verify(ctx, caip2, msg, wrapped, opts)
		if err != nil {
			t.Fatalf("want verified, got %v", err)
		}
		if id.Account.Address != wallet.Hex() {
			t.Errorf("identity: got %q want counterfactual wallet %q", id.Account.Address, wallet.Hex())
		}
	})

	t.Run("stranger-signed counterfactual rejected", func(t *testing.T) {
		strangerKey, _ := ethcrypto.GenerateKey()
		wrapped := wrap6492(t, factory, factoryCalldata, signDigest(t, strangerKey, hash))
		if _, err := reg.Verify(ctx, caip2, msg, wrapped, opts); err == nil {
			t.Fatal("stranger-signed counterfactual must not verify")
		}
	})

	// The deployless validation must not have actually deployed the wallet.
	if code, _ := cl.CodeAt(ctx, wallet, nil); len(code) != 0 {
		t.Fatalf("wallet must remain counterfactual after verify, got %d bytes", len(code))
	}
}

func wrap6492(t *testing.T, factory common.Address, factoryCalldata, sig []byte) []byte {
	t.Helper()
	args := abi.Arguments{{Type: abiType(t, "address")}, {Type: abiType(t, "bytes")}, {Type: abiType(t, "bytes")}}
	enc, err := args.Pack(factory, factoryCalldata, sig)
	if err != nil {
		t.Fatal(err)
	}
	return append(enc, common.FromHex("0x"+erc6492Magic)...)
}

func signDigest(t *testing.T, key *ecdsa.PrivateKey, hash []byte) []byte {
	t.Helper()
	sig, err := ethcrypto.Sign(hash, key)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27 // the test wallet's ecrecover expects v in {27,28}
	return sig
}

func create2(deployer common.Address, salt, initCodeHash [32]byte) common.Address {
	data := append([]byte{0xff}, deployer.Bytes()...)
	data = append(data, salt[:]...)
	data = append(data, initCodeHash[:]...)
	return common.BytesToAddress(ethcrypto.Keccak256(data)[12:])
}

func deployContract(t *testing.T, ctx context.Context, cl *ethclient.Client, chainID *big.Int, code []byte) common.Address {
	t.Helper()
	key, _ := ethcrypto.HexToECDSA(anvilDevKey)
	from := ethcrypto.PubkeyToAddress(key.PublicKey)
	nonce, err := cl.PendingNonceAt(ctx, from)
	if err != nil {
		t.Fatal(err)
	}
	gasPrice, err := cl.SuggestGasPrice(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx := types.NewContractCreation(nonce, big.NewInt(0), 3_000_000, gasPrice, code)
	signed, err := types.SignTx(tx, types.NewEIP155Signer(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.SendTransaction(ctx, signed); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if r, err := cl.TransactionReceipt(ctx, signed.Hash()); err == nil {
			return r.ContractAddress
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("deploy not mined")
	return common.Address{}
}

func mustReadHexFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return common.FromHex(strings.TrimSpace(string(b)))
}
