package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/anitconsultant/siwx-go/siwx"
	evmadapter "github.com/anitconsultant/siwx-go/siwx/evm"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	siwelib "github.com/spruceid/siwe-go"
)

// signContractWalletSIWE builds a SIWE message naming the contract WALLET
// address but signs it with the OWNER key — exactly what the browser demo does.
func signContractWalletSIWE(t *testing.T, ownerKey, walletAddr, domain, nonce string) ([]byte, []byte) {
	t.Helper()
	uri := fmt.Sprintf("https://%s/login", domain)
	exp := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	msg, err := siwelib.InitMessage(domain, walletAddr, uri, nonce, map[string]interface{}{
		"chainId":        1,
		"expirationTime": exp,
	})
	if err != nil {
		t.Fatalf("InitMessage: %v", err)
	}
	msgStr := msg.String()

	key, err := ethcrypto.HexToECDSA(ownerKey)
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	hash := ethcrypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msgStr), msgStr)))
	sig, err := ethcrypto.Sign(hash, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig[64] += 27 // EIP-191 v is 27/28
	return []byte(msgStr), sig
}

// TestContractWalletERC1271RoundTrip proves the simulated chain validates a
// signature produced by the wallet's owner via the ERC-1271 path, and rejects
// one produced by anyone else.
func TestContractWalletERC1271RoundTrip(t *testing.T) {
	dw := newDemoContractWallets()
	reg := siwx.NewRegistry()
	reg.Register(evmadapter.New(evmadapter.WithChainClient(dw)))

	ownerKey, _ := ethcrypto.GenerateKey()
	owner := ethcrypto.PubkeyToAddress(ownerKey.PublicKey)
	ownerHex := fmt.Sprintf("%x", ethcrypto.FromECDSA(ownerKey))
	wallet := dw.Register(owner)

	nonce := siwelib.GenerateNonce()
	chainID, _ := siwx.ParseCAIP2("eip155:1")
	opts := siwx.VerifyOpts{
		ExpectedDomain: testDomain,
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          siwx.RealClock{},
	}

	// Owner signs for the contract wallet -> ERC-1271 accepts.
	msg, sig := signContractWalletSIWE(t, ownerHex, wallet.Hex(), testDomain, nonce)
	id, err := reg.Verify(context.Background(), chainID, msg, sig, opts)
	if err != nil {
		t.Fatalf("owner-signed contract wallet should verify, got %v", err)
	}
	if id.Account.Address != wallet.Hex() {
		t.Errorf("identity address: got %q want contract wallet %q", id.Account.Address, wallet.Hex())
	}

	// A different EOA signs for the same wallet -> ERC-1271 rejects.
	strangerKey, _ := ethcrypto.GenerateKey()
	strangerHex := fmt.Sprintf("%x", ethcrypto.FromECDSA(strangerKey))
	msg2, sig2 := signContractWalletSIWE(t, strangerHex, wallet.Hex(), testDomain, siwelib.GenerateNonce())
	opts.ExpectedNonce = mustNonce(msg2)
	_, err = reg.Verify(context.Background(), chainID, msg2, sig2, opts)
	if !errors.Is(err, siwx.ErrContractValidationFailed) {
		t.Errorf("stranger-signed contract wallet: want ErrContractValidationFailed, got %v", err)
	}
}

// mustNonce extracts the Nonce line from a SIWE message so the expected nonce
// matches what was embedded.
func mustNonce(msg []byte) string {
	parsed, err := siwelib.ParseMessage(string(msg))
	if err != nil {
		return ""
	}
	return parsed.GetNonce()
}
