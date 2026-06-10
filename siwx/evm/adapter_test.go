package evm_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	siwelib "github.com/spruceid/siwe-go"

	"github.com/anitconsultant/siwx-go/siwx"
	evmadapter "github.com/anitconsultant/siwx-go/siwx/evm"
)

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

var refClock = fixedClock{time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)}

// signSIWE creates a SIWE message and signs it with key, returning (rawMsg, rawSig).
func signSIWE(t *testing.T, key *ecdsa.PrivateKey, domain, nonce string, opts map[string]interface{}) ([]byte, []byte) {
	t.Helper()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()
	uri := fmt.Sprintf("https://%s/login", domain)
	msg, err := siwelib.InitMessage(domain, addr, uri, nonce, opts)
	if err != nil {
		t.Fatalf("InitMessage: %v", err)
	}
	msgStr := msg.String()

	// EIP-191 personal_sign hash.
	hash := ethcrypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msgStr), msgStr)))
	sig, err := ethcrypto.Sign(hash, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// go-ethereum Sign returns r+s+v where v is 0 or 1; EIP-191 expects 27 or 28.
	sig[64] += 27
	return []byte(msgStr), sig
}

func TestEVMAdapterNamespace(t *testing.T) {
	if evmadapter.New().Namespace() != "eip155" {
		t.Error("want namespace 'eip155'")
	}
}

func TestEVMAdapterHappyPath(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	nonce := siwelib.GenerateNonce()
	exp := refClock.t.Add(10 * time.Minute).UTC().Format(time.RFC3339)
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{
		"chainId":        1,
		"expirationTime": exp,
	})

	v := evmadapter.New()
	id, err := v.Verify(context.Background(), msg, sig, siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Account.ChainID.Namespace != "eip155" {
		t.Errorf("namespace: got %q", id.Account.ChainID.Namespace)
	}
	if id.Domain != "dapp.academy" {
		t.Errorf("domain: got %q", id.Domain)
	}
}

func TestEVMAdapterDomainMismatch(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{"chainId": 1})

	_, err := evmadapter.New().Verify(context.Background(), msg, sig, siwx.VerifyOpts{
		ExpectedDomain: "evil.example",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if !errors.Is(err, siwx.ErrDomainMismatch) {
		t.Errorf("want ErrDomainMismatch, got %v", err)
	}
}

func TestEVMAdapterNonceMismatch(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{"chainId": 1})

	_, err := evmadapter.New().Verify(context.Background(), msg, sig, siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  "wrongnonce00",
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if !errors.Is(err, siwx.ErrNonceMismatch) {
		t.Errorf("want ErrNonceMismatch, got %v", err)
	}
}

func TestEVMAdapterExpired(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	// Expiry in the past relative to refClock.
	exp := refClock.t.Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{
		"chainId":        1,
		"expirationTime": exp,
	})

	_, err := evmadapter.New().Verify(context.Background(), msg, sig, siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if !errors.Is(err, siwx.ErrExpired) {
		t.Errorf("want ErrExpired, got %v", err)
	}
}

func TestEVMAdapterNotYetValid(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	nb := refClock.t.Add(5 * time.Minute).UTC().Format(time.RFC3339)
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{
		"chainId":   1,
		"notBefore": nb,
	})

	_, err := evmadapter.New().Verify(context.Background(), msg, sig, siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if !errors.Is(err, siwx.ErrNotYetValid) {
		t.Errorf("want ErrNotYetValid, got %v", err)
	}
}

func TestEVMAdapterBadSignature(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{"chainId": 1})

	// Flip one byte in the signature.
	sig[0] ^= 0xFF

	_, err := evmadapter.New().Verify(context.Background(), msg, sig, siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if !errors.Is(err, siwx.ErrBadSignature) {
		t.Errorf("want ErrBadSignature, got %v", err)
	}
}

func TestEVMAdapterMalformedMessage(t *testing.T) {
	_, err := evmadapter.New().Verify(context.Background(), []byte("not a siwe message"), make([]byte, 65), siwx.VerifyOpts{
		ExpectedDomain: "x",
		ExpectedNonce:  "y",
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if !errors.Is(err, siwx.ErrMalformed) {
		t.Errorf("want ErrMalformed, got %v", err)
	}
}
