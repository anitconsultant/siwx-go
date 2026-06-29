package evm_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
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

type mockResolver map[string]*mockChainClient

func (r mockResolver) ClientFor(chainID string) (evmadapter.ChainClient, bool) {
	c, ok := r[chainID]
	return c, ok
}

type mockChainClient struct {
	code    []byte
	codeErr error
	ret     []byte
	callErr error

	codeCalls int
	callCalls int
	lastTo    common.Address
	lastData  []byte
}

func (c *mockChainClient) CodeAt(context.Context, common.Address) ([]byte, error) {
	c.codeCalls++
	return c.code, c.codeErr
}

func (c *mockChainClient) CallContract(_ context.Context, to common.Address, data []byte) ([]byte, error) {
	c.callCalls++
	c.lastTo = to
	c.lastData = append([]byte(nil), data...)
	return c.ret, c.callErr
}

func TestEVMAdapterERC1271Valid(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{"chainId": 1})

	ret := make([]byte, 32)
	copy(ret, []byte{0x16, 0x26, 0xba, 0x7e})
	client := &mockChainClient{code: []byte{0x60, 0x00}, ret: ret}
	v := evmadapter.New(evmadapter.WithChainClient(mockResolver{"eip155:1": client}))

	id, err := v.Verify(context.Background(), msg, sig, siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id == nil || id.Account.ChainID.String() != "eip155:1" {
		t.Fatalf("identity: got %#v", id)
	}
	if client.codeCalls != 1 {
		t.Fatalf("CodeAt calls: got %d, want 1", client.codeCalls)
	}
	if client.callCalls != 1 {
		t.Fatalf("CallContract calls: got %d, want 1", client.callCalls)
	}
	if len(client.lastData) < 4 || string(client.lastData[:4]) != string([]byte{0x16, 0x26, 0xba, 0x7e}) {
		t.Fatalf("selector: got %x", client.lastData[:min(len(client.lastData), 4)])
	}
}

func TestEVMAdapterERC1271Invalid(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{"chainId": 1})

	client := &mockChainClient{code: []byte{0x60, 0x00}, ret: make([]byte, 32)}
	v := evmadapter.New(evmadapter.WithChainClient(mockResolver{"eip155:1": client}))

	_, err := v.Verify(context.Background(), msg, sig, siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if !errors.Is(err, siwx.ErrContractValidationFailed) {
		t.Fatalf("want ErrContractValidationFailed, got %v", err)
	}
}

func TestEVMAdapterERC1271RPCErrors(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{"chainId": 1})
	rpcErr := errors.New("rpc down")

	t.Run("CodeAt", func(t *testing.T) {
		client := &mockChainClient{codeErr: rpcErr}
		v := evmadapter.New(evmadapter.WithChainClient(mockResolver{"eip155:1": client}))

		_, err := v.Verify(context.Background(), msg, sig, siwx.VerifyOpts{
			ExpectedDomain: "dapp.academy",
			ExpectedNonce:  nonce,
			Observer:       siwx.NopObserver{},
			Clock:          refClock,
		})
		if !errors.Is(err, siwx.ErrRPC) {
			t.Fatalf("want ErrRPC, got %v", err)
		}
	})

	t.Run("CallContract", func(t *testing.T) {
		client := &mockChainClient{code: []byte{0x60, 0x00}, callErr: rpcErr}
		v := evmadapter.New(evmadapter.WithChainClient(mockResolver{"eip155:1": client}))

		_, err := v.Verify(context.Background(), msg, sig, siwx.VerifyOpts{
			ExpectedDomain: "dapp.academy",
			ExpectedNonce:  nonce,
			Observer:       siwx.NopObserver{},
			Clock:          refClock,
		})
		if !errors.Is(err, siwx.ErrRPC) {
			t.Fatalf("want ErrRPC, got %v", err)
		}
	})
}

func TestEVMAdapterERC6492UnsupportedWithoutClient(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{"chainId": 1})

	_, err := evmadapter.New().Verify(context.Background(), msg, withERC6492Suffix(sig), siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if !errors.Is(err, siwx.ErrContractWalletUnsupported) {
		t.Fatalf("want ErrContractWalletUnsupported, got %v", err)
	}
}

func TestEVMAdapterERC6492UnsupportedWithClient(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{"chainId": 1})
	client := &mockChainClient{code: []byte{0x60, 0x00}}
	v := evmadapter.New(evmadapter.WithChainClient(mockResolver{"eip155:1": client}))

	_, err := v.Verify(context.Background(), msg, withERC6492Suffix(sig), siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if !errors.Is(err, siwx.ErrContractWalletUnsupported) {
		t.Fatalf("want ErrContractWalletUnsupported, got %v", err)
	}
	if client.codeCalls != 0 || client.callCalls != 0 {
		t.Fatalf("6492 path made chain calls: CodeAt=%d CallContract=%d", client.codeCalls, client.callCalls)
	}
}

func TestEVMAdapterEOAWithClientConfigured(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{"chainId": 1})
	client := &mockChainClient{}
	v := evmadapter.New(evmadapter.WithChainClient(mockResolver{"eip155:1": client}))

	id, err := v.Verify(context.Background(), msg, sig, siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id == nil {
		t.Fatal("identity is nil")
	}
	if client.codeCalls != 1 {
		t.Fatalf("CodeAt calls: got %d, want 1", client.codeCalls)
	}
	if client.callCalls != 0 {
		t.Fatalf("CallContract calls: got %d, want 0", client.callCalls)
	}
}

func withERC6492Suffix(sig []byte) []byte {
	out := append([]byte(nil), sig...)
	return append(out, common.FromHex("0x6492649264926492649264926492649264926492649264926492649264926492")...)
}
