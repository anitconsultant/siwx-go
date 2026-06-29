package evm_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	siwelib "github.com/spruceid/siwe-go"

	"github.com/anitconsultant/siwx-go/siwx"
	evmadapter "github.com/anitconsultant/siwx-go/siwx/evm"
)

// mockDeployless implements both ChainClient and DeploylessCaller.
type mockDeployless struct {
	ret           []byte
	err           error
	creationCalls int
	lastData      []byte
}

func (m *mockDeployless) CodeAt(context.Context, common.Address) ([]byte, error) {
	return nil, nil
}

func (m *mockDeployless) CallContract(context.Context, common.Address, []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockDeployless) CallContractCreation(_ context.Context, data []byte) ([]byte, error) {
	m.creationCalls++
	m.lastData = append([]byte(nil), data...)
	return m.ret, m.err
}

type deploylessResolver struct{ c evmadapter.ChainClient }

func (r deploylessResolver) ClientFor(string) (evmadapter.ChainClient, bool) {
	return r.c, r.c != nil
}

func verifyWith6492(t *testing.T, client evmadapter.ChainClient) error {
	t.Helper()
	key, _ := ethcrypto.GenerateKey()
	nonce := siwelib.GenerateNonce()
	msg, sig := signSIWE(t, key, "dapp.academy", nonce, map[string]interface{}{"chainId": 1})
	v := evmadapter.New(evmadapter.WithChainClient(deploylessResolver{client}))
	_, err := v.Verify(context.Background(), msg, withERC6492Suffix(sig), siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  nonce,
		Observer:       siwx.NopObserver{},
		Clock:          refClock,
	})
	return err
}

func TestEVMAdapterERC6492Valid(t *testing.T) {
	m := &mockDeployless{ret: []byte{0x01}}
	if err := verifyWith6492(t, m); err != nil {
		t.Fatalf("want success, got %v", err)
	}
	if m.creationCalls != 1 {
		t.Fatalf("CallContractCreation calls: got %d, want 1", m.creationCalls)
	}
	// The deployless calldata must be the validator creation bytecode plus the
	// ABI-encoded (signer, hash, sig) args — far larger than the args alone.
	if len(m.lastData) < 3000 {
		t.Fatalf("deployless calldata too short (%d): bytecode not prepended?", len(m.lastData))
	}
}

func TestEVMAdapterERC6492Invalid(t *testing.T) {
	m := &mockDeployless{ret: []byte{0x00}}
	if err := verifyWith6492(t, m); !errors.Is(err, siwx.ErrContractValidationFailed) {
		t.Fatalf("want ErrContractValidationFailed, got %v", err)
	}
}

func TestEVMAdapterERC6492RPCError(t *testing.T) {
	m := &mockDeployless{err: errors.New("rpc down")}
	if err := verifyWith6492(t, m); !errors.Is(err, siwx.ErrRPC) {
		t.Fatalf("want ErrRPC, got %v", err)
	}
}
