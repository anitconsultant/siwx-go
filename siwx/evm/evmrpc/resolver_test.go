package evmrpc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/anitconsultant/siwx-go/siwx/evm"
	"github.com/anitconsultant/siwx-go/siwx/evm/evmrpc"
)

// rpcServer is a minimal JSON-RPC endpoint that returns canned results for the
// two methods the resolver's client issues (eth_getCode, eth_call), so the
// happy paths can be exercised without a real node.
func rpcServer(t *testing.T, codeHex, callHex string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode rpc request: %v", err)
			return
		}
		var result string
		switch req.Method {
		case "eth_getCode":
			result = codeHex
		case "eth_call":
			result = callHex
		default:
			result = "0x"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":"` + result + `"}`))
	}))
}

func TestResolverClientFor(t *testing.T) {
	srv := rpcServer(t, "0x", "0x")
	defer srv.Close()

	r := evmrpc.NewResolver(map[string]string{"eip155:1": srv.URL})

	if _, ok := r.ClientFor("eip155:1"); !ok {
		t.Error("want client for configured chain eip155:1")
	}
	if _, ok := r.ClientFor("eip155:999"); ok {
		t.Error("want no client for unconfigured chain")
	}
	if _, ok := r.ClientFor("solana:mainnet"); ok {
		t.Error("want no client for unconfigured chain id")
	}
}

func TestResolverCodeAtAndCallContract(t *testing.T) {
	srv := rpcServer(t, "0x6080604052", "0x1626ba7e")
	defer srv.Close()

	r := evmrpc.NewResolver(map[string]string{"eip155:8453": srv.URL})
	c, ok := r.ClientFor("eip155:8453")
	if !ok {
		t.Fatal("client missing")
	}

	ctx := context.Background()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	code, err := c.CodeAt(ctx, addr)
	if err != nil {
		t.Fatalf("CodeAt: %v", err)
	}
	if !bytes.Equal(code, common.FromHex("0x6080604052")) {
		t.Errorf("CodeAt bytes: got %x", code)
	}

	// Second call exercises the cached *ethclient.Client path.
	ret, err := c.CallContract(ctx, addr, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("CallContract: %v", err)
	}
	if !bytes.Equal(ret, common.FromHex("0x1626ba7e")) {
		t.Errorf("CallContract bytes: got %x", ret)
	}
}

func TestResolverCallContractCreation(t *testing.T) {
	srv := rpcServer(t, "0x", "0x01")
	defer srv.Close()

	r := evmrpc.NewResolver(map[string]string{"eip155:1": srv.URL})
	c, ok := r.ClientFor("eip155:1")
	if !ok {
		t.Fatal("client missing")
	}
	dc, ok := c.(evm.DeploylessCaller)
	if !ok {
		t.Fatal("evmrpc client must implement evm.DeploylessCaller")
	}

	ret, err := dc.CallContractCreation(context.Background(), []byte{0x60, 0x80})
	if err != nil {
		t.Fatalf("CallContractCreation: %v", err)
	}
	if !bytes.Equal(ret, common.FromHex("0x01")) {
		t.Errorf("CallContractCreation bytes: got %x", ret)
	}
}

func TestResolverDialError(t *testing.T) {
	// A syntactically invalid endpoint makes the lazy dial fail; the error must
	// surface from the chain-access methods rather than panic.
	r := evmrpc.NewResolver(map[string]string{"eip155:1": "://not-a-url"})
	c, ok := r.ClientFor("eip155:1")
	if !ok {
		t.Fatal("client missing")
	}
	if _, err := c.CodeAt(context.Background(), common.Address{}); err == nil {
		t.Error("want dial error from CodeAt on invalid endpoint")
	}
	if _, err := c.CallContract(context.Background(), common.Address{}, nil); err == nil {
		t.Error("want dial error from CallContract on invalid endpoint")
	}
	if _, err := c.(evm.DeploylessCaller).CallContractCreation(context.Background(), nil); err == nil {
		t.Error("want dial error from CallContractCreation on invalid endpoint")
	}
}
