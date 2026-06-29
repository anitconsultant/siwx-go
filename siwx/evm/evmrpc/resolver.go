// Package evmrpc provides an RPC-backed resolver for the EVM verifier.
package evmrpc

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/anitconsultant/siwx-go/siwx/evm"
)

type resolver struct {
	mu      sync.Mutex
	clients map[string]*client
}

type client struct {
	mu  sync.Mutex
	url string
	eth *ethclient.Client
}

// NewResolver returns an EVM resolver backed by caller-supplied RPC URLs.
// Map keys are CAIP-2 chain ids like "eip155:1"; values are RPC URLs.
func NewResolver(rpcByChain map[string]string) evm.Resolver {
	clients := make(map[string]*client, len(rpcByChain))
	for chainID, url := range rpcByChain {
		clients[chainID] = &client{url: url}
	}
	return &resolver{clients: clients}
}

func (r *resolver) ClientFor(chainID string) (evm.ChainClient, bool) {
	r.mu.Lock()
	c, ok := r.clients[chainID]
	r.mu.Unlock()
	if !ok {
		return nil, false
	}
	return c, true
}

func (c *client) CallContract(ctx context.Context, to common.Address, data []byte) ([]byte, error) {
	eth, err := c.ethClient(ctx)
	if err != nil {
		return nil, err
	}
	return eth.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
}

func (c *client) CodeAt(ctx context.Context, addr common.Address) ([]byte, error) {
	eth, err := c.ethClient(ctx)
	if err != nil {
		return nil, err
	}
	return eth.CodeAt(ctx, addr, nil)
}

func (c *client) ethClient(ctx context.Context) (*ethclient.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.eth != nil {
		return c.eth, nil
	}
	eth, err := ethclient.DialContext(ctx, c.url)
	if err != nil {
		return nil, err
	}
	c.eth = eth
	return eth, nil
}
