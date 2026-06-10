package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/anitconsultant/siwx-go/siwx"
)

// ---- NonceStore ----

type nonceEntry struct {
	expires time.Time
}

// memNonceStore is an in-memory NonceStore backed by a mutex-guarded map.
// Single-use is enforced: Burn deletes; a second Burn returns ErrNonceMismatch.
type memNonceStore struct {
	mu      sync.Mutex
	entries map[string]nonceEntry
	clock   func() time.Time
}

func newNonceStore(clock func() time.Time) *memNonceStore {
	return &memNonceStore{
		entries: make(map[string]nonceEntry),
		clock:   clock,
	}
}

func (s *memNonceStore) Issue(_ context.Context, ttl time.Duration) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(b)

	s.mu.Lock()
	s.sweep()
	s.entries[nonce] = nonceEntry{expires: s.clock().Add(ttl)}
	s.mu.Unlock()
	return nonce, nil
}

func (s *memNonceStore) Burn(_ context.Context, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[nonce]
	if !ok {
		return siwx.ErrNonceMismatch
	}
	delete(s.entries, nonce)
	if s.clock().After(e.expires) {
		return siwx.ErrNonceMismatch
	}
	return nil
}

// sweep deletes expired entries. Must be called with s.mu held.
func (s *memNonceStore) sweep() {
	now := s.clock()
	for k, e := range s.entries {
		if now.After(e.expires) {
			delete(s.entries, k)
		}
	}
}

// ---- IdentityStore ----

// memIdentityStore maps wallets↔identities in memory.
type memIdentityStore struct {
	mu          sync.Mutex
	walletToID  map[string]string   // CAIP-10 string → identityID
	idToWallets map[string][]string // identityID → []CAIP-10 strings
}

func newIdentityStore() *memIdentityStore {
	return &memIdentityStore{
		walletToID:  make(map[string]string),
		idToWallets: make(map[string][]string),
	}
}

func (s *memIdentityStore) UpsertByWallet(_ context.Context, w siwx.CAIP10) (identityID string, created bool, err error) {
	key := w.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.walletToID[key]; ok {
		return id, false, nil
	}
	// New identity.
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", false, err
	}
	id := "id_" + hex.EncodeToString(b)
	s.walletToID[key] = id
	s.idToWallets[id] = []string{key}
	return id, true, nil
}

func (s *memIdentityStore) LinkWallet(_ context.Context, identityID string, w siwx.CAIP10) error {
	key := w.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.idToWallets[identityID]; !ok {
		return errors.New("identity not found")
	}
	// Idempotent: skip if already linked.
	for _, existing := range s.idToWallets[identityID] {
		if existing == key {
			return nil
		}
	}
	s.walletToID[key] = identityID
	s.idToWallets[identityID] = append(s.idToWallets[identityID], key)
	return nil
}

func (s *memIdentityStore) Wallets(_ context.Context, identityID string) ([]siwx.CAIP10, error) {
	s.mu.Lock()
	strs := s.idToWallets[identityID]
	s.mu.Unlock()

	out := make([]siwx.CAIP10, 0, len(strs))
	for _, str := range strs {
		c, err := siwx.ParseCAIP10(str)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
