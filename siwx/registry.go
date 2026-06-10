package siwx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// registry is the default VerifierRegistry implementation.
type registry struct {
	mu        sync.RWMutex
	verifiers map[string]Verifier // namespace -> Verifier
}

// RegistryOption configures a new registry.
type RegistryOption func(*registry)

// NewRegistry creates a new VerifierRegistry.
// Register replaces any existing verifier for the same namespace silently.
func NewRegistry(opts ...RegistryOption) VerifierRegistry {
	r := &registry{verifiers: make(map[string]Verifier)}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Register adds or replaces the verifier for its namespace.
func (r *registry) Register(v Verifier) {
	r.mu.Lock()
	r.verifiers[v.Namespace()] = v
	r.mu.Unlock()
}

// Verify dispatches to the registered namespace verifier.
// It generates an AttemptID if none is provided, defaults nil Observer to
// NopObserver and nil Clock to RealClock, then delegates.
func (r *registry) Verify(ctx context.Context, chainID CAIP2, msg []byte, sig []byte, opts VerifyOpts) (*Identity, error) {
	// Default nil fields so adapters never need to nil-check.
	if opts.Observer == nil {
		opts.Observer = NopObserver{}
	}
	if opts.Clock == nil {
		opts.Clock = RealClock{}
	}
	if opts.AttemptID == "" {
		opts.AttemptID = newAttemptID()
	}

	start := time.Now()
	obs := opts.Observer

	obs.OnVerifyAttempt(VerifyAttempt{
		AttemptID: opts.AttemptID,
		Namespace: chainID.Namespace,
		Domain:    opts.ExpectedDomain,
	})

	r.mu.RLock()
	v, ok := r.verifiers[chainID.Namespace]
	r.mu.RUnlock()

	if !ok {
		err := fmt.Errorf("registry: namespace %q not registered: %w", chainID.Namespace, ErrUnsupportedNamespace)
		obs.OnVerifyResult(VerifyResult{
			AttemptID: opts.AttemptID,
			OK:        false,
			ErrorIs:   ErrUnsupportedNamespace,
			Namespace: chainID.Namespace,
			Duration:  time.Since(start),
		})
		return nil, err
	}

	id, err := v.Verify(ctx, msg, sig, opts)
	obs.OnVerifyResult(VerifyResult{
		AttemptID: opts.AttemptID,
		OK:        err == nil,
		ErrorIs:   sentinelFor(err),
		Namespace: chainID.Namespace,
		Duration:  time.Since(start),
	})
	return id, err
}

// newAttemptID returns a random 16-byte hex string.
func newAttemptID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("siwx: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// sentinelFor extracts the first known sentinel from err, or nil if err is nil.
func sentinelFor(err error) error {
	if err == nil {
		return nil
	}
	for _, s := range []error{
		ErrMalformed, ErrBadSignature, ErrExpired, ErrNotYetValid,
		ErrDomainMismatch, ErrNonceMismatch, ErrUnsupportedNamespace,
	} {
		if errors.Is(err, s) {
			return s
		}
	}
	return err
}
