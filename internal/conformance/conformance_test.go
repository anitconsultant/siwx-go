// Package conformance_test proves that every test vector produces the same
// result whether it is verified via siws.VerifyRaw or via the full
// siwx.VerifierRegistry + solana adapter pipeline.
package conformance_test

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/anitconsultant/siwx-go/internal/testvectors"
	"github.com/anitconsultant/siwx-go/siws"
	"github.com/anitconsultant/siwx-go/siwx"
	solanadapter "github.com/anitconsultant/siwx-go/siwx/solana"
)

func loadCorpus(t *testing.T) *testvectors.Corpus {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	c, err := testvectors.Load(filepath.Join(root, "internal", "testvectors", "vectors.json"))
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	return c
}

// domainNonce extracts the verification parameters for a vector.
// domain_mismatch_check is the only vector where ExpectedDomain differs from
// the domain embedded in the message — by design.
func domainNonce(v testvectors.Vector) (domain, nonce string) {
	domain, nonce = testvectors.ExtractDomainNonce(v.Message)
	if v.Name == "domain_mismatch_check" {
		domain = "evil.example"
	}
	if domain == "" {
		domain = "placeholder.example"
	}
	if nonce == "" {
		nonce = "placeholder000"
	}
	return
}

// chainRef extracts the CAIP-2 reference (e.g. "mainnet") from a SIWS message.
func chainRef(msg []byte) string {
	for _, line := range strings.Split(string(msg), "\n") {
		if strings.HasPrefix(line, "Chain ID: ") {
			return strings.TrimPrefix(line, "Chain ID: ")
		}
	}
	return "mainnet"
}

// ---- siws.VerifyRaw conformance ----

func TestSIWSValidVectors(t *testing.T) {
	c := loadCorpus(t)
	refTime := c.ReferenceTime

	for _, v := range c.Valid {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			domain, nonce := domainNonce(v)
			opts := siws.VerifyOpts{
				ExpectedDomain: domain,
				ExpectedNonce:  nonce,
				Now:            func() time.Time { return refTime },
			}
			if _, err := siws.VerifyRaw(v.Message, v.Signature, opts); err != nil {
				t.Errorf("siws.VerifyRaw: unexpected error: %v", err)
			}
		})
	}
}

func TestSIWSInvalidVectors(t *testing.T) {
	c := loadCorpus(t)
	refTime := c.ReferenceTime

	for _, v := range c.Invalid {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			domain, nonce := domainNonce(v)
			opts := siws.VerifyOpts{
				ExpectedDomain: domain,
				ExpectedNonce:  nonce,
				Now:            func() time.Time { return refTime },
			}
			_, err := siws.VerifyRaw(v.Message, v.Signature, opts)
			if err == nil {
				t.Fatalf("want error wrapping %v, got nil", v.ExpectedError)
			}
			if !errors.Is(err, v.ExpectedError) {
				t.Errorf("want errors.Is(%v), got %v", v.ExpectedError, err)
			}
		})
	}
}

// ---- siwx registry + solana adapter conformance ----

func newRegistry() siwx.VerifierRegistry {
	r := siwx.NewRegistry()
	r.Register(solanadapter.New())
	return r
}

func TestRegistryValidVectors(t *testing.T) {
	c := loadCorpus(t)
	r := newRegistry()

	for _, v := range c.Valid {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			domain, nonce := domainNonce(v)
			chainID := siwx.CAIP2{Namespace: "solana", Reference: chainRef(v.Message)}
			opts := siwx.VerifyOpts{
				ExpectedDomain: domain,
				ExpectedNonce:  nonce,
				Observer:       siwx.NopObserver{},
				Clock:          c.FrozenClock(),
			}
			id, err := r.Verify(context.Background(), chainID, v.Message, v.Signature, opts)
			if err != nil {
				t.Fatalf("registry.Verify: unexpected error: %v", err)
			}
			if id.Domain != domain {
				t.Errorf("identity domain: got %q want %q", id.Domain, domain)
			}
		})
	}
}

func TestRegistryInvalidVectors(t *testing.T) {
	c := loadCorpus(t)
	r := newRegistry()

	for _, v := range c.Invalid {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			domain, nonce := domainNonce(v)
			chainID := siwx.CAIP2{Namespace: "solana", Reference: chainRef(v.Message)}
			opts := siwx.VerifyOpts{
				ExpectedDomain: domain,
				ExpectedNonce:  nonce,
				Observer:       siwx.NopObserver{},
				Clock:          c.FrozenClock(),
			}
			_, err := r.Verify(context.Background(), chainID, v.Message, v.Signature, opts)
			if err == nil {
				t.Fatalf("want error wrapping %v, got nil", v.ExpectedError)
			}
			// The registry pipeline maps siws.* sentinels to siwx.* equivalents.
			wantSiwx := testvectors.SiwxSentinelFor(v.ExpectedError)
			if !errors.Is(err, wantSiwx) {
				t.Errorf("want errors.Is(%v), got %v", wantSiwx, err)
			}
		})
	}
}
