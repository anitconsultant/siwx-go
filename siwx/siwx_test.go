package siwx_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anitconsultant/siwx-go/siwx"
)

// ---- CAIP2 tests ----

func TestParseCAIP2(t *testing.T) {
	type tc struct {
		input   string
		wantNS  string
		wantRef string
		wantErr bool
	}
	cases := []tc{
		{"solana:mainnet", "solana", "mainnet", false},
		{"eip155:1", "eip155", "1", false},
		{"eip155:137", "eip155", "137", false},
		{"abc:xyz123", "abc", "xyz123", false},
		{"ab:mainnet", "", "", true},           // namespace too short
		{"toolongname:ref", "", "", true},       // namespace too long
		{"Solana:mainnet", "", "", true},        // uppercase in namespace
		{"solanamainnet", "", "", true},         // no colon
		{"solana:", "", "", true},               // empty reference
		{"solana:" + strings.Repeat("a", 33), "", "", true}, // reference too long
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := siwx.ParseCAIP2(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("want error, got nil")
					return
				}
				if !errors.Is(err, siwx.ErrMalformed) {
					t.Errorf("want ErrMalformed, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Namespace != tc.wantNS || got.Reference != tc.wantRef {
				t.Errorf("got %+v, want {%s %s}", got, tc.wantNS, tc.wantRef)
			}
			if got.String() != tc.input {
				t.Errorf("String() round-trip: got %q want %q", got.String(), tc.input)
			}
		})
	}
}

// ---- CAIP10 tests ----

func TestParseCAIP10Valid(t *testing.T) {
	inputs := []string{
		"solana:mainnet:DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA",
		"eip155:1:0xAb5801a7D398351b8bE11C439e05C5b3259aeC9B",
		"eip155:1:0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
	}
	for _, s := range inputs {
		t.Run(s, func(t *testing.T) {
			got, err := siwx.ParseCAIP10(s)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != s {
				t.Errorf("round-trip: got %q want %q", got.String(), s)
			}
		})
	}
}

func TestParseCAIP10Invalid(t *testing.T) {
	cases := []string{
		"solanamainnet",
		"solana:mainnet",
		"ab:mainnet:addr",
		"solana:mainnet:",
		"SOLANA:mainnet:addr",
		"solana:mainnet:" + strings.Repeat("x", 129),
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			_, err := siwx.ParseCAIP10(s)
			if !errors.Is(err, siwx.ErrMalformed) {
				t.Errorf("want ErrMalformed, got %v", err)
			}
		})
	}
}

// ---- Observer tests ----

// recordingObserver captures all events in order.
type recordingObserver struct {
	attempts []siwx.VerifyAttempt
	parses   []siwx.ParseResult
	checks   []siwx.CheckResult
	results  []siwx.VerifyResult
}

func (r *recordingObserver) OnVerifyAttempt(e siwx.VerifyAttempt) { r.attempts = append(r.attempts, e) }
func (r *recordingObserver) OnParseResult(e siwx.ParseResult)     { r.parses = append(r.parses, e) }
func (r *recordingObserver) OnCheckResult(e siwx.CheckResult)     { r.checks = append(r.checks, e) }
func (r *recordingObserver) OnVerifyResult(e siwx.VerifyResult)   { r.results = append(r.results, e) }

func TestNopObserver(t *testing.T) {
	var n siwx.NopObserver
	// Must not panic.
	n.OnVerifyAttempt(siwx.VerifyAttempt{})
	n.OnParseResult(siwx.ParseResult{})
	n.OnCheckResult(siwx.CheckResult{})
	n.OnVerifyResult(siwx.VerifyResult{})
}

func TestRealClock(t *testing.T) {
	c := siwx.RealClock{}
	before := c.Now()
	after := c.Now()
	if after.Before(before) {
		t.Error("RealClock.Now is not monotonic")
	}
}

func TestRegistrySentinelMapping(t *testing.T) {
	// Trigger sentinelFor by having the stub return known sentinel errors.
	for _, wantErr := range []error{
		siwx.ErrMalformed, siwx.ErrBadSignature, siwx.ErrExpired,
		siwx.ErrNotYetValid, siwx.ErrDomainMismatch, siwx.ErrNonceMismatch,
	} {
		t.Run(wantErr.Error(), func(t *testing.T) {
			r := siwx.NewRegistry()
			stub := &stubVerifier{ns: "solana", err: wantErr}
			r.Register(stub)
			rec := &recordingObserver{}
			chainID := siwx.CAIP2{Namespace: "solana", Reference: "mainnet"}
			_, err := r.Verify(context.Background(), chainID, nil, nil, siwx.VerifyOpts{
				ExpectedDomain: "x", ExpectedNonce: "y", Observer: rec,
			})
			if !errors.Is(err, wantErr) {
				t.Errorf("want %v, got %v", wantErr, err)
			}
			if len(rec.results) != 1 || rec.results[0].ErrorIs != wantErr {
				t.Errorf("result ErrorIs not set correctly: got %v", rec.results[0].ErrorIs)
			}
		})
	}
}

func TestMultiObserverFanOut(t *testing.T) {
	r1 := &recordingObserver{}
	r2 := &recordingObserver{}
	m := siwx.MultiObserver(r1, r2)

	m.OnVerifyAttempt(siwx.VerifyAttempt{AttemptID: "x"})
	m.OnParseResult(siwx.ParseResult{AttemptID: "x", OK: true})
	m.OnCheckResult(siwx.CheckResult{AttemptID: "x", Check: siwx.CheckDomain, OK: true})
	m.OnVerifyResult(siwx.VerifyResult{AttemptID: "x", OK: true})

	for _, r := range []*recordingObserver{r1, r2} {
		if len(r.attempts) != 1 || r.attempts[0].AttemptID != "x" {
			t.Error("attempt not fanned out")
		}
		if len(r.parses) != 1 || !r.parses[0].OK {
			t.Error("parse result not fanned out")
		}
		if len(r.checks) != 1 {
			t.Error("check result not fanned out")
		}
		if len(r.results) != 1 || !r.results[0].OK {
			t.Error("verify result not fanned out")
		}
	}
}

func TestMultiObserverPanicIsolation(t *testing.T) {
	panic := &panicObserver{}
	rec := &recordingObserver{}
	m := siwx.MultiObserver(panic, rec)

	// Must not propagate the panic; rec must still receive events.
	m.OnVerifyAttempt(siwx.VerifyAttempt{AttemptID: "y"})
	if len(rec.attempts) != 1 {
		t.Errorf("want 1 attempt on rec, got %d", len(rec.attempts))
	}
}

type panicObserver struct{}

func (panicObserver) OnVerifyAttempt(siwx.VerifyAttempt) { panic("observer panic") }
func (panicObserver) OnParseResult(siwx.ParseResult)     { panic("observer panic") }
func (panicObserver) OnCheckResult(siwx.CheckResult)     { panic("observer panic") }
func (panicObserver) OnVerifyResult(siwx.VerifyResult)   { panic("observer panic") }

// ---- Registry tests ----

// stubVerifier is a minimal Verifier for registry dispatch tests.
type stubVerifier struct {
	ns  string
	err error
	id  *siwx.Identity
}

func (s *stubVerifier) Namespace() string { return s.ns }
func (s *stubVerifier) Verify(_ context.Context, _ []byte, _ []byte, _ siwx.VerifyOpts) (*siwx.Identity, error) {
	return s.id, s.err
}

func TestRegistryDispatch(t *testing.T) {
	r := siwx.NewRegistry()
	stub := &stubVerifier{ns: "solana", id: &siwx.Identity{Domain: "dapp.academy"}}
	r.Register(stub)

	rec := &recordingObserver{}
	chainID := siwx.CAIP2{Namespace: "solana", Reference: "mainnet"}
	opts := siwx.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  "nonce12345",
		Observer:       rec,
	}
	id, err := r.Verify(context.Background(), chainID, []byte("msg"), []byte("sig"), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Domain != "dapp.academy" {
		t.Errorf("got domain %q", id.Domain)
	}
	// Events: Attempt + Result (stub emits nothing itself)
	if len(rec.attempts) != 1 {
		t.Errorf("want 1 Attempt event, got %d", len(rec.attempts))
	}
	if len(rec.results) != 1 || !rec.results[0].OK {
		t.Errorf("want 1 successful Result event")
	}
}

func TestRegistryUnknownNamespace(t *testing.T) {
	r := siwx.NewRegistry()
	chainID := siwx.CAIP2{Namespace: "unknown", Reference: "1"}
	_, err := r.Verify(context.Background(), chainID, nil, nil, siwx.VerifyOpts{
		ExpectedDomain: "x",
		ExpectedNonce:  "y",
	})
	if !errors.Is(err, siwx.ErrUnsupportedNamespace) {
		t.Errorf("want ErrUnsupportedNamespace, got %v", err)
	}
}

func TestRegistryAttemptIDGenerated(t *testing.T) {
	r := siwx.NewRegistry()
	var captured string
	stub := &stubVerifier{ns: "solana", id: &siwx.Identity{}}
	r.Register(stub)

	rec := &recordingObserver{}
	chainID := siwx.CAIP2{Namespace: "solana", Reference: "mainnet"}
	opts := siwx.VerifyOpts{
		ExpectedDomain: "x",
		ExpectedNonce:  "y12345678",
		Observer:       rec,
		AttemptID:      "", // empty → registry generates one
	}
	r.Verify(context.Background(), chainID, nil, nil, opts) //nolint:errcheck

	if len(rec.attempts) == 0 {
		t.Fatal("no attempt event")
	}
	captured = rec.attempts[0].AttemptID
	if len(captured) != 32 { // 16 bytes hex = 32 chars
		t.Errorf("expected 32-char hex attemptID, got %q (len %d)", captured, len(captured))
	}
}

func TestRegistryAttemptIDPropagated(t *testing.T) {
	r := siwx.NewRegistry()
	stub := &stubVerifier{ns: "solana", id: &siwx.Identity{}}
	r.Register(stub)

	rec := &recordingObserver{}
	chainID := siwx.CAIP2{Namespace: "solana", Reference: "mainnet"}
	opts := siwx.VerifyOpts{
		ExpectedDomain: "x",
		ExpectedNonce:  "y12345678",
		Observer:       rec,
		AttemptID:      "fixed-attempt-id",
	}
	r.Verify(context.Background(), chainID, nil, nil, opts) //nolint:errcheck

	if len(rec.attempts) != 1 || rec.attempts[0].AttemptID != "fixed-attempt-id" {
		t.Error("attemptID not propagated to Attempt event")
	}
	if len(rec.results) != 1 || rec.results[0].AttemptID != "fixed-attempt-id" {
		t.Error("attemptID not propagated to Result event")
	}
}

func TestRegistryReplaceVerifier(t *testing.T) {
	r := siwx.NewRegistry()
	v1 := &stubVerifier{ns: "solana", id: &siwx.Identity{Domain: "v1"}}
	v2 := &stubVerifier{ns: "solana", id: &siwx.Identity{Domain: "v2"}}
	r.Register(v1)
	r.Register(v2)

	chainID := siwx.CAIP2{Namespace: "solana", Reference: "mainnet"}
	id, err := r.Verify(context.Background(), chainID, nil, nil, siwx.VerifyOpts{ExpectedDomain: "x", ExpectedNonce: "y"})
	if err != nil {
		t.Fatal(err)
	}
	if id.Domain != "v2" {
		t.Errorf("expected v2 to replace v1, got domain %q", id.Domain)
	}
}
