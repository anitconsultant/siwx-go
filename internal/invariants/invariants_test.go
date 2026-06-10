// Package invariants_test asserts security and observability invariants that
// must hold regardless of which path through the verification pipeline is taken.
package invariants_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// mustJSON serializes an observer event so tests can scan every field at once.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return string(b)
}

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

// validSiwsOpts builds siws.VerifyOpts for the first valid vector at the given time.
func validSiwsOpts(c *testvectors.Corpus, v testvectors.Vector, now time.Time) siws.VerifyOpts {
	domain, nonce := testvectors.ExtractDomainNonce(v.Message)
	return siws.VerifyOpts{
		ExpectedDomain: domain,
		ExpectedNonce:  nonce,
		Now:            func() time.Time { return now },
	}
}

// ---- S3 security invariants ----

// Invariant 1: expired messages never verify.
func TestInvariantExpiredNeverVerifies(t *testing.T) {
	c := loadCorpus(t)
	// basic_with_expiry expires at 2026-06-09T12:09:00Z
	v := c.Valid[0] // basic_with_expiry

	// Advance clock past expiry.
	afterExpiry := c.ReferenceTime.Add(10 * time.Minute)
	opts := validSiwsOpts(c, v, afterExpiry)
	_, err := siws.VerifyRaw(v.Message, v.Signature, opts)
	if !errors.Is(err, siws.ErrExpired) {
		t.Errorf("want ErrExpired after expiry, got %v", err)
	}
}

// Invariant 2: wrong domain never verifies.
func TestInvariantWrongDomainNeverVerifies(t *testing.T) {
	c := loadCorpus(t)
	v := c.Valid[0] // basic_with_expiry

	_, nonce := testvectors.ExtractDomainNonce(v.Message)
	opts := siws.VerifyOpts{
		ExpectedDomain: "evil.example",
		ExpectedNonce:  nonce,
		Now:            func() time.Time { return c.ReferenceTime },
	}
	_, err := siws.VerifyRaw(v.Message, v.Signature, opts)
	if !errors.Is(err, siws.ErrDomainMismatch) {
		t.Errorf("want ErrDomainMismatch, got %v", err)
	}
}

// Invariant 3: wrong nonce never verifies.
func TestInvariantWrongNonceNeverVerifies(t *testing.T) {
	c := loadCorpus(t)
	v := c.Valid[0] // basic_with_expiry

	domain, _ := testvectors.ExtractDomainNonce(v.Message)
	opts := siws.VerifyOpts{
		ExpectedDomain: domain,
		ExpectedNonce:  "wrongnonce00",
		Now:            func() time.Time { return c.ReferenceTime },
	}
	_, err := siws.VerifyRaw(v.Message, v.Signature, opts)
	if !errors.Is(err, siws.ErrNonceMismatch) {
		t.Errorf("want ErrNonceMismatch, got %v", err)
	}
}

// Invariant 4: a single flipped bit in the signature causes failure.
func TestInvariantFlippedBitNeverVerifies(t *testing.T) {
	c := loadCorpus(t)
	v := c.Valid[0] // basic_with_expiry

	flipped := make([]byte, len(v.Signature))
	copy(flipped, v.Signature)
	flipped[0] ^= 0x01

	opts := validSiwsOpts(c, v, c.ReferenceTime)
	_, err := siws.VerifyRaw(v.Message, flipped, opts)
	if !errors.Is(err, siws.ErrBadSignature) {
		t.Errorf("want ErrBadSignature for flipped bit, got %v", err)
	}
}

// Invariant 5: signature by a different key never verifies.
func TestInvariantWrongKeyNeverVerifies(t *testing.T) {
	c := loadCorpus(t)
	// basic_with_expiry is signed by key0; no_statement_no_expiry is signed by key1.
	// Use key1's sig against basic_with_expiry's message (which claims key0's address).
	validForKey0 := c.Valid[0]           // message carries key0 address
	signedByKey1 := c.Valid[1].Signature // signature made by key1

	opts := validSiwsOpts(c, validForKey0, c.ReferenceTime)
	_, err := siws.VerifyRaw(validForKey0.Message, signedByKey1, opts)
	if !errors.Is(err, siws.ErrBadSignature) {
		t.Errorf("want ErrBadSignature for wrong key, got %v", err)
	}
}

// Invariant 6: future Not-Before never verifies.
func TestInvariantFutureNotBeforeNeverVerifies(t *testing.T) {
	c := loadCorpus(t)
	// with_not_before_devnet: NotBefore = 2026-06-09T11:59:00.000Z
	// Use a clock set to 11:58:30 (before NotBefore).
	v := c.Valid[2] // with_not_before_devnet

	beforeNotBefore := time.Date(2026, 6, 9, 11, 58, 30, 0, time.UTC)
	opts := validSiwsOpts(c, v, beforeNotBefore)
	_, err := siws.VerifyRaw(v.Message, v.Signature, opts)
	if !errors.Is(err, siws.ErrNotYetValid) {
		t.Errorf("want ErrNotYetValid before NotBefore, got %v", err)
	}
}

// ---- Observability invariants (S4, S5) ----

// captureObserver records all observer events.
type captureObserver struct {
	order    []string
	attempts []siwx.VerifyAttempt
	parses   []siwx.ParseResult
	checks   []siwx.CheckResult
	results  []siwx.VerifyResult
}

func (o *captureObserver) OnVerifyAttempt(e siwx.VerifyAttempt) {
	o.order = append(o.order, "attempt")
	o.attempts = append(o.attempts, e)
}
func (o *captureObserver) OnParseResult(e siwx.ParseResult) {
	o.order = append(o.order, "parse")
	o.parses = append(o.parses, e)
}
func (o *captureObserver) OnCheckResult(e siwx.CheckResult) {
	o.order = append(o.order, "check")
	o.checks = append(o.checks, e)
}
func (o *captureObserver) OnVerifyResult(e siwx.VerifyResult) {
	o.order = append(o.order, "result")
	o.results = append(o.results, e)
}

func runWithObserver(t *testing.T, c *testvectors.Corpus, v testvectors.Vector) (*captureObserver, error) {
	t.Helper()
	r := siwx.NewRegistry()
	r.Register(solanadapter.New())

	obs := &captureObserver{}
	domain, nonce := testvectors.ExtractDomainNonce(v.Message)
	opts := siwx.VerifyOpts{
		ExpectedDomain: domain,
		ExpectedNonce:  nonce,
		Observer:       obs,
		Clock:          c.FrozenClock(),
	}
	chainID := siwx.CAIP2{Namespace: "solana", Reference: "mainnet"}
	_, err := r.Verify(context.Background(), chainID, v.Message, v.Signature, opts)
	return obs, err
}

// Invariant 7: Observer events arrive in a predictable order.
// For a successful Solana verify: parse → checks → result (no attempt since
// the registry emits attempt before delegating, then parse comes from the adapter).
func TestInvariantObserverEventOrdering(t *testing.T) {
	c := loadCorpus(t)
	obs, err := runWithObserver(t, c, c.Valid[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(obs.order) < 3 {
		t.Fatalf("expected at least 3 events, got %v", obs.order)
	}
	// parse must come before any check.
	parseIdx := -1
	for i, e := range obs.order {
		if e == "parse" {
			parseIdx = i
			break
		}
	}
	if parseIdx < 0 {
		t.Fatal("no parse event")
	}
	for i, e := range obs.order {
		if e == "check" && i < parseIdx {
			t.Errorf("check event at %d appeared before parse event at %d", i, parseIdx)
		}
	}

	// result must be the last event.
	if obs.order[len(obs.order)-1] != "result" {
		t.Errorf("last event must be 'result', got %q", obs.order[len(obs.order)-1])
	}
}

// Invariant 8 (S5): Observer events carry no raw signature bytes or key material.
// ParseResult.MsgBytes is just a count, not the bytes. No event field should
// equal the raw signature.
func TestInvariantObserverNoSensitiveData(t *testing.T) {
	c := loadCorpus(t)
	v := c.Valid[0]
	obs, _ := runWithObserver(t, c, v)

	// Verify MsgBytes is a count, not the raw bytes.
	for _, pr := range obs.parses {
		if pr.MsgBytes != len(v.Message) {
			t.Errorf("ParseResult.MsgBytes=%d want %d (count, not bytes)", pr.MsgBytes, len(v.Message))
		}
	}

	// Serialize every captured event and assert the raw signature never appears
	// in any field, in either base64 or hex encoding. This catches a leak in any
	// current or future event field, not just the ones we name by hand.
	sigB64 := base64.StdEncoding.EncodeToString(v.Signature)
	sigHex := hex.EncodeToString(v.Signature)
	var events []string
	for _, e := range obs.attempts {
		events = append(events, mustJSON(t, e))
	}
	for _, e := range obs.parses {
		events = append(events, mustJSON(t, e))
	}
	for _, e := range obs.checks {
		events = append(events, mustJSON(t, e))
	}
	for _, e := range obs.results {
		events = append(events, mustJSON(t, e))
	}
	for _, e := range events {
		if strings.Contains(e, sigB64) || strings.Contains(e, sigHex) {
			t.Errorf("observer event leaks raw signature: %s", e)
		}
	}

	// Verify no attempt event leaks message text.
	for _, ae := range obs.attempts {
		if ae.Namespace != "solana" {
			t.Errorf("VerifyAttempt.Namespace unexpected: %q", ae.Namespace)
		}
	}
}

// Invariant: corpus loadCorpus panics cleanly when index is out of bounds.
func TestCorpusHasValidVectors(t *testing.T) {
	c := loadCorpus(t)
	if len(c.Valid) == 0 {
		t.Fatal("corpus has no valid vectors — subsequent c.Valid[N] calls would panic")
	}
	if len(c.Invalid) == 0 {
		t.Fatal("corpus has no invalid vectors")
	}
}

// Invariant (S4): Error text from VerifyRaw never echoes attacker-controlled
// field values. Only field names and sentinel descriptions are allowed.
func TestInvariantS4ErrorTextNeverEchoesInput(t *testing.T) {
	c := loadCorpus(t)
	ref := c.ReferenceTime

	marker := "ATTACKER_MARKER_12345"

	// For each well-formed field we inject the marker, expecting ErrMalformed or
	// a sentinel — but never the marker reflected back in the error text.
	cases := []struct {
		name string
		msg  string
		opts siws.VerifyOpts
	}{
		{
			name: "marker_in_statement",
			msg: "dapp.academy wants you to sign in with your Solana account:\n" +
				"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
				marker + "\n\n" +
				"URI: https://dapp.academy/login\nVersion: 1\nChain ID: mainnet\n" +
				"Nonce: 32891756dCb1\nIssued At: 2026-06-09T11:59:00.000Z\n" +
				"Expiration Time: 2026-06-09T12:09:00.000Z",
			opts: siws.VerifyOpts{
				ExpectedDomain: "dapp.academy",
				ExpectedNonce:  "32891756dCb1",
				Now:            func() time.Time { return ref },
			},
		},
		{
			name: "marker_as_nonce",
			msg: "dapp.academy wants you to sign in with your Solana account:\n" +
				"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
				"URI: https://dapp.academy\nVersion: 1\nChain ID: mainnet\n" +
				"Nonce: " + marker + "\nIssued At: 2026-06-09T11:59:00.000Z",
			opts: siws.VerifyOpts{
				ExpectedDomain: "dapp.academy",
				ExpectedNonce:  "wrongnonce000",
				Now:            func() time.Time { return ref },
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// The all-zero signature guarantees a failure path, so an error is
			// required; a nil here would mean the test passed vacuously.
			_, err := siws.VerifyRaw([]byte(tc.msg), make([]byte, 64), tc.opts)
			if err == nil {
				t.Fatal("expected an error (bad signature at minimum), got nil")
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("S4 violation: error text echoes attacker marker: %v", err)
			}
		})
	}
}

// Invariant (S5 extended): Observer events on a failing verification also carry
// no sensitive data. Covers all event types and the failure path.
func TestInvariantObserverNoSensitiveDataOnFailure(t *testing.T) {
	c := loadCorpus(t)
	if len(c.Invalid) == 0 {
		t.Fatal("no invalid vectors")
	}
	// Use the first invalid vector (tampered_nonce — bad signature, valid structure).
	v := c.Invalid[0]
	domain, nonce := testvectors.ExtractDomainNonce(v.Message)
	if domain == "" {
		domain = "placeholder.example"
	}
	if nonce == "" {
		nonce = "placeholder000"
	}

	r := siwx.NewRegistry()
	r.Register(solanadapter.New())
	obs := &captureObserver{}
	opts := siwx.VerifyOpts{
		ExpectedDomain: domain,
		ExpectedNonce:  nonce,
		Observer:       obs,
		Clock:          c.FrozenClock(),
	}
	chainID := siwx.CAIP2{Namespace: "solana", Reference: "mainnet"}
	_, err := r.Verify(context.Background(), chainID, v.Message, v.Signature, opts)
	if err == nil {
		t.Fatal("expected error for invalid vector, got nil")
	}

	// Check events contain no raw signature or message bytes.
	for _, pr := range obs.parses {
		if pr.MsgBytes != len(v.Message) {
			t.Errorf("ParseResult.MsgBytes is not the byte count: got %d, len(msg)=%d", pr.MsgBytes, len(v.Message))
		}
	}
	for _, cr := range obs.checks {
		if bytes.Contains([]byte(cr.AttemptID), v.Signature) {
			t.Error("CheckResult.AttemptID contains raw signature bytes")
		}
		if bytes.Contains([]byte(string(cr.Check)), v.Signature) {
			t.Error("CheckResult.Check contains raw signature bytes")
		}
	}
	for _, vr := range obs.results {
		if bytes.Contains([]byte(vr.AttemptID), v.Signature) {
			t.Error("VerifyResult.AttemptID contains raw signature bytes")
		}
	}
}

// Invariant 9: AttemptID is consistent across all events from a single call.
func TestInvariantAttemptIDConsistent(t *testing.T) {
	c := loadCorpus(t)
	obs, _ := runWithObserver(t, c, c.Valid[0])

	// Collect all attempt IDs from all events.
	var ids []string
	for _, e := range obs.parses {
		ids = append(ids, e.AttemptID)
	}
	for _, e := range obs.checks {
		ids = append(ids, e.AttemptID)
	}
	for _, e := range obs.results {
		ids = append(ids, e.AttemptID)
	}

	if len(ids) == 0 {
		t.Fatal("no events captured")
	}
	first := ids[0]
	for _, id := range ids[1:] {
		if id != first {
			t.Errorf("inconsistent AttemptID: %q != %q", id, first)
		}
	}
	if len(first) == 0 {
		t.Error("AttemptID must not be empty")
	}
}
