package solana_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anitconsultant/siwx-go/siwx"
	solanadapter "github.com/anitconsultant/siwx-go/siwx/solana"
)

// ---- vector loader (mirrors siws package; WT-D will unify) ----

type tvKey struct {
	ID              string `json:"id"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
}

type tvEntry struct {
	Name            string `json:"name"`
	Key             string `json:"key"`
	MessageBase64   string `json:"messageBase64"`
	SignatureBase64 string `json:"signatureBase64"`
	ExpectedError   string `json:"expectedError"`
}

type tvFile struct {
	ReferenceTime string    `json:"referenceTime"`
	Keys          []tvKey   `json:"keys"`
	Valid         []tvEntry `json:"valid"`
	Invalid       []tvEntry `json:"invalid"`
}

func loadVectors(t *testing.T) tvFile {
	t.Helper()
	raw, err := os.ReadFile("../../internal/testvectors/vectors.json")
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var tv tvFile
	if err := json.Unmarshal(raw, &tv); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return tv
}

func refTime(t *testing.T, tv tvFile) time.Time {
	t.Helper()
	s := strings.Replace(tv.ReferenceTime, ".000Z", "Z", 1)
	rt, err := time.Parse(time.RFC3339, s)
	if err != nil {
		rt, err = time.Parse("2006-01-02T15:04:05.000Z", tv.ReferenceTime)
	}
	if err != nil {
		t.Fatalf("parse referenceTime: %v", err)
	}
	return rt
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return b
}

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

// recordingObserver captures events for ordering assertions.
type recordingObserver struct {
	events []string
}

func (r *recordingObserver) OnVerifyAttempt(e siwx.VerifyAttempt) {
	r.events = append(r.events, "attempt")
}
func (r *recordingObserver) OnParseResult(e siwx.ParseResult) { r.events = append(r.events, "parse") }
func (r *recordingObserver) OnCheckResult(e siwx.CheckResult) {
	r.events = append(r.events, "check:"+string(e.Check))
}
func (r *recordingObserver) OnVerifyResult(e siwx.VerifyResult) {
	r.events = append(r.events, "result")
}

// ---- tests ----

func TestSolanaAdapterNamespace(t *testing.T) {
	if solanadapter.New().Namespace() != "solana" {
		t.Error("want namespace 'solana'")
	}
}

func TestSolanaAdapterValidVectors(t *testing.T) {
	tv := loadVectors(t)
	rt := refTime(t, tv)
	v := solanadapter.New()

	for _, vec := range tv.Valid {
		t.Run(vec.Name, func(t *testing.T) {
			msgBytes := decodeB64(t, vec.MessageBase64)
			sig := decodeB64(t, vec.SignatureBase64)

			// Parse message to get domain and nonce.
			// We reuse siws indirectly via the adapter; for opts we need the
			// actual values from the message — parse them manually.
			domain, nonce := extractDomainNonce(t, msgBytes)

			rec := &recordingObserver{}
			opts := siwx.VerifyOpts{
				ExpectedDomain: domain,
				ExpectedNonce:  nonce,
				Observer:       rec,
				Clock:          fixedClock{rt},
				AttemptID:      "test-attempt",
			}
			id, err := v.Verify(context.Background(), msgBytes, sig, opts)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if id.Account.ChainID.Namespace != "solana" {
				t.Errorf("account namespace: got %q", id.Account.ChainID.Namespace)
			}
			if id.Domain != domain {
				t.Errorf("identity domain: got %q want %q", id.Domain, domain)
			}
		})
	}
}

func TestSolanaAdapterInvalidVectors(t *testing.T) {
	tv := loadVectors(t)
	rt := refTime(t, tv)
	v := solanadapter.New()

	errMap := map[string]error{
		"ErrMalformed":      siwx.ErrMalformed,
		"ErrBadSignature":   siwx.ErrBadSignature,
		"ErrExpired":        siwx.ErrExpired,
		"ErrNotYetValid":    siwx.ErrNotYetValid,
		"ErrDomainMismatch": siwx.ErrDomainMismatch,
		"ErrNonceMismatch":  siwx.ErrNonceMismatch,
	}

	for _, vec := range tv.Invalid {
		t.Run(vec.Name, func(t *testing.T) {
			want := errMap[vec.ExpectedError]
			msgBytes := decodeB64(t, vec.MessageBase64)
			sig := decodeB64(t, vec.SignatureBase64)

			domain := "dapp.academy"
			nonce := "placeholder0000"
			if vec.Name == "domain_mismatch_check" {
				domain = "evil.example"
			}
			if d, n := extractDomainNonceSafe(msgBytes); d != "" {
				if vec.Name != "domain_mismatch_check" {
					domain = d
				}
				nonce = n
			}

			opts := siwx.VerifyOpts{
				ExpectedDomain: domain,
				ExpectedNonce:  nonce,
				Observer:       siwx.NopObserver{},
				Clock:          fixedClock{rt},
			}
			_, err := v.Verify(context.Background(), msgBytes, sig, opts)
			if err == nil {
				t.Fatalf("want error %v, got nil", want)
			}
			if !errors.Is(err, want) {
				t.Errorf("want errors.Is(%v), got %v", want, err)
			}
		})
	}
}

func TestSolanaAdapterObserverEventOrder(t *testing.T) {
	tv := loadVectors(t)
	rt := refTime(t, tv)
	v := solanadapter.New()

	vec := tv.Valid[0]
	msgBytes := decodeB64(t, vec.MessageBase64)
	sig := decodeB64(t, vec.SignatureBase64)
	domain, nonce := extractDomainNonce(t, msgBytes)

	rec := &recordingObserver{}
	opts := siwx.VerifyOpts{
		ExpectedDomain: domain,
		ExpectedNonce:  nonce,
		Observer:       rec,
		Clock:          fixedClock{rt},
	}
	v.Verify(context.Background(), msgBytes, sig, opts) //nolint:errcheck

	// Expected: parse, check:domain, check:not_before, check:expiry, check:nonce, check:signature
	if len(rec.events) < 6 {
		t.Fatalf("expected >=6 events, got %d: %v", len(rec.events), rec.events)
	}
	if rec.events[0] != "parse" {
		t.Errorf("first event should be parse, got %q", rec.events[0])
	}
}

// ---- helpers ----

// extractDomainNonce parses the first two meaningful fields from a SIWS message
// without importing the full siws package (avoids circular dep in tests).
func extractDomainNonce(t *testing.T, msg []byte) (domain, nonce string) {
	t.Helper()
	d, n := extractDomainNonceSafe(msg)
	if d == "" || n == "" {
		t.Fatalf("could not extract domain/nonce from message")
	}
	return d, n
}

func extractDomainNonceSafe(msg []byte) (domain, nonce string) {
	lines := strings.Split(string(msg), "\n")
	const suffix = " wants you to sign in with your Solana account:"
	for _, line := range lines {
		if strings.HasSuffix(line, suffix) {
			domain = strings.TrimSuffix(line, suffix)
		}
		if strings.HasPrefix(line, "Nonce: ") {
			nonce = strings.TrimPrefix(line, "Nonce: ")
		}
	}
	return
}
