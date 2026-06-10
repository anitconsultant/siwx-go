package siws_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anitconsultant/siwx-go/siws"
)

// ---- test vector loader (WT-D will replace with shared loader) ----

type tvKey struct {
	ID              string `json:"id"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
}

type tvEntry struct {
	Name            string `json:"name"`
	Key             string `json:"key"`
	Message         string `json:"message"`
	MessageBase64   string `json:"messageBase64"`
	SignatureBase64 string `json:"signatureBase64"`
	ExpectedError   string `json:"expectedError"`
	Note            string `json:"note"`
}

type tvFile struct {
	ReferenceTime string    `json:"referenceTime"`
	Keys          []tvKey   `json:"keys"`
	Valid         []tvEntry `json:"valid"`
	Invalid       []tvEntry `json:"invalid"`
}

func loadVectors(t *testing.T) tvFile {
	t.Helper()
	raw, err := os.ReadFile("../internal/testvectors/vectors.json")
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
	rt, err := time.Parse(time.RFC3339, strings.Replace(tv.ReferenceTime, ".000Z", "Z", 1))
	if err != nil {
		rt, err = time.Parse("2006-01-02T15:04:05.000Z", tv.ReferenceTime)
	}
	if err != nil {
		t.Fatalf("parse referenceTime: %v", err)
	}
	return rt
}

// ---- base58 tests ----

func TestBase58RoundTrip(t *testing.T) {
	tv := loadVectors(t)
	for _, k := range tv.Keys {
		t.Run(k.ID, func(t *testing.T) {
			dec, err := siws.DecodeBase58(k.PublicKeyBase58)
			if err != nil {
				t.Fatalf("DecodeBase58(%q): %v", k.ID, err)
			}
			if len(dec) != 32 {
				t.Fatalf("want 32 bytes, got %d", len(dec))
			}
			enc := siws.EncodeBase58(dec)
			if enc != k.PublicKeyBase58 {
				t.Fatalf("round-trip mismatch: got %q want %q", enc, k.PublicKeyBase58)
			}
		})
	}
}

func TestBase58InvalidChar(t *testing.T) {
	cases := []string{"0abc", "Oabc", "Iabc", "labc", "abc!", "abc "}
	for _, c := range cases {
		if _, err := siws.DecodeBase58(c); err == nil {
			t.Errorf("DecodeBase58(%q): want error, got nil", c)
		}
	}
}

// ---- parse tests ----

func TestParseValid(t *testing.T) {
	tv := loadVectors(t)
	for _, vec := range tv.Valid {
		t.Run(vec.Name, func(t *testing.T) {
			msgBytes := decodeB64(t, vec.MessageBase64)
			m, err := siws.ParseMessage(msgBytes)
			if err != nil {
				t.Fatalf("ParseMessage: %v", err)
			}
			if m.Domain == "" {
				t.Error("domain is empty")
			}
			if m.Address == "" {
				t.Error("address is empty")
			}
			if m.Nonce == "" {
				t.Error("nonce is empty")
			}
		})
	}
}

func TestParseRoundTrip(t *testing.T) {
	tv := loadVectors(t)
	for _, vec := range tv.Valid {
		t.Run(vec.Name, func(t *testing.T) {
			msgBytes := decodeB64(t, vec.MessageBase64)
			m1, err := siws.ParseMessage(msgBytes)
			if err != nil {
				t.Fatalf("first parse: %v", err)
			}
			m2, err := siws.ParseMessage([]byte(m1.String()))
			if err != nil {
				t.Fatalf("second parse: %v", err)
			}
			if m1.String() != m2.String() {
				t.Errorf("round-trip mismatch:\nfirst:  %q\nsecond: %q", m1.String(), m2.String())
			}
		})
	}
}

func TestParseRejectsCRLF(t *testing.T) {
	msg := "dapp.academy wants you to sign in with your Solana account:\r\n"
	if _, err := siws.ParseMessage([]byte(msg)); err == nil {
		t.Error("expected error for CRLF input, got nil")
	}
}

func TestParseEmptyInput(t *testing.T) {
	if _, err := siws.ParseMessage([]byte{}); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParseMissingRequiredFields(t *testing.T) {
	base := "dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Nonce: Ab1Cd2Ef3G\n" +
		"Issued At: 2026-06-09T12:00:00.000Z\n"

	cases := []struct {
		name  string
		input string
	}{
		{"no_header", "DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\nURI: x\nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\n"},
		{"no_uri", "dapp.academy wants you to sign in with your Solana account:\nDFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\n"},
		{"bad_version", strings.Replace(base, "Version: 1", "Version: 2", 1)},
		{"short_nonce", strings.Replace(base, "Nonce: Ab1Cd2Ef3G", "Nonce: short", 1)},
		{"bad_issued_at", strings.Replace(base, "Issued At: 2026-06-09T12:00:00.000Z", "Issued At: not-a-date", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := siws.ParseMessage([]byte(tc.input))
			if err == nil {
				t.Error("want error, got nil")
				return
			}
			if !errors.Is(err, siws.ErrMalformed) {
				t.Errorf("want ErrMalformed, got %v", err)
			}
		})
	}
}

func TestParseHugeInput(t *testing.T) {
	// 1MB line must not panic and must return ErrMalformed.
	huge := strings.Repeat("x", 1<<20)
	_, err := siws.ParseMessage([]byte(huge))
	if err == nil {
		t.Error("want error for 1MB line, got nil")
	}
}

func TestParseOutOfOrderField(t *testing.T) {
	// Nonce before URI is out of order.
	msg := "dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
		"Nonce: Ab1Cd2Ef3G\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Issued At: 2026-06-09T12:00:00.000Z\n"
	_, err := siws.ParseMessage([]byte(msg))
	if !errors.Is(err, siws.ErrMalformed) {
		t.Errorf("want ErrMalformed for out-of-order field, got %v", err)
	}
}

// ---- verify tests using real Ed25519 test vectors ----

func TestVerifyValidVectors(t *testing.T) {
	tv := loadVectors(t)
	rt := refTime(t, tv)

	for _, vec := range tv.Valid {
		t.Run(vec.Name, func(t *testing.T) {
			msgBytes := decodeB64(t, vec.MessageBase64)
			sig := decodeB64(t, vec.SignatureBase64)

			// Parse to learn the domain and nonce the message carries.
			m, err := siws.ParseMessage(msgBytes)
			if err != nil {
				t.Fatalf("ParseMessage: %v", err)
			}

			opts := siws.VerifyOpts{
				ExpectedDomain: m.Domain,
				ExpectedNonce:  m.Nonce,
				Now:            func() time.Time { return rt },
			}
			if _, err := siws.VerifyRaw(msgBytes, sig, opts); err != nil {
				t.Errorf("VerifyRaw: unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyInvalidVectors(t *testing.T) {
	tv := loadVectors(t)
	rt := refTime(t, tv)

	errorMap := map[string]error{
		"ErrMalformed":      siws.ErrMalformed,
		"ErrBadSignature":   siws.ErrBadSignature,
		"ErrExpired":        siws.ErrExpired,
		"ErrNotYetValid":    siws.ErrNotYetValid,
		"ErrDomainMismatch": siws.ErrDomainMismatch,
		"ErrNonceMismatch":  siws.ErrNonceMismatch,
	}

	for _, vec := range tv.Invalid {
		t.Run(vec.Name, func(t *testing.T) {
			want, ok := errorMap[vec.ExpectedError]
			if !ok {
				t.Fatalf("unknown expectedError %q", vec.ExpectedError)
			}

			msgBytes := decodeB64(t, vec.MessageBase64)
			sig := decodeB64(t, vec.SignatureBase64)

			// For domain_mismatch_check, opts use the wrong domain intentionally.
			expectedDomain := "dapp.academy"
			if vec.Name == "domain_mismatch_check" {
				expectedDomain = "evil.example"
			}

			// Parse to extract nonce; for malformed cases parse may fail.
			expectedNonce := "placeholder00000"
			if m, err := siws.ParseMessage(msgBytes); err == nil {
				expectedNonce = m.Nonce
				if expectedDomain == "dapp.academy" {
					expectedDomain = m.Domain
				}
			}

			opts := siws.VerifyOpts{
				ExpectedDomain: expectedDomain,
				ExpectedNonce:  expectedNonce,
				Now:            func() time.Time { return rt },
			}

			_, err := siws.VerifyRaw(msgBytes, sig, opts)
			if err == nil {
				t.Fatalf("want error %v, got nil", want)
			}
			if !errors.Is(err, want) {
				t.Errorf("want errors.Is(%v), got %v", want, err)
			}
		})
	}
}

// ---- negative crypto tests ----

func TestVerifyBadSignatureLengths(t *testing.T) {
	msg := []byte("dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Nonce: Ab1Cd2Ef3G\n" +
		"Issued At: 2026-06-09T12:00:00.000Z\n")

	opts := siws.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  "Ab1Cd2Ef3G",
		Now:            func() time.Time { return time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC) },
	}

	for _, size := range []int{0, 31, 63, 65} {
		sig := make([]byte, size)
		_, err := siws.VerifyRaw(msg, sig, opts)
		if !errors.Is(err, siws.ErrBadSignature) {
			t.Errorf("sig len %d: want ErrBadSignature, got %v", size, err)
		}
	}
}

func TestVerifyZeroPubKey(t *testing.T) {
	// Construct a message whose address is a base58-encoded 32-zero-byte key.
	zeroPub := siws.EncodeBase58(make([]byte, 32))
	msg := []byte("dapp.academy wants you to sign in with your Solana account:\n" +
		zeroPub + "\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Nonce: Ab1Cd2Ef3G\n" +
		"Issued At: 2026-06-09T12:00:00.000Z\n")

	sig := make([]byte, 64)
	opts := siws.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  "Ab1Cd2Ef3G",
		Now:            func() time.Time { return time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC) },
	}
	_, err := siws.VerifyRaw(msg, sig, opts)
	if !errors.Is(err, siws.ErrBadSignature) {
		t.Errorf("zero pubkey: want ErrBadSignature, got %v", err)
	}
}

// ---- Message.Verify (re-serialization path) ----

// TestMessageVerifyPreCryptoChecks exercises Message.Verify's check order
// (domain → not-before → expiry → nonce) without reaching the crypto step.
// Message.Verify re-serializes via String(); the happy-path crypto test would
// require signing String() bytes which is outside this package's scope.
func TestMessageVerifyPreCryptoChecks(t *testing.T) {
	exp := time.Date(2026, 6, 9, 11, 0, 0, 0, time.UTC) // already expired
	m := &siws.Message{
		Domain:         "dapp.academy",
		Address:        "DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA",
		URI:            "https://dapp.academy/login",
		Version:        "1",
		ChainID:        "mainnet",
		Nonce:          "Ab1Cd2Ef3G",
		IssuedAt:       time.Date(2026, 6, 9, 10, 0, 0, 0, time.UTC),
		ExpirationTime: &exp,
	}
	rt := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	sig := make([]byte, 64) // zero sig; never reaches crypto on pre-crypto failures

	cases := []struct {
		name    string
		opts    siws.VerifyOpts
		wantErr error
	}{
		{
			name:    "domain_mismatch",
			opts:    siws.VerifyOpts{ExpectedDomain: "evil.example", ExpectedNonce: "Ab1Cd2Ef3G", Now: func() time.Time { return rt }},
			wantErr: siws.ErrDomainMismatch,
		},
		{
			name:    "expired",
			opts:    siws.VerifyOpts{ExpectedDomain: "dapp.academy", ExpectedNonce: "Ab1Cd2Ef3G", Now: func() time.Time { return rt }},
			wantErr: siws.ErrExpired,
		},
		{
			name:    "nonce_mismatch",
			opts:    siws.VerifyOpts{ExpectedDomain: "dapp.academy", ExpectedNonce: "WrongNonce1", Now: func() time.Time { return exp.Add(-time.Hour) }},
			wantErr: siws.ErrNonceMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := m.Verify(sig, tc.opts)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// ---- String() optional-field serialization ----

func TestStringOptionalFields(t *testing.T) {
	exp := time.Date(2026, 6, 9, 13, 0, 0, 0, time.UTC)
	nb := time.Date(2026, 6, 9, 11, 0, 0, 0, time.UTC)
	m := &siws.Message{
		Domain:         "example.com",
		Address:        "DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA",
		Statement:      "I agree to the terms.",
		URI:            "https://example.com/login",
		Version:        "1",
		ChainID:        "mainnet",
		Nonce:          "TestNonce1A",
		IssuedAt:       time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC),
		ExpirationTime: &exp,
		NotBefore:      &nb,
		RequestID:      "req-abc-123",
		Resources:      []string{"https://example.com/r1", "https://example.com/r2"},
	}
	s := m.String()

	for _, want := range []string{
		"Expiration Time: 2026-06-09T13:00:00.000Z",
		"Not Before: 2026-06-09T11:00:00.000Z",
		"Request ID: req-abc-123",
		"Resources:\n- https://example.com/r1\n- https://example.com/r2",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("String() missing %q", want)
		}
	}

	// Round-trip.
	m2, err := siws.ParseMessage([]byte(s))
	if err != nil {
		t.Fatalf("ParseMessage round-trip: %v", err)
	}
	if m2.RequestID != m.RequestID {
		t.Errorf("RequestID: got %q want %q", m2.RequestID, m.RequestID)
	}
	if len(m2.Resources) != 2 {
		t.Errorf("Resources len: got %d want 2", len(m2.Resources))
	}
}

// ---- parse edge cases for optional fields ----

func TestParseDuplicateOptionalFields(t *testing.T) {
	base := "dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Nonce: Ab1Cd2Ef3G\n" +
		"Issued At: 2026-06-09T12:00:00.000Z\n"

	cases := []struct {
		name  string
		extra string
	}{
		{"dup_expiry", "Expiration Time: 2026-06-09T13:00:00.000Z\nExpiration Time: 2026-06-09T14:00:00.000Z\n"},
		{"dup_not_before", "Not Before: 2026-06-09T11:00:00.000Z\nNot Before: 2026-06-09T10:00:00.000Z\n"},
		{"dup_request_id", "Request ID: r1\nRequest ID: r2\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := siws.ParseMessage([]byte(base + tc.extra))
			if !errors.Is(err, siws.ErrMalformed) {
				t.Errorf("want ErrMalformed, got %v", err)
			}
		})
	}
}

func TestParseInvalidResourceLine(t *testing.T) {
	msg := "dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Nonce: Ab1Cd2Ef3G\n" +
		"Issued At: 2026-06-09T12:00:00.000Z\n" +
		"Resources:\nhttps://no-dash-prefix.com\n"
	_, err := siws.ParseMessage([]byte(msg))
	if !errors.Is(err, siws.ErrMalformed) {
		t.Errorf("want ErrMalformed for resource without '- ', got %v", err)
	}
}

func TestParseNonceWithSpecialChar(t *testing.T) {
	// Nonce with a non-alphanumeric char must fail validNonce.
	msg := "dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Nonce: Ab1!Cd2Ef\n" +
		"Issued At: 2026-06-09T12:00:00.000Z\n"
	_, err := siws.ParseMessage([]byte(msg))
	if !errors.Is(err, siws.ErrMalformed) {
		t.Errorf("want ErrMalformed for nonce with '!', got %v", err)
	}
}

func TestParseTruncatedBeforeURI(t *testing.T) {
	// Message truncated right after Issued At — expectField for URI is called
	// on an exhausted line slice, hitting the pos >= len(lines) branch.
	msg := "dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n"
	_, err := siws.ParseMessage([]byte(msg))
	if !errors.Is(err, siws.ErrMalformed) {
		t.Errorf("want ErrMalformed for truncated input, got %v", err)
	}
}

func TestParseTimestampRFC3339NoMillis(t *testing.T) {
	// Issued At without milliseconds — exercises the RFC3339 fallback layout.
	msg := "dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Nonce: Ab1Cd2Ef3G\n" +
		"Issued At: 2026-06-09T12:00:00Z\n"
	m, err := siws.ParseMessage([]byte(msg))
	if err != nil {
		t.Fatalf("want success for RFC3339 timestamp, got %v", err)
	}
	if m.IssuedAt.IsZero() {
		t.Error("IssuedAt is zero")
	}
}

func TestVerifyShortPubkeyDecode(t *testing.T) {
	// Construct a message whose address base58-decodes to fewer than 32 bytes
	// to hit the len(pubKeyBytes) != 32 branch in checkSig.
	// "2" encodes to a single 0x01 byte in base58 (just one byte after decode).
	// We need something that DecodeBase58 succeeds on but is not 32 bytes.
	// EncodeBase58 of a 16-byte key will decode back to 16 bytes.
	shortKey := siws.EncodeBase58(make([]byte, 16))
	msg := []byte("dapp.academy wants you to sign in with your Solana account:\n" +
		shortKey + "\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Nonce: Ab1Cd2Ef3G\n" +
		"Issued At: 2026-06-09T12:00:00.000Z\n")

	// ParseMessage validates address length, so we need to bypass it.
	// Directly construct a Message and call Verify.
	m := &siws.Message{
		Domain:   "dapp.academy",
		Address:  shortKey,
		URI:      "https://dapp.academy/login",
		Version:  "1",
		ChainID:  "mainnet",
		Nonce:    "Ab1Cd2Ef3G",
		IssuedAt: time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC),
	}
	sig := make([]byte, 64)
	opts := siws.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  "Ab1Cd2Ef3G",
		Now:            func() time.Time { return time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC) },
	}
	// Silence the unused msg variable lint.
	_ = msg
	err := m.Verify(sig, opts)
	if !errors.Is(err, siws.ErrBadSignature) {
		t.Errorf("want ErrBadSignature for short pubkey, got %v", err)
	}
}

func TestParseMissingFieldMidway(t *testing.T) {
	// Valid through Chain ID but missing Nonce — expectField called when pos==len(lines).
	msg := "dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet"
	_, err := siws.ParseMessage([]byte(msg))
	if !errors.Is(err, siws.ErrMalformed) {
		t.Errorf("want ErrMalformed for missing Nonce, got %v", err)
	}
}

func TestParseExpirationTimeRFC3339(t *testing.T) {
	// Expiration Time without milliseconds exercises the RFC3339 fallback in parseTimestamp.
	msg := "dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Nonce: Ab1Cd2Ef3G\n" +
		"Issued At: 2026-06-09T12:00:00Z\n" +
		"Expiration Time: 2026-06-09T13:00:00Z\n"
	m, err := siws.ParseMessage([]byte(msg))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if m.ExpirationTime == nil {
		t.Error("ExpirationTime is nil")
	}
}

func TestParseNotBeforeRFC3339Nano(t *testing.T) {
	// Not Before with RFC3339Nano exercises that layout in parseTimestamp.
	msg := "dapp.academy wants you to sign in with your Solana account:\n" +
		"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
		"URI: https://dapp.academy/login\n" +
		"Version: 1\n" +
		"Chain ID: mainnet\n" +
		"Nonce: Ab1Cd2Ef3G\n" +
		"Issued At: 2026-06-09T12:00:00Z\n" +
		"Not Before: 2026-06-09T11:00:00.123456789Z\n"
	m, err := siws.ParseMessage([]byte(msg))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if m.NotBefore == nil {
		t.Error("NotBefore is nil")
	}
}

func TestParseSpecificMalformedCases(t *testing.T) {
	const addr = "DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA"
	cases := []struct {
		name  string
		input string
	}{
		{
			// Domain extracted as "" from the header line.
			"empty_domain",
			" wants you to sign in with your Solana account:\n" + addr + "\n\nURI: x\nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\n",
		},
		{
			// Address contains '0' which is not in the base58 alphabet.
			"invalid_base58_address",
			"dapp.academy wants you to sign in with your Solana account:\n0InvalidAddress\n\nURI: x\nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\n",
		},
		{
			// "11" decodes to [0,0] — 2 bytes, not 32.
			"address_wrong_length",
			"dapp.academy wants you to sign in with your Solana account:\n11\n\nURI: x\nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\n",
		},
		{
			// No blank line after address.
			"no_blank_after_address",
			"dapp.academy wants you to sign in with your Solana account:\n" + addr + "\nURI: x\nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\n",
		},
		{
			// Statement with no blank line following it.
			"statement_no_trailing_blank",
			"dapp.academy wants you to sign in with your Solana account:\n" + addr + "\n\nSign in\nURI: x\nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\n",
		},
		{
			// URI field is present but value is empty.
			"empty_uri",
			"dapp.academy wants you to sign in with your Solana account:\n" + addr + "\n\nURI: \nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\n",
		},
		{
			// Chain ID value is empty → would default to mainnet, but let's test the field error when Version is missing.
			"missing_version",
			"dapp.academy wants you to sign in with your Solana account:\n" + addr + "\n\nURI: https://dapp.academy\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\n",
		},
		{
			// Invalid Expiration Time timestamp hits parseTimestamp error return.
			"invalid_expiry_timestamp",
			"dapp.academy wants you to sign in with your Solana account:\n" + addr + "\n\nURI: https://dapp.academy\nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\nExpiration Time: not-a-date\n",
		},
		{
			// Invalid Not Before timestamp.
			"invalid_not_before_timestamp",
			"dapp.academy wants you to sign in with your Solana account:\n" + addr + "\n\nURI: https://dapp.academy\nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\nNot Before: not-a-date\n",
		},
		{
			// Unknown field in optional section.
			"unknown_optional_field",
			"dapp.academy wants you to sign in with your Solana account:\n" + addr + "\n\nURI: https://dapp.academy\nVersion: 1\nChain ID: mainnet\nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\nUnknown: value\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := siws.ParseMessage([]byte(tc.input))
			if !errors.Is(err, siws.ErrMalformed) {
				t.Errorf("want ErrMalformed, got %v", err)
			}
		})
	}
}

func TestParseEmptyChainIDDefaultsToMainnet(t *testing.T) {
	const addr = "DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA"
	msg := "dapp.academy wants you to sign in with your Solana account:\n" + addr + "\n\n" +
		"URI: https://dapp.academy\nVersion: 1\nChain ID: \nNonce: Ab1Cd2Ef3G\nIssued At: 2026-06-09T12:00:00.000Z\n"
	m, err := siws.ParseMessage([]byte(msg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.ChainID != "mainnet" {
		t.Errorf("want ChainID=mainnet, got %q", m.ChainID)
	}
}

func TestMessageVerifyReachesCheckSig(t *testing.T) {
	// Passes all pre-crypto checks; checkSig fails because sig is all zeros.
	m := &siws.Message{
		Domain:   "dapp.academy",
		Address:  "DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA",
		URI:      "https://dapp.academy/login",
		Version:  "1",
		ChainID:  "mainnet",
		Nonce:    "Ab1Cd2Ef3G",
		IssuedAt: time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC),
	}
	sig := make([]byte, 64) // zero sig — passes length check, fails crypto
	opts := siws.VerifyOpts{
		ExpectedDomain: "dapp.academy",
		ExpectedNonce:  "Ab1Cd2Ef3G",
		Now:            func() time.Time { return time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC) },
	}
	err := m.Verify(sig, opts)
	if !errors.Is(err, siws.ErrBadSignature) {
		t.Errorf("want ErrBadSignature, got %v", err)
	}
}

func TestVerifyNilNowUsesSystemClock(t *testing.T) {
	// Passing Now=nil should not panic and should use real time.
	// Use a message with no expiry so real time doesn't matter.
	tv := loadVectors(t)
	vec := tv.Valid[1] // no_statement_no_expiry — no expiry field
	msgBytes := decodeB64(t, vec.MessageBase64)
	sig := decodeB64(t, vec.SignatureBase64)

	m, err := siws.ParseMessage(msgBytes)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	opts := siws.VerifyOpts{
		ExpectedDomain: m.Domain,
		ExpectedNonce:  m.Nonce,
		Now:            nil, // triggers real time.Now()
	}
	// We only care that it doesn't panic; it may return ErrBadSignature if the
	// real clock makes the IssuedAt check fail (no expiry, so it shouldn't), or
	// succeed. Either is acceptable as long as no panic occurs.
	siws.VerifyRaw(msgBytes, sig, opts) //nolint:errcheck
}

// ---- helpers ----

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return b
}
