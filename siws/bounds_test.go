package siws_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/anitconsultant/siwx-go/siws"
)

// Guards against the M2 DoS finding: base58 → base256 decode is O(n²), so both
// the decoder and the parser must reject oversized input up front rather than
// burning CPU on it.

func TestDecodeBase58RejectsOverlongInput(t *testing.T) {
	// 200 chars of valid alphabet — well past the 128 cap. A 32-byte key is
	// ≤ 44 chars, so nothing this long is legitimate.
	overlong := strings.Repeat("1", 200)
	if _, err := siws.DecodeBase58(overlong); !errors.Is(err, siws.ErrMalformed) {
		t.Fatalf("want ErrMalformed for overlong base58, got %v", err)
	}

	// A normal 44-char key length still decodes (sanity: the cap is not too tight).
	if _, err := siws.DecodeBase58("DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA"); err != nil {
		t.Fatalf("valid 44-char base58 should decode, got %v", err)
	}
}

func TestParseMessageRejectsOversizedInput(t *testing.T) {
	// A multi-KB message past the 8 KiB cap must be rejected immediately,
	// before the address line reaches the O(n²) base58 decode.
	huge := make([]byte, 9<<10)
	for i := range huge {
		huge[i] = 'A'
	}
	if _, err := siws.ParseMessage(huge); !errors.Is(err, siws.ErrMalformed) {
		t.Fatalf("want ErrMalformed for oversized message, got %v", err)
	}
}

// TestParseMessageRejectsOutOfOrderOptionalFields guards the L2 strictness fix:
// optional trailer fields must appear in SIWS ABNF order.
func TestParseMessageRejectsOutOfOrderOptionalFields(t *testing.T) {
	const addr = "DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA"
	base := "dapp.academy wants you to sign in with your Solana account:\n" + addr +
		"\n\nURI: https://dapp.academy\nVersion: 1\nChain ID: mainnet\n" +
		"Nonce: 32891756dCb1\nIssued At: 2026-06-09T11:59:00.000Z\n"

	// In-order (Expiration Time then Not Before) must parse.
	inOrder := base + "Expiration Time: 2026-06-09T12:09:00.000Z\nNot Before: 2026-06-09T11:00:00.000Z"
	if _, err := siws.ParseMessage([]byte(inOrder)); err != nil {
		t.Fatalf("in-order optional fields should parse, got %v", err)
	}

	// Reversed (Not Before before Expiration Time) must be rejected.
	reversed := base + "Not Before: 2026-06-09T11:00:00.000Z\nExpiration Time: 2026-06-09T12:09:00.000Z"
	if _, err := siws.ParseMessage([]byte(reversed)); !errors.Is(err, siws.ErrMalformed) {
		t.Fatalf("want ErrMalformed for out-of-order fields, got %v", err)
	}
}
