package siws_test

import (
	"testing"

	"github.com/anitconsultant/siwx-go/siws"
)

// FuzzParseMessage verifies that the parser never panics and that successful
// parses produce a round-trippable message.
func FuzzParseMessage(f *testing.F) {
	// Seed from known-good message bytes (trimmed to keep binary size small).
	seeds := []string{
		"dapp.academy wants you to sign in with your Solana account:\n" +
			"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n" +
			"Sign in\n\n" +
			"URI: https://dapp.academy/login\nVersion: 1\nChain ID: mainnet\n" +
			"Nonce: 32891756dCb1\nIssued At: 2026-06-09T11:59:00.000Z\n" +
			"Expiration Time: 2026-06-09T12:09:00.000Z",

		"nexus.dapp.academy wants you to sign in with your Solana account:\n" +
			"FdSXoQtDKu3xNDbfXsRmhKfiaB6taaSmsVf2MtWeoKHT\n\n" +
			"URI: https://nexus.dapp.academy\nVersion: 1\nChain ID: mainnet\n" +
			"Nonce: aF9x2Lq8Mn4p\nIssued At: 2026-06-09T11:59:30.000Z",

		"",
		"not a siws message",
		"x wants you to sign in with your Solana account:\n\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := siws.ParseMessage(b)
		if err != nil {
			return // invalid input — expected
		}
		// Successful parse must round-trip: re-parsing String() must succeed.
		serialized := m.String()
		m2, err2 := siws.ParseMessage([]byte(serialized))
		if err2 != nil {
			t.Errorf("round-trip failed: ParseMessage(m.String()) returned %v\noriginal: %q\nserialized: %q",
				err2, b, serialized)
			return
		}
		// Core fields must be preserved.
		if m2.Domain != m.Domain {
			t.Errorf("round-trip domain mismatch: %q != %q", m2.Domain, m.Domain)
		}
		if m2.Address != m.Address {
			t.Errorf("round-trip address mismatch: %q != %q", m2.Address, m.Address)
		}
		if m2.Nonce != m.Nonce {
			t.Errorf("round-trip nonce mismatch: %q != %q", m2.Nonce, m.Nonce)
		}
	})
}

// FuzzVerifyRaw verifies that the verifier never panics regardless of inputs.
func FuzzVerifyRaw(f *testing.F) {
	f.Add(
		[]byte("dapp.academy wants you to sign in with your Solana account:\n"+
			"DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA\n\n"+
			"URI: https://dapp.academy\nVersion: 1\nChain ID: mainnet\n"+
			"Nonce: abcd1234XY\nIssued At: 2026-06-09T12:00:00.000Z"),
		make([]byte, 64),
	)
	f.Add([]byte(""), []byte{})
	f.Add([]byte("garbage"), make([]byte, 64))
	f.Add([]byte("x"), make([]byte, 32))

	f.Fuzz(func(t *testing.T, msg []byte, sig []byte) {
		opts := siws.VerifyOpts{
			ExpectedDomain: "dapp.academy",
			ExpectedNonce:  "abcd1234XY",
		}
		// Must never panic; errors are expected and acceptable.
		siws.VerifyRaw(msg, sig, opts) //nolint:errcheck
	})
}
