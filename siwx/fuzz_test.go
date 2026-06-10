package siwx_test

import (
	"testing"

	"github.com/anitconsultant/siwx-go/siwx"
)

// FuzzParseCAIP10 verifies that the parser never panics and that successful
// parses produce a round-trippable CAIP-10 string.
func FuzzParseCAIP10(f *testing.F) {
	seeds := []string{
		"solana:mainnet:DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA",
		"eip155:1:0xAb5801a7D398351b8bE11C439e05C5b3259aeC9B",
		"eip155:137:0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
		"",
		"solana",
		"solana:mainnet",
		"::::",
		"ab:x:y",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		c, err := siwx.ParseCAIP10(s)
		if err != nil {
			return // invalid input — expected
		}
		// Successful parse must round-trip.
		if c.String() != s {
			t.Errorf("round-trip failed: ParseCAIP10(%q).String() = %q", s, c.String())
		}
		// Re-parsing must succeed.
		c2, err2 := siwx.ParseCAIP10(c.String())
		if err2 != nil {
			t.Errorf("re-parse failed: ParseCAIP10(%q) returned %v", c.String(), err2)
			return
		}
		if c2.ChainID.Namespace != c.ChainID.Namespace ||
			c2.ChainID.Reference != c.ChainID.Reference ||
			c2.Address != c.Address {
			t.Errorf("re-parse field mismatch: %+v != %+v", c2, c)
		}
	})
}
