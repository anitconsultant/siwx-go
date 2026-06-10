package siwx

import (
	"fmt"
	"regexp"
	"strings"
)

// Validation regexps per CAIP-2 / CAIP-10 specs.
var (
	reNamespace = regexp.MustCompile(`^[-a-z0-9]{3,8}$`)
	reReference = regexp.MustCompile(`^[-_a-zA-Z0-9]{1,32}$`)
	reAddress   = regexp.MustCompile(`^[-.%a-zA-Z0-9]{1,128}$`)
)

// CAIP2 is a chain identifier: namespace + ":" + reference, e.g. "solana:mainnet".
type CAIP2 struct {
	Namespace string // [-a-z0-9]{3,8}
	Reference string // [-_a-zA-Z0-9]{1,32}
}

// String returns the canonical "namespace:reference" form.
func (c CAIP2) String() string { return c.Namespace + ":" + c.Reference }

// ParseCAIP2 parses and validates a CAIP-2 chain ID string.
func ParseCAIP2(s string) (CAIP2, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return CAIP2{}, fmt.Errorf("caip2: missing colon separator: %w", ErrMalformed)
	}
	ns, ref := parts[0], parts[1]
	if !reNamespace.MatchString(ns) {
		return CAIP2{}, fmt.Errorf("caip2: invalid namespace: %w", ErrMalformed)
	}
	if !reReference.MatchString(ref) {
		return CAIP2{}, fmt.Errorf("caip2: invalid reference: %w", ErrMalformed)
	}
	return CAIP2{Namespace: ns, Reference: ref}, nil
}

// CAIP10 is an account identifier: CAIP2 + ":" + address.
type CAIP10 struct {
	ChainID CAIP2
	Address string
}

// String returns the canonical "namespace:reference:address" form.
func (c CAIP10) String() string { return c.ChainID.String() + ":" + c.Address }

// ParseCAIP10 parses and validates a CAIP-10 account ID string.
// For eip155 addresses, casing is preserved as-given (EIP-55 checksummed).
func ParseCAIP10(s string) (CAIP10, error) {
	// Split into exactly three parts: namespace, reference, address.
	// Address may itself contain colons in some future namespaces, so split at most 3.
	idx1 := strings.Index(s, ":")
	if idx1 < 0 {
		return CAIP10{}, fmt.Errorf("caip10: missing first colon: %w", ErrMalformed)
	}
	rest := s[idx1+1:]
	idx2 := strings.Index(rest, ":")
	if idx2 < 0 {
		return CAIP10{}, fmt.Errorf("caip10: missing second colon: %w", ErrMalformed)
	}
	ns := s[:idx1]
	ref := rest[:idx2]
	addr := rest[idx2+1:]

	if !reNamespace.MatchString(ns) {
		return CAIP10{}, fmt.Errorf("caip10: invalid namespace: %w", ErrMalformed)
	}
	if !reReference.MatchString(ref) {
		return CAIP10{}, fmt.Errorf("caip10: invalid reference: %w", ErrMalformed)
	}
	if !reAddress.MatchString(addr) {
		return CAIP10{}, fmt.Errorf("caip10: invalid address: %w", ErrMalformed)
	}
	return CAIP10{ChainID: CAIP2{Namespace: ns, Reference: ref}, Address: addr}, nil
}
