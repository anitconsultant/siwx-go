package siws

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// ParseMessage parses raw SIWS message bytes into a Message.
// The input must use LF line endings; CRLF is rejected as malformed.
// A single trailing newline on the last line is accepted.
//
// Field order is strict per the SIWS spec: any unknown or out-of-order line
// returns ErrMalformed. All errors wrap ErrMalformed and name the offending
// field without echoing its value (S4).
func ParseMessage(b []byte) (*Message, error) {
	if bytes.ContainsRune(b, '\r') {
		return nil, fmt.Errorf("parse: CRLF line endings not allowed: %w", ErrMalformed)
	}

	// Trim a single trailing newline if present; the serializer always adds one.
	b = bytes.TrimRight(b, "\n")

	lines := strings.Split(string(b), "\n")
	if len(lines) < 6 {
		return nil, fmt.Errorf("parse: too few lines: %w", ErrMalformed)
	}

	m := &Message{}
	pos := 0

	// Line 0: "<domain> wants you to sign in with your Solana account:"
	const headerSuffix = " wants you to sign in with your Solana account:"
	if !strings.HasSuffix(lines[pos], headerSuffix) {
		return nil, fmt.Errorf("parse: invalid header line: %w", ErrMalformed)
	}
	m.Domain = strings.TrimSuffix(lines[pos], headerSuffix)
	if m.Domain == "" {
		return nil, fmt.Errorf("parse: missing domain: %w", ErrMalformed)
	}
	pos++

	// Line 1: address (base58, must decode to exactly 32 bytes)
	addr := lines[pos]
	if addr == "" {
		return nil, fmt.Errorf("parse: missing address: %w", ErrMalformed)
	}
	addrBytes, err := DecodeBase58(addr)
	if err != nil {
		return nil, fmt.Errorf("parse: invalid address encoding: %w", ErrMalformed)
	}
	if len(addrBytes) != 32 {
		return nil, fmt.Errorf("parse: address must decode to 32 bytes: %w", ErrMalformed)
	}
	m.Address = addr
	pos++

	// Line 2: blank line (required)
	if lines[pos] != "" {
		return nil, fmt.Errorf("parse: expected blank line after address: %w", ErrMalformed)
	}
	pos++

	// Optional statement: a non-empty line that is not a field label.
	// When present it is followed by a blank line.
	// When absent, the next line is a field label or end-of-input.
	if pos < len(lines) && lines[pos] != "" && !isFieldPrefix(lines[pos]) {
		m.Statement = lines[pos]
		pos++
		if pos >= len(lines) || lines[pos] != "" {
			return nil, fmt.Errorf("parse: expected blank line after statement: %w", ErrMalformed)
		}
		pos++ // consume blank line after statement
	}
	// No statement: pos already points at the first field line.

	// Required fields in exact order: URI, Version, Chain ID, Nonce, Issued At.
	var parseErr error

	m.URI, parseErr = expectField(lines, &pos, "URI: ")
	if parseErr != nil {
		return nil, parseErr
	}
	if m.URI == "" {
		return nil, fmt.Errorf("parse: empty URI: %w", ErrMalformed)
	}

	m.Version, parseErr = expectField(lines, &pos, "Version: ")
	if parseErr != nil {
		return nil, parseErr
	}
	if m.Version != "1" {
		return nil, fmt.Errorf("parse: unsupported version: %w", ErrMalformed)
	}

	// Chain ID is OPTIONAL per the SIWS spec (SIP-12); absent means mainnet.
	if pos < len(lines) && strings.HasPrefix(lines[pos], "Chain ID: ") {
		m.ChainID = strings.TrimPrefix(lines[pos], "Chain ID: ")
		pos++
	}
	if m.ChainID == "" {
		m.ChainID = "mainnet"
	}

	m.Nonce, parseErr = expectField(lines, &pos, "Nonce: ")
	if parseErr != nil {
		return nil, parseErr
	}
	if !validNonce(m.Nonce) {
		return nil, fmt.Errorf("parse: invalid nonce: %w", ErrMalformed)
	}

	issuedAtStr, parseErr := expectField(lines, &pos, "Issued At: ")
	if parseErr != nil {
		return nil, parseErr
	}
	m.IssuedAt, err = time.Parse(time.RFC3339, issuedAtStr)
	if err != nil {
		// Try with milliseconds.
		m.IssuedAt, err = time.Parse("2006-01-02T15:04:05.000Z07:00", issuedAtStr)
		if err != nil {
			return nil, fmt.Errorf("parse: invalid Issued At: %w", ErrMalformed)
		}
	}

	// Optional fields in order: Expiration Time, Not Before, Request ID, Resources.
	for pos < len(lines) {
		line := lines[pos]
		switch {
		case strings.HasPrefix(line, "Expiration Time: "):
			if m.ExpirationTime != nil {
				return nil, fmt.Errorf("parse: duplicate Expiration Time: %w", ErrMalformed)
			}
			val := strings.TrimPrefix(line, "Expiration Time: ")
			t, terr := parseTimestamp(val)
			if terr != nil {
				return nil, fmt.Errorf("parse: invalid Expiration Time: %w", ErrMalformed)
			}
			m.ExpirationTime = &t
			pos++

		case strings.HasPrefix(line, "Not Before: "):
			if m.NotBefore != nil {
				return nil, fmt.Errorf("parse: duplicate Not Before: %w", ErrMalformed)
			}
			val := strings.TrimPrefix(line, "Not Before: ")
			t, terr := parseTimestamp(val)
			if terr != nil {
				return nil, fmt.Errorf("parse: invalid Not Before: %w", ErrMalformed)
			}
			m.NotBefore = &t
			pos++

		case strings.HasPrefix(line, "Request ID: "):
			if m.RequestID != "" {
				return nil, fmt.Errorf("parse: duplicate Request ID: %w", ErrMalformed)
			}
			m.RequestID = strings.TrimPrefix(line, "Request ID: ")
			pos++

		case line == "Resources:":
			pos++
			for pos < len(lines) {
				rline := lines[pos]
				if !strings.HasPrefix(rline, "- ") {
					// End of resources block; outer loop handles whatever follows.
					break
				}
				m.Resources = append(m.Resources, strings.TrimPrefix(rline, "- "))
				pos++
			}

		default:
			return nil, fmt.Errorf("parse: unexpected line: %w", ErrMalformed)
		}
	}

	return m, nil
}

// expectField reads the next line, asserts it has the given prefix, and
// returns the value after the prefix. Advances pos.
func expectField(lines []string, pos *int, prefix string) (string, error) {
	if *pos >= len(lines) {
		return "", fmt.Errorf("parse: missing field %q: %w", strings.TrimSuffix(prefix, ": "), ErrMalformed)
	}
	line := lines[*pos]
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("parse: expected field %q: %w", strings.TrimSuffix(prefix, ": "), ErrMalformed)
	}
	*pos++
	return strings.TrimPrefix(line, prefix), nil
}

// isFieldPrefix reports whether s starts with a known field label.
func isFieldPrefix(s string) bool {
	for _, p := range []string{
		"URI: ", "Version: ", "Chain ID: ", "Nonce: ", "Issued At: ",
		"Expiration Time: ", "Not Before: ", "Request ID: ", "Resources:",
	} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// validNonce reports whether s is 8+ ASCII alphanumeric characters [a-zA-Z0-9].
// Unicode letters and digits are explicitly rejected to match the CAIP-122 spec
// character set and avoid normalization ambiguity.
func validNonce(s string) bool {
	if len(s) < 8 {
		return false
	}
	for _, r := range s {
		if !('a' <= r && r <= 'z') && !('A' <= r && r <= 'Z') && !('0' <= r && r <= '9') {
			return false
		}
	}
	return true
}

// parseTimestamp accepts any valid RFC 3339 timestamp, including the
// milliseconds-with-Z variant used in vectors.json.
func parseTimestamp(s string) (time.Time, error) {
	for _, layout := range []string{
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05.999Z",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp")
}
