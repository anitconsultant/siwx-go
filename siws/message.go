package siws

import (
	"strings"
	"time"
)

// timestampFormat is the canonical serialization format for all timestamps.
// Parse accepts any valid RFC 3339; String() always emits this format.
const timestampFormat = "2006-01-02T15:04:05.000Z"

// Message represents a parsed Sign-In With Solana message.
type Message struct {
	// Domain is the RFC 4501 authority requesting sign-in (e.g. "dapp.academy").
	Domain string

	// Address is the signer's Solana public key in base58 encoding.
	Address string

	// Statement is an optional human-readable assertion. Empty means absent.
	Statement string

	// URI identifies the resource the sign-in is requested for.
	URI string

	// Version must be "1".
	Version string

	// ChainID is the Solana cluster; defaults to "mainnet" when absent in input.
	ChainID string

	// Nonce is the server-issued anti-replay token (8+ alphanumeric chars).
	Nonce string

	// IssuedAt is when the message was created.
	IssuedAt time.Time

	// ExpirationTime, if non-nil, is when the message expires.
	ExpirationTime *time.Time

	// NotBefore, if non-nil, is the earliest time the message is valid.
	NotBefore *time.Time

	// RequestID is an optional application-specific identifier.
	RequestID string

	// Resources is an optional list of resources the sign-in grants access to.
	Resources []string
}

// String serializes m to the canonical SIWS ABNF text that was (or will be)
// signed. The output is deterministic: optional fields are omitted when zero,
// timestamps are always emitted in timestampFormat.
//
// Use VerifyRaw when you need to verify bytes that were externally signed,
// because the signed bytes must match exactly what the wallet produced.
func (m *Message) String() string {
	var b strings.Builder

	b.WriteString(m.Domain)
	b.WriteString(" wants you to sign in with your Solana account:\n")
	b.WriteString(m.Address)
	b.WriteByte('\n')

	if m.Statement != "" {
		b.WriteByte('\n')
		b.WriteString(m.Statement)
		b.WriteByte('\n')
	}

	b.WriteByte('\n')
	b.WriteString("URI: ")
	b.WriteString(m.URI)
	b.WriteByte('\n')

	b.WriteString("Version: ")
	b.WriteString(m.Version)
	b.WriteByte('\n')

	b.WriteString("Chain ID: ")
	b.WriteString(m.ChainID)
	b.WriteByte('\n')

	b.WriteString("Nonce: ")
	b.WriteString(m.Nonce)
	b.WriteByte('\n')

	b.WriteString("Issued At: ")
	b.WriteString(m.IssuedAt.UTC().Format(timestampFormat))
	b.WriteByte('\n')

	if m.ExpirationTime != nil {
		b.WriteString("Expiration Time: ")
		b.WriteString(m.ExpirationTime.UTC().Format(timestampFormat))
		b.WriteByte('\n')
	}

	if m.NotBefore != nil {
		b.WriteString("Not Before: ")
		b.WriteString(m.NotBefore.UTC().Format(timestampFormat))
		b.WriteByte('\n')
	}

	if m.RequestID != "" {
		b.WriteString("Request ID: ")
		b.WriteString(m.RequestID)
		b.WriteByte('\n')
	}

	if len(m.Resources) > 0 {
		b.WriteString("Resources:\n")
		for _, r := range m.Resources {
			b.WriteString("- ")
			b.WriteString(r)
			b.WriteByte('\n')
		}
	}

	return b.String()
}
