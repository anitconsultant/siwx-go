// NOT FOR PRODUCTION: this issuer uses an in-memory RSA key generated at
// startup and is intended solely for demo and test purposes.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"

	"github.com/anitconsultant/siwx-go/siwx"
	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	mockKid  = "mock-1"
	tokenTTL = time.Hour
)

// mockIssuer generates an RSA-2048 key at construction and mints RS256 JWTs.
// issuerURL and audience are injected from config (single source of truth).
type mockIssuer struct {
	key       *rsa.PrivateKey
	issuerURL string
	audience  string
}

// hubClaims extends the standard JWT claims with the wallets list.
type hubClaims struct {
	jwt.RegisteredClaims
	Wallets []string `json:"wallets"`
}

func newIssuer(issuerURL, audience string) (*mockIssuer, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &mockIssuer{key: k, issuerURL: issuerURL, audience: audience}, nil
}

func (m *mockIssuer) Issue(_ context.Context, identityID string, wallets []siwx.CAIP10) (string, error) {
	now := time.Now()
	ws := make([]string, len(wallets))
	for i, w := range wallets {
		ws[i] = w.String()
	}
	// sub is the stable identity anchor, not the wallet address.
	// Wallets (including the primary) are carried in the wallets claim.
	sub := identityID
	claims := hubClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    m.issuerURL,
			Audience:  jwt.ClaimStrings{m.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
		Wallets: ws,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = mockKid
	return token.SignedString(m.key)
}

// jwksDoc is the minimal JSON Web Key Set document shape.
type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"` // base64url-encoded modulus
	E   string `json:"e"` // base64url-encoded exponent
}

func (m *mockIssuer) JWKS(_ context.Context) ([]byte, error) {
	pub := &m.key.PublicKey
	doc := jwksDoc{Keys: []jwk{{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: mockKid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	return json.Marshal(doc)
}
