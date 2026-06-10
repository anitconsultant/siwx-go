// Package middleware provides JWKS-validating JWT middleware for Gin.
package middleware

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
)

// claimsKey is the Gin context key for injected JWT claims.
const claimsKey = "jwtClaims"

// HubClaims holds the verified JWT claims injected into the Gin context.
type HubClaims struct {
	Subject    string   `json:"sub"`
	IdentityID string   `json:"identityId,omitempty"`
	Wallets    []string `json:"wallets"`
}

// jwksCache caches public keys fetched from a JWKS endpoint.
type jwksCache struct {
	mu      sync.RWMutex
	url     string
	keys    map[string]*rsa.PublicKey // kid → key
}

func newJWKSCache(url string) *jwksCache { return &jwksCache{url: url, keys: make(map[string]*rsa.PublicKey)} }

func (c *jwksCache) get(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	k, ok := c.keys[kid]
	c.mu.RUnlock()
	if ok {
		return k, nil
	}
	return c.refresh(kid)
}

func (c *jwksCache) refresh(kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check under write lock.
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}

	resp, err := http.Get(c.url) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	for _, k := range doc.Keys {
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		c.keys[k.Kid] = &rsa.PublicKey{N: n, E: e}
	}

	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("middleware: unknown kid: " + kid)
}

// JWTAuth returns a Gin middleware that validates RS256 JWTs using the JWKS
// at jwksURL. expectedIssuer and expectedAud are validated against the token
// claims (iss and aud). On success, claims are injected under "jwtClaims".
// On failure, aborts with 401.
func JWTAuth(jwksURL, expectedIssuer, expectedAud string) gin.HandlerFunc {
	cache := newJWKSCache(jwksURL)
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		var hubClaims struct {
			jwt.RegisteredClaims
			Wallets []string `json:"wallets"`
		}

		token, err := jwt.ParseWithClaims(tokenStr, &hubClaims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, errors.New("middleware: unexpected signing method")
			}
			kid, _ := t.Header["kid"].(string)
			return cache.get(kid)
		},
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithIssuer(expectedIssuer),
			jwt.WithAudience(expectedAud),
		)

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set("identityID", hubClaims.Subject)
		c.Set("wallets", hubClaims.Wallets)
		c.Set(claimsKey, HubClaims{
			Subject: hubClaims.Subject,
			Wallets: hubClaims.Wallets,
		})
		c.Next()
	}
}

// GetMe is a demo protected handler that returns the injected claims.
func GetMe(c *gin.Context) {
	claims, exists := c.Get(claimsKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no claims"})
		return
	}
	c.JSON(http.StatusOK, claims)
}
