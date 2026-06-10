package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/anitconsultant/siwx-go/siwx"
)

// verifyRequest is the POST /auth/verify body.
type verifyRequest struct {
	Message   string `json:"message"`   // base64-encoded raw signed message bytes
	Signature string `json:"signature"` // base64-encoded raw signature bytes
	ChainID   string `json:"chainId"`   // e.g. "solana:mainnet" or "eip155:1"
}

// verifyResponse is the POST /auth/verify success body.
type verifyResponse struct {
	Token      string      `json:"token"`
	IdentityID string      `json:"identityId"`
	Checks     []CheckInfo `json:"checks"`
}

// Hub holds all server-level dependencies.
type Hub struct {
	domain   string // expected domain for all verify calls
	registry siwx.VerifierRegistry
	nonces   *memNonceStore
	ids      *memIdentityStore
	issuer   *mockIssuer
	recorder *Recorder
}

func requestID(c *gin.Context) string {
	if id := c.GetHeader("X-Request-ID"); id != "" {
		return id
	}
	return ""
}

// getNonce handles GET /auth/nonce
func (h *Hub) getNonce(c *gin.Context) {
	ctx := c.Request.Context()
	nonce, err := h.nonces.Issue(ctx, 10*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "nonce issue failed"})
		return
	}
	h.recorder.counters.incNonceIssued()
	c.JSON(http.StatusOK, gin.H{"nonce": nonce, "domain": h.domain})
}

// postVerify handles POST /auth/verify
func (h *Hub) postVerify(c *gin.Context) {
	ctx := c.Request.Context()
	reqID := requestID(c)

	var req verifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeProblem(c, siwx.ErrMalformed, reqID)
		return
	}

	msg, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		writeProblem(c, siwx.ErrMalformed, reqID)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeProblem(c, siwx.ErrMalformed, reqID)
		return
	}

	chainID, err := siwx.ParseCAIP2(req.ChainID)
	if err != nil {
		writeProblem(c, siwx.ErrMalformed, reqID)
		return
	}

	// Extract nonce from the raw message for NonceStore.Burn.
	nonce := extractNonce(msg)
	if nonce == "" {
		writeProblem(c, siwx.ErrMalformed, reqID)
		return
	}

	// Burn nonce first: reject if unknown/expired/reused.
	if err := h.nonces.Burn(ctx, nonce); err != nil {
		writeProblem(c, siwx.ErrNonceMismatch, reqID)
		return
	}
	h.recorder.counters.incNonceBurned()

	attemptID := newAttemptID()
	opts := siwx.VerifyOpts{
		ExpectedDomain: h.domain,
		ExpectedNonce:  nonce,
		Observer:       h.recorder,
		Clock:          siwx.RealClock{},
		AttemptID:      attemptID,
	}

	id, verifyErr := h.registry.Verify(ctx, chainID, msg, sig, opts)
	checks := h.recorder.DrainChecks(attemptID)

	if verifyErr != nil {
		writeProblem(c, verifyErr, reqID)
		return
	}

	// Upsert identity and collect linked wallets for token.
	identityID, _, err := h.ids.UpsertByWallet(ctx, id.Account)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "identity upsert failed"})
		return
	}
	wallets, err := h.ids.Wallets(ctx, identityID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "wallets lookup failed"})
		return
	}

	token, err := h.issuer.Issue(ctx, identityID, wallets)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token issue failed"})
		return
	}
	h.recorder.counters.incTokensIssued()

	c.JSON(http.StatusOK, verifyResponse{
		Token:      token,
		IdentityID: identityID,
		Checks:     checks,
	})
}

// postLink handles POST /auth/link (requires Bearer token validated by middleware)
func (h *Hub) postLink(c *gin.Context) {
	ctx := c.Request.Context()
	reqID := requestID(c)

	identityID, exists := c.Get("identityID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing identity"})
		return
	}

	var req verifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeProblem(c, siwx.ErrMalformed, reqID)
		return
	}
	msg, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		writeProblem(c, siwx.ErrMalformed, reqID)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeProblem(c, siwx.ErrMalformed, reqID)
		return
	}
	chainID, err := siwx.ParseCAIP2(req.ChainID)
	if err != nil {
		writeProblem(c, siwx.ErrMalformed, reqID)
		return
	}

	nonce := extractNonce(msg)
	if nonce == "" {
		writeProblem(c, siwx.ErrMalformed, reqID)
		return
	}
	if err := h.nonces.Burn(ctx, nonce); err != nil {
		writeProblem(c, siwx.ErrNonceMismatch, reqID)
		return
	}

	opts := siwx.VerifyOpts{
		ExpectedDomain: h.domain,
		ExpectedNonce:  nonce,
		Observer:       h.recorder,
		Clock:          siwx.RealClock{},
	}
	id, verifyErr := h.registry.Verify(context.Background(), chainID, msg, sig, opts)
	if verifyErr != nil {
		writeProblem(c, verifyErr, reqID)
		return
	}

	if err := h.ids.LinkWallet(ctx, identityID.(string), id.Account); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "link failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"linked": id.Account.String()})
}

// getJWKS handles GET /.well-known/jwks.json
func (h *Hub) getJWKS(c *gin.Context) {
	doc, err := h.issuer.JWKS(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "jwks error"})
		return
	}
	c.Data(http.StatusOK, "application/json", doc)
}

// getMetrics handles GET /metrics
func (h *Hub) getMetrics(c *gin.Context) {
	c.String(http.StatusOK, h.recorder.counters.render())
}

// extractNonce parses the Nonce field from a raw SIWS/SIWE message.
func extractNonce(msg []byte) string {
	for _, line := range strings.Split(string(msg), "\n") {
		if strings.HasPrefix(line, "Nonce: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Nonce: "))
		}
	}
	return ""
}

// newAttemptID generates a random 16-byte hex string.
func newAttemptID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("hub: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
