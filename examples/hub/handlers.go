package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/anitconsultant/siwx-go/siwx"
	"github.com/gin-gonic/gin"
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

	// Demo display config surfaced to the frontend via GET /config.
	statement     string // sign-in prompt statement
	solanaChain   string // Solana cluster, e.g. "mainnet"
	sessionTTLMin int    // sign-in message expiration window, in minutes
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
	nonce, err := h.nonces.Issue(ctx, nonceTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "nonce issue failed"})
		return
	}
	h.recorder.counters.incNonceIssued()
	// Bind the nonce to this client in an HttpOnly cookie so verify/link read
	// the expected nonce from a channel WE control, not the message body.
	setNonceCookie(c, nonce)
	c.JSON(http.StatusOK, gin.H{"nonce": nonce, "domain": h.domain})
}

// getConfig handles GET /config — demo display config the frontend uses to
// build the sign-in message. Single source of truth: these come from the
// hub's environment-driven Config, never hard-coded in the browser.
func (h *Hub) getConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"statement":         h.statement,
		"solanaChain":       h.solanaChain,
		"sessionTtlMinutes": h.sessionTTLMin,
	})
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

	// Anti-replay: the expected nonce is the value WE issued to this client,
	// carried in an HttpOnly cookie by GET /auth/nonce — never re-derived from the
	// attacker-controlled message. This makes the library's ExpectedNonce check
	// load-bearing (a forged/replayed message carrying a different nonce fails the
	// in-library comparison) rather than a comparison of the message against itself.
	expectedNonce, _ := c.Cookie(nonceCookie)
	if expectedNonce == "" {
		writeProblem(c, siwx.ErrNonceMismatch, reqID)
		return
	}
	clearNonceCookie(c)

	// Burn first: reject if unknown/expired/reused.
	if err := h.nonces.Burn(ctx, expectedNonce); err != nil {
		writeProblem(c, siwx.ErrNonceMismatch, reqID)
		return
	}
	h.recorder.counters.incNonceBurned()

	attemptID := newAttemptID()
	opts := siwx.VerifyOpts{
		ExpectedDomain: h.domain,
		ExpectedNonce:  expectedNonce,
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

	expectedNonce, _ := c.Cookie(nonceCookie)
	if expectedNonce == "" {
		writeProblem(c, siwx.ErrNonceMismatch, reqID)
		return
	}
	clearNonceCookie(c)
	if err := h.nonces.Burn(ctx, expectedNonce); err != nil {
		writeProblem(c, siwx.ErrNonceMismatch, reqID)
		return
	}

	opts := siwx.VerifyOpts{
		ExpectedDomain: h.domain,
		ExpectedNonce:  expectedNonce,
		Observer:       h.recorder,
		Clock:          siwx.RealClock{},
	}
	id, verifyErr := h.registry.Verify(ctx, chainID, msg, sig, opts)
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

// nonceCookie carries the server-issued nonce back to verify/link so the
// expected nonce comes from a channel the server controls, not the message body.
const nonceCookie = "siwx_nonce"

// nonceTTL is how long an issued nonce (and its cookie) remains valid.
const nonceTTL = 10 * time.Minute

// setNonceCookie stores the issued nonce in an HttpOnly, SameSite=Lax cookie
// scoped to this client. Secure is false for the http://localhost demo; behind
// TLS in production this must be set true.
func setNonceCookie(c *gin.Context, nonce string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(nonceCookie, nonce, int(nonceTTL.Seconds()), "/", "", false, true)
}

// clearNonceCookie deletes the nonce cookie after a verify/link attempt so each
// issued nonce is presented at most once per client.
func clearNonceCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(nonceCookie, "", -1, "/", "", false, true)
}

// newAttemptID generates a random 16-byte hex string.
func newAttemptID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("hub: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
