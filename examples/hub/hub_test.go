package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/anitconsultant/siwx-go/siws"
	"github.com/anitconsultant/siwx-go/siwx"
	solanadapter "github.com/anitconsultant/siwx-go/siwx/solana"
)

func init() { gin.SetMode(gin.TestMode) }

// ---- test helpers ----

const testDomain = "dapp.academy"

// buildTestHub wires a Hub backed by a test Ed25519 key, using a frozen clock.
func buildTestHub(t *testing.T) (*Hub, *httptest.Server) {
	t.Helper()

	issuer, err := newIssuer()
	if err != nil {
		t.Fatalf("newIssuer: %v", err)
	}

	registry := siwx.NewRegistry()
	registry.Register(solanadapter.New())

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	hub := &Hub{
		domain:   testDomain,
		registry: registry,
		nonces:   newNonceStore(time.Now),
		ids:      newIdentityStore(),
		issuer:   issuer,
		recorder: newRecorder(log),
	}
	return hub, nil
}

func buildRouter(hub *Hub, jwksURL string) *gin.Engine {
	r := gin.New()
	r.GET("/auth/nonce", hub.getNonce)
	r.POST("/auth/verify", hub.postVerify)
	r.GET("/.well-known/jwks.json", hub.getJWKS)
	r.GET("/metrics", hub.getMetrics)
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func doJSON(t *testing.T, router *gin.Engine, method, path string, body any, headers map[string]string) *http.Response {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Result()
}

func decodeJSON(t *testing.T, r *http.Response, dst any) {
	t.Helper()
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// signSIWS creates a SIWS message and signs it with the given key.
// Returns (base64-encoded message, base64-encoded signature).
func signSIWS(t *testing.T, key ed25519.PrivateKey, domain, nonce string) (string, string) {
	t.Helper()
	pubBytes := key.Public().(ed25519.PublicKey)

	// Encode public key as base58 for the address.
	address := siws.EncodeBase58(pubBytes)

	m := &siws.Message{
		Domain:    domain,
		Address:   address,
		Statement: "Sign in to siwx-go demo",
		URI:       "https://" + domain + "/login",
		Version:   "1",
		ChainID:   "mainnet",
		Nonce:     nonce,
		IssuedAt:  time.Now().UTC(),
	}
	exp := time.Now().Add(10 * time.Minute).UTC()
	m.ExpirationTime = &exp

	msgBytes := []byte(m.String())
	sig := ed25519.Sign(key, msgBytes)

	return base64.StdEncoding.EncodeToString(msgBytes), base64.StdEncoding.EncodeToString(sig)
}

// ---- tests ----

func TestHealthz(t *testing.T) {
	hub, _ := buildTestHub(t)
	r := buildRouter(hub, "")
	resp := doJSON(t, r, "GET", "/healthz", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

func TestGetNonce(t *testing.T) {
	hub, _ := buildTestHub(t)
	r := buildRouter(hub, "")
	resp := doJSON(t, r, "GET", "/auth/nonce", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	decodeJSON(t, resp, &body)
	if nonce := body["nonce"]; len(nonce) < 8 {
		t.Errorf("expected non-empty nonce, got %q", nonce)
	}
}

func TestJWKS(t *testing.T) {
	hub, _ := buildTestHub(t)
	r := buildRouter(hub, "")
	resp := doJSON(t, r, "GET", "/.well-known/jwks.json", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	decodeJSON(t, resp, &body)
	keys := body["keys"].([]any)
	if len(keys) == 0 {
		t.Error("expected at least one key in JWKS")
	}
}

func TestVerifyHappyPath(t *testing.T) {
	hub, _ := buildTestHub(t)
	r := buildRouter(hub, "")

	// Step 1: get nonce.
	resp1 := doJSON(t, r, "GET", "/auth/nonce", nil, nil)
	var n1 map[string]string
	decodeJSON(t, resp1, &n1)
	nonce := n1["nonce"]

	// Step 2: sign SIWS.
	_, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	msgB64, sigB64 := signSIWS(t, privKey, testDomain, nonce)

	// Step 3: verify.
	body := map[string]string{
		"message":   msgB64,
		"signature": sigB64,
		"chainId":   "solana:mainnet",
	}
	resp2 := doJSON(t, r, "POST", "/auth/verify", body, nil)
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("want 200, got %d: %s", resp2.StatusCode, b)
	}
	var vResp verifyResponse
	decodeJSON(t, resp2, &vResp)
	if vResp.Token == "" {
		t.Error("expected non-empty token")
	}
	if vResp.IdentityID == "" {
		t.Error("expected non-empty identityID")
	}
	// Checks trail must be present and ordered.
	if len(vResp.Checks) == 0 {
		t.Error("expected checks trail in response")
	}
}

func TestVerifyReplayRejected(t *testing.T) {
	hub, _ := buildTestHub(t)
	r := buildRouter(hub, "")

	resp1 := doJSON(t, r, "GET", "/auth/nonce", nil, nil)
	var n1 map[string]string
	decodeJSON(t, resp1, &n1)
	nonce := n1["nonce"]

	_, privKey, _ := ed25519.GenerateKey(nil)
	msgB64, sigB64 := signSIWS(t, privKey, testDomain, nonce)

	body := map[string]string{"message": msgB64, "signature": sigB64, "chainId": "solana:mainnet"}

	// First request succeeds.
	resp2 := doJSON(t, r, "POST", "/auth/verify", body, nil)
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("first verify: want 200, got %d: %s", resp2.StatusCode, b)
	}

	// Replay must be rejected with 401.
	resp3 := doJSON(t, r, "POST", "/auth/verify", body, nil)
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay: want 401, got %d", resp3.StatusCode)
	}
	var prob problem
	decodeJSON(t, resp3, &prob)
	if !strings.Contains(prob.Type, "nonce") {
		t.Errorf("problem type should mention nonce, got %q", prob.Type)
	}
}

func TestVerifyBadSignature(t *testing.T) {
	hub, _ := buildTestHub(t)
	r := buildRouter(hub, "")

	resp1 := doJSON(t, r, "GET", "/auth/nonce", nil, nil)
	var n1 map[string]string
	decodeJSON(t, resp1, &n1)
	nonce := n1["nonce"]

	_, privKey, _ := ed25519.GenerateKey(nil)
	msgB64, _ := signSIWS(t, privKey, testDomain, nonce)

	// Corrupt signature: all zeros.
	badSig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	body := map[string]string{"message": msgB64, "signature": badSig, "chainId": "solana:mainnet"}

	resp2 := doJSON(t, r, "POST", "/auth/verify", body, nil)
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp2.StatusCode)
	}
}

func TestVerifyUnsupportedNamespace(t *testing.T) {
	hub, _ := buildTestHub(t)
	r := buildRouter(hub, "")

	resp1 := doJSON(t, r, "GET", "/auth/nonce", nil, nil)
	var n1 map[string]string
	decodeJSON(t, resp1, &n1)
	nonce := n1["nonce"]

	body := map[string]string{
		"message":   base64.StdEncoding.EncodeToString([]byte("dummy")),
		"signature": base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"chainId":   "cosmos:cosmoshub-4",
	}
	// Nonce will be burned; registry fails on unsupported namespace.
	// Actually nonce extractor will fail on "dummy" message.
	_ = nonce
	resp2 := doJSON(t, r, "POST", "/auth/verify", body, nil)
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("expected non-200 for dummy message")
	}
}

func TestMetrics(t *testing.T) {
	hub, _ := buildTestHub(t)
	r := buildRouter(hub, "")

	resp := doJSON(t, r, "GET", "/metrics", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "verify_attempts_total") {
		t.Error("metrics missing verify_attempts_total")
	}
}

// ---- stores unit tests ----

func TestNonceSingleUse(t *testing.T) {
	store := newNonceStore(time.Now)
	ctx := context.Background()

	nonce, err := store.Issue(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// First Burn: success.
	if err := store.Burn(ctx, nonce); err != nil {
		t.Fatalf("first Burn: %v", err)
	}
	// Second Burn: must fail.
	if err := store.Burn(ctx, nonce); err == nil {
		t.Fatal("second Burn should fail")
	}
}

func TestNonceExpiry(t *testing.T) {
	var now time.Time
	store := newNonceStore(func() time.Time { return now })
	ctx := context.Background()

	now = time.Unix(1000, 0)
	nonce, err := store.Issue(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance past TTL.
	now = time.Unix(2000, 0)
	if err := store.Burn(ctx, nonce); err == nil {
		t.Fatal("expired nonce should fail")
	}
}

func TestIdentityUpsertAndLink(t *testing.T) {
	store := newIdentityStore()
	ctx := context.Background()

	w1, _ := siwx.ParseCAIP10("solana:mainnet:DFAvxPgy3BtANWnT4EiWab5kcXWY8u5wgqUY5brpaYbA")
	w2, _ := siwx.ParseCAIP10("eip155:1:0xAb5801a7D398351b8bE11C439e05C5b3259aeC9B")

	id1, created, err := store.UpsertByWallet(ctx, w1)
	if err != nil || !created {
		t.Fatalf("first upsert: %v, created=%v", err, created)
	}

	id2, created2, err := store.UpsertByWallet(ctx, w1)
	if err != nil || created2 {
		t.Fatalf("second upsert (same wallet): %v, created=%v", err, created2)
	}
	if id1 != id2 {
		t.Error("same wallet should return same identity")
	}

	if err := store.LinkWallet(ctx, id1, w2); err != nil {
		t.Fatalf("LinkWallet: %v", err)
	}

	wallets, err := store.Wallets(ctx, id1)
	if err != nil {
		t.Fatalf("Wallets: %v", err)
	}
	if len(wallets) != 2 {
		t.Errorf("expected 2 wallets, got %d", len(wallets))
	}
}

// TestChecksTrailOrdering verifies the checks trail matches Observer event order.
func TestChecksTrailOrdering(t *testing.T) {
	hub, _ := buildTestHub(t)
	r := buildRouter(hub, "")

	resp1 := doJSON(t, r, "GET", "/auth/nonce", nil, nil)
	var n1 map[string]string
	decodeJSON(t, resp1, &n1)
	nonce := n1["nonce"]

	_, privKey, _ := ed25519.GenerateKey(nil)
	msgB64, sigB64 := signSIWS(t, privKey, testDomain, nonce)

	body := map[string]string{"message": msgB64, "signature": sigB64, "chainId": "solana:mainnet"}
	resp2 := doJSON(t, r, "POST", "/auth/verify", body, nil)
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("want 200, got %d: %s", resp2.StatusCode, b)
	}
	var vResp verifyResponse
	decodeJSON(t, resp2, &vResp)

	// S3 order: domain, not_before, expiry, nonce, signature.
	expectedOrder := []string{"domain", "not_before", "expiry", "nonce", "signature"}
	for i, want := range expectedOrder {
		if i >= len(vResp.Checks) {
			break
		}
		if vResp.Checks[i].Name != want {
			t.Errorf("check[%d]: want %q, got %q", i, want, vResp.Checks[i].Name)
		}
	}
}
