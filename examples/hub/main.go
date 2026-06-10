package main

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	hubmw "github.com/anitconsultant/siwx-go/examples/middleware"
	"github.com/anitconsultant/siwx-go/siwx"
	evmadapter "github.com/anitconsultant/siwx-go/siwx/evm"
	solanadapter "github.com/anitconsultant/siwx-go/siwx/solana"
	"github.com/gin-gonic/gin"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)

	cfg := loadConfig()

	issuer, err := newIssuer(cfg.IssuerURL, cfg.Audience)
	if err != nil {
		log.Error("failed to generate issuer key", "err", err)
		os.Exit(1)
	}

	registry := siwx.NewRegistry()
	registry.Register(solanadapter.New())
	registry.Register(evmadapter.New())

	recorder := newRecorder(log)

	hub := &Hub{
		domain:        cfg.Domain,
		registry:      registry,
		nonces:        newNonceStore(time.Now),
		ids:           newIdentityStore(),
		issuer:        issuer,
		recorder:      recorder,
		statement:     cfg.Statement,
		solanaChain:   cfg.SolanaChain,
		sessionTTLMin: cfg.SessionTTLMin,
	}

	r := gin.New()
	r.Use(gin.Recovery())

	// Auth endpoints.
	r.GET("/auth/nonce", hub.getNonce)
	r.POST("/auth/verify", hub.postVerify)
	r.POST("/auth/link", hubmw.JWTAuth(cfg.JWKSURL, cfg.IssuerURL, cfg.Audience), hub.postLink)

	// Demo display config for the frontend.
	r.GET("/config", hub.getConfig)

	// Well-known + observability.
	r.GET("/.well-known/jwks.json", hub.getJWKS)
	r.GET("/metrics", hub.getMetrics)
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	// Demo protected endpoint.
	r.GET("/me", hubmw.JWTAuth(cfg.JWKSURL, cfg.IssuerURL, cfg.Audience), hubmw.GetMe)

	// Static web files served explicitly to avoid Gin v1.9.1 wildcard conflicts.
	webDir := "./examples/web"
	r.GET("/", func(c *gin.Context) { c.File(webDir + "/index.html") })
	r.GET("/app.js", func(c *gin.Context) { c.File(webDir + "/app.js") })
	r.GET("/siwx-progress.js", func(c *gin.Context) { c.File(webDir + "/siwx-progress.js") })

	log.Info("siwx-go hub starting", "addr", cfg.Addr, "domain", cfg.Domain)
	if err := r.Run(cfg.Addr); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// buildDomain combines host and port into an RFC 3986 authority.
// If host already contains a colon (has port or is IPv6), it is returned as-is.
func buildDomain(host, port string) string {
	if strings.Contains(host, ":") || port == "" {
		return host
	}
	return host + ":" + port
}
