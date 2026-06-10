package main

import (
	"log/slog"
	"net/http"
	"os"
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

	domain := env("SIWX_DOMAIN", "localhost:8081")
	addr := env("SIWX_ADDR", ":8081")
	jwksURL := env("SIWX_JWKS_URL", "http://localhost:8081/.well-known/jwks.json")

	issuer, err := newIssuer()
	if err != nil {
		log.Error("failed to generate issuer key", "err", err)
		os.Exit(1)
	}

	registry := siwx.NewRegistry()
	registry.Register(solanadapter.New())
	registry.Register(evmadapter.New())

	recorder := newRecorder(log)

	hub := &Hub{
		domain:   domain,
		registry: registry,
		nonces:   newNonceStore(time.Now),
		ids:      newIdentityStore(),
		issuer:   issuer,
		recorder: recorder,
	}

	r := gin.New()
	r.Use(gin.Recovery())

	// Auth endpoints.
	r.GET("/auth/nonce", hub.getNonce)
	r.POST("/auth/verify", hub.postVerify)
	r.POST("/auth/link", hubmw.JWTAuth(jwksURL, issuerURL, defaultAud), hub.postLink)

	// Well-known + observability.
	r.GET("/.well-known/jwks.json", hub.getJWKS)
	r.GET("/metrics", hub.getMetrics)
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	// Demo protected endpoint.
	r.GET("/me", hubmw.JWTAuth(jwksURL, issuerURL, defaultAud), hubmw.GetMe)

	// Static web files served explicitly to avoid Gin v1.9.1 wildcard conflicts.
	webDir := "./examples/web"
	r.GET("/", func(c *gin.Context) { c.File(webDir + "/index.html") })
	r.GET("/app.js", func(c *gin.Context) { c.File(webDir + "/app.js") })
	r.GET("/siwx-progress.js", func(c *gin.Context) { c.File(webDir + "/siwx-progress.js") })

	log.Info("siwx-go hub starting", "addr", addr, "domain", domain)
	if err := r.Run(addr); err != nil {
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
