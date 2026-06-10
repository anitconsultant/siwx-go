package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Config holds all runtime-configurable hub settings, sourced from the
// environment (optionally seeded from a .env file in the working directory).
// Single source of truth: no hub setting is hard-coded at a call site; every
// value flows from here so it can be changed without touching code.
type Config struct {
	Domain        string // SIWX_DOMAIN + SIWX_PORT -> authority, e.g. "localhost:8081"
	Addr          string // SIWX_ADDR, e.g. ":8081"
	JWKSURL       string // SIWX_JWKS_URL
	IssuerURL     string // SIWX_ISSUER_URL (JWT "iss")
	Audience      string // SIWX_AUDIENCE (JWT "aud")
	Statement     string // SIWX_STATEMENT (shown in the wallet sign-in prompt)
	SolanaChain   string // SIWX_SOLANA_CHAIN (e.g. "mainnet", "devnet")
	SessionTTLMin int    // SIWX_SESSION_TTL_MIN (sign-in message expiration window)
}

// loadConfig reads a .env file (if present) then resolves every setting from
// the environment, applying documented defaults. Real environment variables
// always win over .env values.
func loadConfig() Config {
	loadDotEnv(".env")
	port := env("SIWX_PORT", "8081")
	return Config{
		Domain:        buildDomain(env("SIWX_DOMAIN", "localhost"), port),
		Addr:          env("SIWX_ADDR", ":"+port),
		JWKSURL:       env("SIWX_JWKS_URL", "http://localhost:"+port+"/.well-known/jwks.json"),
		IssuerURL:     env("SIWX_ISSUER_URL", "https://accounts.example.local"),
		Audience:      env("SIWX_AUDIENCE", "siwx-go-demo"),
		Statement:     env("SIWX_STATEMENT", "Sign in to siwx-go demo"),
		SolanaChain:   env("SIWX_SOLANA_CHAIN", "mainnet"),
		SessionTTLMin: envInt("SIWX_SESSION_TTL_MIN", 10),
	}
}

// envInt reads an integer environment variable, returning fallback when unset
// or unparseable.
func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// loadDotEnv reads KEY=VALUE lines from path and sets them in the process
// environment, but only when the variable is not already set (real env wins).
// A missing file is not an error. Blank lines and lines starting with '#' are
// skipped; surrounding quotes on values are stripped. This is a deliberately
// minimal loader so the demo stays dependency-free.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // no .env file is fine
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
}
