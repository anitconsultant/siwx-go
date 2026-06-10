// Package testvectors provides a typed loader for vectors.json and helpers
// for reconstructing Ed25519 keys so other packages can sign fresh messages.
package testvectors

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/anitconsultant/siwx-go/siws"
	"github.com/anitconsultant/siwx-go/siwx"
)

// Key holds a test Ed25519 key pair.
type Key struct {
	ID              string
	PublicKeyBase58 string
	PrivateSeed     []byte // 32-byte raw seed
}

// PrivateKey reconstructs the ed25519.PrivateKey from the seed.
func (k Key) PrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(k.PrivateSeed)
}

// Sign signs msg with this key and returns the raw 64-byte Ed25519 signature.
func (k Key) Sign(msg []byte) []byte {
	return ed25519.Sign(k.PrivateKey(), msg)
}

// Vector is a single test case from vectors.json.
type Vector struct {
	Name           string
	Key            string
	Message        []byte // decoded from messageBase64
	Signature      []byte // decoded from signatureBase64
	ExpectedError  error  // nil for valid vectors; one of the siwx/siws sentinels
}

// Corpus holds the loaded test data.
type Corpus struct {
	ReferenceTime time.Time
	Keys          map[string]Key
	Valid         []Vector
	Invalid       []Vector
}

// Load reads vectors.json relative to the caller's source file location.
// Pass the path from the module root to the desired vectors.json.
func Load(path string) (*Corpus, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("testvectors: %w", err)
	}
	return parse(raw)
}

// MustLoad calls Load with the module-root-relative path and panics on error.
// path is resolved relative to the module root via runtime.Caller.
func MustLoad() *Corpus {
	_, file, _, _ := runtime.Caller(0)
	// file is .../internal/testvectors/load.go; module root is two dirs up.
	root := filepath.Join(filepath.Dir(file), "..", "..")
	c, err := Load(filepath.Join(root, "internal", "testvectors", "vectors.json"))
	if err != nil {
		panic(err)
	}
	return c
}

// FrozenClock returns a Clock whose Now() is fixed at the corpus referenceTime.
func (c *Corpus) FrozenClock() siwx.Clock {
	return frozenClock{c.ReferenceTime}
}

// Signer returns the Key with the given ID for signing fresh messages.
func (c *Corpus) Signer(keyID string) Key {
	k, ok := c.Keys[keyID]
	if !ok {
		panic(fmt.Sprintf("testvectors: key %q not found", keyID))
	}
	return k
}

// SiwsVerifyOpts builds siws.VerifyOpts from the vector's parsed message.
// domain and nonce are extracted from the already-parsed message.
func SiwsVerifyOpts(now func() time.Time, domain, nonce string) siws.VerifyOpts {
	return siws.VerifyOpts{
		ExpectedDomain: domain,
		ExpectedNonce:  nonce,
		Now:            now,
	}
}

// ---- internals ----

type frozenClock struct{ t time.Time }

func (f frozenClock) Now() time.Time { return f.t }

type rawFile struct {
	Description   string     `json:"description"`
	ReferenceTime string     `json:"referenceTime"`
	Keys          []rawKey   `json:"keys"`
	Valid         []rawEntry `json:"valid"`
	Invalid       []rawEntry `json:"invalid"`
}

type rawKey struct {
	ID              string `json:"id"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
	PrivateSeedB64  string `json:"privateSeedBase64"`
}

type rawEntry struct {
	Name           string `json:"name"`
	Key            string `json:"key"`
	MessageB64     string `json:"messageBase64"`
	SignatureB64   string `json:"signatureBase64"`
	ExpectedError  string `json:"expectedError"`
}

// sentinelMap maps expectedError strings → siws sentinels (for siws.VerifyRaw tests).
var sentinelMap = map[string]error{
	"ErrMalformed":      siws.ErrMalformed,
	"ErrBadSignature":   siws.ErrBadSignature,
	"ErrExpired":        siws.ErrExpired,
	"ErrNotYetValid":    siws.ErrNotYetValid,
	"ErrDomainMismatch": siws.ErrDomainMismatch,
	"ErrNonceMismatch":  siws.ErrNonceMismatch,
}

// SiwxSentinelFor returns the siwx equivalent of the siws sentinel stored in v.ExpectedError.
// Use this when testing via the siwx.VerifierRegistry, which maps siws→siwx before returning.
func SiwxSentinelFor(siwsSentinel error) error {
	switch siwsSentinel {
	case siws.ErrMalformed:
		return siwx.ErrMalformed
	case siws.ErrBadSignature:
		return siwx.ErrBadSignature
	case siws.ErrExpired:
		return siwx.ErrExpired
	case siws.ErrNotYetValid:
		return siwx.ErrNotYetValid
	case siws.ErrDomainMismatch:
		return siwx.ErrDomainMismatch
	case siws.ErrNonceMismatch:
		return siwx.ErrNonceMismatch
	}
	return siwsSentinel
}

func parse(raw []byte) (*Corpus, error) {
	var f rawFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("testvectors: parse: %w", err)
	}

	refTime, err := parseTime(f.ReferenceTime)
	if err != nil {
		return nil, fmt.Errorf("testvectors: referenceTime: %w", err)
	}

	keys := make(map[string]Key, len(f.Keys))
	for _, k := range f.Keys {
		seed, err := base64.StdEncoding.DecodeString(k.PrivateSeedB64)
		if err != nil {
			return nil, fmt.Errorf("testvectors: key %s seed: %w", k.ID, err)
		}
		keys[k.ID] = Key{ID: k.ID, PublicKeyBase58: k.PublicKeyBase58, PrivateSeed: seed}
	}

	toVector := func(e rawEntry, valid bool) (Vector, error) {
		msg, err := base64.StdEncoding.DecodeString(e.MessageB64)
		if err != nil {
			return Vector{}, fmt.Errorf("testvectors: %s message: %w", e.Name, err)
		}
		sig, err := base64.StdEncoding.DecodeString(e.SignatureB64)
		if err != nil {
			return Vector{}, fmt.Errorf("testvectors: %s signature: %w", e.Name, err)
		}
		var sentinel error
		if !valid {
			s, ok := sentinelMap[e.ExpectedError]
			if !ok {
				return Vector{}, fmt.Errorf("testvectors: unknown expectedError %q", e.ExpectedError)
			}
			sentinel = s
		}
		return Vector{Name: e.Name, Key: e.Key, Message: msg, Signature: sig, ExpectedError: sentinel}, nil
	}

	c := &Corpus{ReferenceTime: refTime, Keys: keys}
	for _, e := range f.Valid {
		v, err := toVector(e, true)
		if err != nil {
			return nil, err
		}
		c.Valid = append(c.Valid, v)
	}
	for _, e := range f.Invalid {
		v, err := toVector(e, false)
		if err != nil {
			return nil, err
		}
		c.Invalid = append(c.Invalid, v)
	}
	return c, nil
}

func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("unparseable timestamp: " + s)
}

// ExtractDomainNonce extracts domain and nonce from a raw SIWS message.
// Used by tests that need to build VerifyOpts from a message without re-parsing.
func ExtractDomainNonce(msg []byte) (domain, nonce string) {
	const suffix = " wants you to sign in with your Solana account:"
	for _, line := range strings.Split(string(msg), "\n") {
		if strings.HasSuffix(line, suffix) {
			domain = strings.TrimSuffix(line, suffix)
		}
		if strings.HasPrefix(line, "Nonce: ") {
			nonce = strings.TrimPrefix(line, "Nonce: ")
		}
	}
	return
}
