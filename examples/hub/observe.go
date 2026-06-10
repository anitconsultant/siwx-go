package main

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/anitconsultant/siwx-go/siwx"
)

// CheckInfo is a single verification check result suitable for API responses.
type CheckInfo struct {
	Name string  `json:"name"`
	OK   bool    `json:"ok"`
	Ms   float64 `json:"ms"`
}

// counters holds Prometheus-style atomic counters.
type counters struct {
	attemptsTotal atomic.Int64
	failuresTotal sync.Map // reason string → *atomic.Int64
	checksTotal   sync.Map // check name → *atomic.Int64
	noncesIssued  atomic.Int64
	nonceBurned   atomic.Int64
	tokensIssued  atomic.Int64
}

func (c *counters) incAttempts()        { c.attemptsTotal.Add(1) }
func (c *counters) incNonceIssued()     { c.noncesIssued.Add(1) }
func (c *counters) incNonceBurned()     { c.nonceBurned.Add(1) }
func (c *counters) incTokensIssued()    { c.tokensIssued.Add(1) }

func (c *counters) incFailure(reason string) {
	v, _ := c.failuresTotal.LoadOrStore(reason, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

func (c *counters) incCheckFailed(check string) {
	v, _ := c.checksTotal.LoadOrStore(check, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

func (c *counters) render() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# TYPE verify_attempts_total counter\nverify_attempts_total %d\n", c.attemptsTotal.Load())
	c.failuresTotal.Range(func(k, v any) bool {
		fmt.Fprintf(&sb, "verify_failures_total{reason=%q} %d\n", k, v.(*atomic.Int64).Load())
		return true
	})
	c.checksTotal.Range(func(k, v any) bool {
		fmt.Fprintf(&sb, "checks_failed_total{check=%q} %d\n", k, v.(*atomic.Int64).Load())
		return true
	})
	fmt.Fprintf(&sb, "# TYPE nonces_issued_total counter\nnonces_issued_total %d\n", c.noncesIssued.Load())
	fmt.Fprintf(&sb, "# TYPE nonces_burned_total counter\nnonces_burned_total %d\n", c.nonceBurned.Load())
	fmt.Fprintf(&sb, "# TYPE tokens_issued_total counter\ntokens_issued_total %d\n", c.tokensIssued.Load())
	return sb.String()
}

// Recorder implements siwx.Observer with slog logging and metrics counters.
// S5: never stores message text, signature bytes, or key material.
type Recorder struct {
	log      *slog.Logger
	counters *counters

	mu     sync.Mutex
	checks map[string][]CheckInfo // attemptID → accumulated checks (bounded to 1024)
}

func newRecorder(log *slog.Logger) *Recorder {
	return &Recorder{
		log:      log,
		counters: &counters{},
		checks:   make(map[string][]CheckInfo),
	}
}

// DrainChecks returns and removes the buffered checks for the given attemptID.
// Called by the verify handler immediately after registry.Verify returns.
func (r *Recorder) DrainChecks(attemptID string) []CheckInfo {
	r.mu.Lock()
	cs := r.checks[attemptID]
	delete(r.checks, attemptID)
	r.mu.Unlock()
	return cs
}

func (r *Recorder) OnVerifyAttempt(e siwx.VerifyAttempt) {
	r.counters.incAttempts()
	r.log.Info("verify_attempt",
		"attemptID", e.AttemptID,
		"namespace", e.Namespace,
		"domain", e.Domain,
	)
}

func (r *Recorder) OnParseResult(e siwx.ParseResult) {
	level := slog.LevelInfo
	if !e.OK {
		level = slog.LevelWarn
	}
	r.log.Log(nil, level, "parse_result", //nolint:staticcheck
		"attemptID", e.AttemptID,
		"ok", e.OK,
		"msgBytes", e.MsgBytes,
	)
}

func (r *Recorder) OnCheckResult(e siwx.CheckResult) {
	if !e.OK {
		r.counters.incCheckFailed(string(e.Check))
	}
	r.log.Info("check_result",
		"attemptID", e.AttemptID,
		"check", string(e.Check),
		"ok", e.OK,
		"ms", float64(e.Duration.Microseconds())/1000.0,
	)
	r.mu.Lock()
	if len(r.checks) < 1024 {
		r.checks[e.AttemptID] = append(r.checks[e.AttemptID], CheckInfo{
			Name: string(e.Check),
			OK:   e.OK,
			Ms:   float64(e.Duration.Microseconds()) / 1000.0,
		})
	}
	r.mu.Unlock()
}

func (r *Recorder) OnVerifyResult(e siwx.VerifyResult) {
	if !e.OK && e.ErrorIs != nil {
		r.counters.incFailure(e.ErrorIs.Error())
	}
	level := slog.LevelInfo
	if !e.OK {
		level = slog.LevelWarn
	}
	r.log.Log(nil, level, "verify_result", //nolint:staticcheck
		"attemptID", e.AttemptID,
		"ok", e.OK,
		"namespace", e.Namespace,
		"durationMs", float64(e.Duration.Microseconds())/1000.0,
	)
}
