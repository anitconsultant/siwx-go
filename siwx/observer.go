package siwx

import "time"

// CheckName identifies a verification step for Observer events.
type CheckName string

const (
	CheckDomain    CheckName = "domain"
	CheckNotBefore CheckName = "not_before"
	CheckExpiry    CheckName = "expiry"
	CheckNonce     CheckName = "nonce"
	CheckSignature CheckName = "signature"
)

// VerifyAttempt is emitted once per verification call before any checks run.
type VerifyAttempt struct {
	AttemptID string
	Namespace string
	Domain    string
	Account   string // CAIP-10 string; empty until parse succeeds
}

// ParseResult is emitted after the message is parsed (or fails to parse).
type ParseResult struct {
	AttemptID string
	OK        bool
	ErrorIs   error // ErrMalformed or nil
	MsgBytes  int
}

// CheckResult is emitted after each individual verification check.
type CheckResult struct {
	AttemptID string
	Check     CheckName
	OK        bool
	Duration  time.Duration
}

// VerifyResult is emitted once per verification call after all checks complete.
type VerifyResult struct {
	AttemptID string
	OK        bool
	ErrorIs   error // terminal sentinel or nil
	Namespace string
	Duration  time.Duration
}

// Observer receives verification lifecycle events.
// Implementations must be safe for concurrent use and must not block.
type Observer interface {
	OnVerifyAttempt(VerifyAttempt)
	OnParseResult(ParseResult)
	OnCheckResult(CheckResult)
	OnVerifyResult(VerifyResult)
}

// NopObserver discards all events.
type NopObserver struct{}

func (NopObserver) OnVerifyAttempt(VerifyAttempt) {}
func (NopObserver) OnParseResult(ParseResult)     {}
func (NopObserver) OnCheckResult(CheckResult)     {}
func (NopObserver) OnVerifyResult(VerifyResult)   {}

// MultiObserver fans out events to multiple observers in order.
// If an observer panics, the panic is recovered and the remaining observers
// still receive the event (S5: observability must not bring down the auth path).
func MultiObserver(obs ...Observer) Observer { return multiObserver(obs) }

type multiObserver []Observer

func (m multiObserver) OnVerifyAttempt(e VerifyAttempt) {
	for _, o := range m {
		safeCall(func() { o.OnVerifyAttempt(e) })
	}
}

func (m multiObserver) OnParseResult(e ParseResult) {
	for _, o := range m {
		safeCall(func() { o.OnParseResult(e) })
	}
}

func (m multiObserver) OnCheckResult(e CheckResult) {
	for _, o := range m {
		safeCall(func() { o.OnCheckResult(e) })
	}
}

func (m multiObserver) OnVerifyResult(e VerifyResult) {
	for _, o := range m {
		safeCall(func() { o.OnVerifyResult(e) })
	}
}

func safeCall(fn func()) {
	defer func() { recover() }() //nolint:errcheck
	fn()
}
