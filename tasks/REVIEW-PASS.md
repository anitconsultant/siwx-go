# Final security review pass (Opus-class model)

Run AFTER all four PRs are merged and CI is green. One session, read-only
mindset: findings, not fixes (fixes go through normal PRs).

Scope (in priority order):
1. siws/parse.go — parser robustness: any input that could panic, mis-parse,
   or accept a message that differs from what was signed. Pay attention to
   line-ending handling, optional-field ordering, and unicode in domain/statement.
2. siws/verify.go — check ordering vs SPEC S3, constant-time nonce comparison,
   exact-length enforcement before ed25519.Verify, VerifyRaw vs Verify byte-source
   discrepancy risks.
3. siws/base58.go — alphabet handling, leading-zero handling, 32-byte enforcement.
4. internal/invariants — do the tests actually prove the THREAT_MODEL claims?
   Look for invariants that pass vacuously.
5. siwx/evm/adapter.go — error mapping completeness; can any siwe-go failure
   surface as success or as the wrong sentinel?

Output: a markdown report with severity (Critical/High/Med/Low/Info), file:line,
description, and suggested test that would have caught it. No code changes.
Tag v0.1.0 only after the human dispositions every Critical/High finding.
