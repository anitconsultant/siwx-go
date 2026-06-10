# WT-D — test harness, fuzzing, CI, threat model

Branch: `feat/test-harness` · Worktree: `../siwx-go-wt-d` · Depends on: frozen contracts only
Read SPEC.md sections 5, 6, 8, 10. You own PROOF. Where A/B/C test their own
code, you test the system's promises. Write everything against the frozen
contracts now; tests that need real implementations are committed `t.Skip`ped
and un-skipped at the sync points (you own un-skipping).

## Deliverables

### internal/testvectors/load.go
Typed loader for vectors.json: Keys (with base58 pubkey + base64 seed),
Valid[], Invalid[] (with ExpectedError string -> mapped to the sentinel via a
lookup table). Helper `FrozenClock()` returning the referenceTime. Helper
`Signer(keyID)` reconstructing ed25519.PrivateKey from the seed so other tracks
can sign fresh messages in tests.

### Conformance suite — internal/conformance/conformance_test.go
For every Valid vector: siws.VerifyRaw AND siwx registry (solana adapter) both
succeed with frozen clock, correct domain ("dapp.academy" etc. from the message),
correct nonce. For every Invalid vector: fails and `errors.Is` matches the
mapped sentinel. The domain_mismatch_check vector: pass wrong ExpectedDomain.

### Fuzz targets (native go fuzzing)
- siws/fuzz_test.go `FuzzParseMessage`: corpus seeded from all vector messages +
  hand mutations (committed in testdata/fuzz/...). Property: never panics;
  if Parse succeeds, String() then Parse round-trips to an equal Message (S10).
- siws `FuzzVerifyRaw`: random msg/sig bytes never panic; valid-vector seeds.
- siwx/caip `FuzzParseCAIP10`: never panics; round-trip on success.
- CI smoke: 60s per target (ci.yml provided has the job; wire your targets in).

### Invariant suite — internal/invariants/invariants_test.go
The six security invariants, each exercised through BOTH siws directly and the
siwx registry, generating fresh messages/signatures with vector keys:
1. expired never verifies  2. wrong domain never verifies
3. burned/wrong nonce never verifies  4. any single flipped bit in message or
signature never verifies  5. wrong key never verifies  6. future not-before
never verifies.
Plus observability invariants: every Verify emits exactly one Attempt, one
ParseResult, N CheckResults stopping at first failure, one VerifyResult — all
sharing one attemptID, in order; and NO event payload contains message text or
signature bytes (assert via a recording Observer over invariant runs).

### CI/CD — .github/workflows/
Extend the provided ci.yml if needed; add release.yml (tag-driven goreleaser or
release-please with conventional-commit changelog), dependabot.yml (gomod +
actions, weekly), and an apidiff informational job. Add OpenSSF Scorecard
workflow. Enforce the siws zero-dep rule:
`test -z "$(go list -deps ./siws | grep -v '^github.com/anitconsultant/siwx-go' | grep -v -E '^(internal/|vendor/)' | grep /)"` style check (implement robustly).

### docs/THREAT_MODEL.md
Fill the provided skeleton: assets, trust boundaries, attacker capabilities,
the five checks and what each defeats (replay -> nonce; phishing -> domain;
stale capture -> expiry/not-before; forgery -> Ed25519; confused deputy ->
audience claim at the hub), S4/S5 logging rules, known non-goals (lookalike
domains, compromised wallet, XSS on the relying site), and the residual-risk
table. Cross-link every claim to the invariant test that proves it.

## Definition of done
- [ ] Conformance + invariants green (post sync points) with -race.
- [ ] Fuzz: 60s clean per target in CI; corpora committed.
- [ ] Coverage gates wired and passing: siws >= 95%, siwx >= 90%.
- [ ] THREAT_MODEL.md complete; every mitigation row links a test.
- [ ] release.yml dry-runs clean; Scorecard workflow green.
- [ ] PR: `test: conformance, fuzz, invariant suites and CI hardening`.
