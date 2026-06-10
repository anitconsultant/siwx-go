# Contributing

- Conventional Commits required (feat/fix/test/docs/ci/chore).
- PRs squash-merge; CI must be green; coverage gates enforced.
- `siws/` accepts no external dependencies. Ever. CI enforces this.
- Security issues: see docs/SECURITY.md — never a public issue first.
- New chains: implement `siwx.Verifier` in a new package under `siwx/`,
  register it, add vectors + invariant coverage. Do not modify existing verifiers.
