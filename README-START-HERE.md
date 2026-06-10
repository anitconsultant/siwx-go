# siwx-go kickoff kit — START HERE

This folder is everything needed to launch the parallel build of
`github.com/anitconsultant/siwx-go` with Claude Code on Sonnet 4.6.

## What's in the box

| Path | What it is |
|---|---|
| SPEC.md | The master build spec. Every session reads this first. |
| contracts/contracts.go | The frozen interfaces. LAW for all four tracks. |
| tasks/WT-A..D.md | One work order per parallel worktree. |
| tasks/REVIEW-PASS.md | The final Opus-class security review prompt. |
| internal/testvectors/vectors.json | REAL Ed25519 test vectors (test keys only), pre-verified. |
| .github/workflows/ci.yml | CI: matrix tests, race, staticcheck, govulncheck, zero-dep gate, fuzz smoke. |
| docs/THREAT_MODEL.md | Skeleton WT-D completes. |
| docs/SECURITY.md | Disclosure policy. Ships as-is. |
| scripts/worktrees.sh | Creates the four worktrees. |
| LICENSE-APACHE, LICENSE-MIT | Dual license. |
| go.mod, CONTRIBUTING.md, CODEOWNERS | Repo scaffolding. |

## Launch sequence

```bash
# 1. New GitHub repo: anitconsultant/siwx-go (public, no auto-README)
# 2. Unzip this kit as the repo root, then:
git init && git add -A && git commit -m "chore: kickoff kit — spec, contracts, vectors, CI"
git branch -M main
git remote add origin git@github.com:anitconsultant/siwx-go.git
git push -u origin main

# 3. Create the four worktrees:
./scripts/worktrees.sh

# 4. Open four terminals (or run sequentially if quota-constrained).
#    In each worktree, start Claude Code with Sonnet 4.6 (/model to confirm)
#    and paste this prompt, swapping the task file name:

#    "Read SPEC.md, contracts/contracts.go, and tasks/WT-A-siws-core.md.
#     Build exactly what the work order specifies. The contracts are frozen:
#     if one seems wrong, stop and ask me instead of adapting. Commit with
#     Conventional Commits as you go. Do not touch files owned by other tracks."

# 5. Merge order: A -> B (then B's sync-point-1 commit) -> D -> C (sync-point-2).
#    Squash-merge PRs, CI green required.

# 6. Final pass: new session, Opus-class model, tasks/REVIEW-PASS.md.
#    Disposition findings, then: git tag v0.1.0 && git push --tags
```

## Quota tip ($20 Pro plan)
Tracks A and D are the heavy ones. If you hit limits, run A and D first
(they're the library and its proof), then B, then C — C is mostly example
code and survives a session break best. The Opus review pass is one short
session; budget for it before tagging.

## After v0.1.0
- README badges light up once CI runs and pkg.go.dev indexes the tag.
- Grant application: solana.org/grants-funding — lead with "the missing Go
  SIWS/CAIP-122 library, fuzz-tested, threat-modeled," attach the repo,
  the THREAT_MODEL.md, and a screenshot of the demo page stepper.
