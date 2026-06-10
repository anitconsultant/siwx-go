#!/usr/bin/env bash
# Run from the repo root after the initial commit on main.
set -euo pipefail
git worktree add ../siwx-go-wt-a -b feat/siws-core
git worktree add ../siwx-go-wt-b -b feat/siwx-layer
git worktree add ../siwx-go-wt-c -b feat/mock-hub
git worktree add ../siwx-go-wt-d -b feat/test-harness
echo "Four worktrees ready. Launch one Claude Code (Sonnet 4.6) session per directory:"
echo "  ../siwx-go-wt-a  -> follow tasks/WT-A-siws-core.md"
echo "  ../siwx-go-wt-b  -> follow tasks/WT-B-siwx-layer.md"
echo "  ../siwx-go-wt-c  -> follow tasks/WT-C-mock-hub.md"
echo "  ../siwx-go-wt-d  -> follow tasks/WT-D-test-harness.md"
echo "Merge order: A -> B -> D -> C (see SPEC.md section 7)."
