#!/usr/bin/env bash
# Reproduce the headline numbers in MEMO.md from scratch.
#
# Prereqs:
#   - circom 2.2.3 on PATH (with --prime goldilocks support)
#   - Rust stable 1.88+
#   - macOS or Linux (M3 is the canonical baseline)
#   - slh-dsa-circuit checked out adjacent at ../slh-dsa-circuit @ 03e7acc
#
# Phases (Phase 6 fills in the actual steps):
#   1. Compile Goldilocks Poseidon circuits via circom
#   2. Run slh-poseidon-gl signer to generate per-layer witnesses
#   3. cargo bench --bench single_fold
#   4. cargo bench --bench ivc_chain
#   5. cargo bench --bench finisher
#   6. cargo bench --bench end_to_end
#   7. neo-bench emits results/tables/*.md
#   8. Template-merge results/tables/* into MEMO.md
set -euo pipefail

echo "scripts/repro.sh: not yet implemented (Phase 6)."
exit 2
