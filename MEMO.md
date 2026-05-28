# Memo: Folding SLH-DSA-128s on Nightstream — Week-3 findings

> **Status: pivoted to findings memo.** The original goal — "end-to-end folded SLH-DSA-128s on Nightstream with competitive prover numbers" — turned out to rest on an unverified assumption about the per-fold overhead of lattice-based folding. Week-3 Phase-2 smoke uncovered the structural issue. Full write-up lives in [`slh-dsa-circuit/research/folding/week3_findings.md`](https://github.com/moven0831/slh-dsa-circuit/blob/main/research/folding/week3_findings.md).

## TL;DR

When we tried to fold a Circom-derived Goldilocks R1CS through Nightstream's `direct_ccs` frontend, the prover rejected the witness:

```
Error: direct_ccs::build_instance — z does not satisfy R1CS
Caused by: CCS instance: ‖z‖_∞ ≥ b at index 1 (b = 2)
```

Root cause: every Nightstream Goldilocks parameter preset hard-pins the witness ℓ∞ norm bound at `b = 2` (binary). Real Circom Goldilocks witnesses have full-range field elements and don't fit. The supported workaround (`r1cs_f_prime` frontend) bit-decomposes every wire to 64 bits, inflating the foldable CCS structure by ~64× the underlying R1CS row count. At SLH-DSA-128s D4 scale (486 K R1CS step), one fold step becomes a ~30.5 M-row CCS instance.

That row blow-up does **not** automatically mean "folding is uncompetitive": Goldilocks field ops are ~5–20× faster than secq256r1, so the wall-clock comparison against the companion repo's 16.2 s monolithic Spartan2-secq256r1 baseline is genuinely uncertain. **Nobody has measured it** — not us, and not Nightstream's authors (whose own integration tests use a reduced-security `tiny_params` preset to fit a single fold step under a 5-minute CI cap).

## What's in this repo

| Path | Content |
|---|---|
| `crates/slh-poseidon-gl/` | Skeleton for the Goldilocks Poseidon SLH-DSA signer (Phase 1 of the original plan) |
| `crates/neo-bridge/` | Circom `.r1cs` + `.wtns` → `neo_ccs::Mat<F>` adapter (validated at 486K-constraint scale via the slh-dsa-circuit spike) |
| `crates/neo-ivc/src/bin/nifs_smoke.rs` | Phase-2 smoke binary. **Demonstrates the b=2 rejection on a real Circom-derived R1CS.** Compiles and runs; reproducing the failure is one command (see "Reproduce the finding" below) |
| `crates/neo-bench/` | Criterion bench placeholders (left for whoever picks up the pivot) |
| `Cargo.toml` | Workspace with Nightstream commit `755c1595` pinned identically to `slh-dsa-circuit/tools/nightstream-spike` |

## What is and isn't verified

| Check | Status | Evidence location |
|---|---|---|
| `b = 2` is hard-pinned in all Nightstream Goldilocks presets | ✅ | `neo-params/src/lib.rs:58–82` (`goldilocks_paper_b2::B_BASE = 2`) and `goldilocks_auto_r1cs_ccs_with` (line 236, only varies `lambda`) |
| `r1cs_f_prime` structure shape (`m × 64 + ~5K rows`) | ✅ | `neo-fold-clean/src/frontends/r1cs_f_prime/mod.rs` + plan analysis in `r1cs_compiler.rs` tests |
| Nightstream's own integration test uses `tiny_params` at reduced security | ✅ | `tests/system/r1cs_compiler.rs:554–632` (`tiny_params` and `make_tiny_lifecycle_plan`) |
| Production-params `r1cs_f_prime` actually runs on a real R1CS at SLH-DSA scale | ❌ | **Not measured.** Nightstream's authors have not characterized this regime |
| Goldilocks Spartan2 wall-clock per CCS row vs Spartan2-secq256r1 | 🟡 Analytic | ~5–20× faster from per-op estimate; not benchmarked here |

## Walking back the "50× worse than monolithic" claim

The first conclusion I jumped to was "folding via `r1cs_f_prime` is ~50× worse than the companion's secq256r1 monolithic baseline." That was a **row-count** statement dressed as a **wall-clock** statement. The corrected version: ~64× row blow-up from bit-decomposition, partially offset by ~5–20× Goldilocks speedup. Net wall-clock direction is genuinely unknown. See `slh-dsa-circuit/research/folding/week3_findings.md §5` for the breakdown.

## Reproduce the finding

```sh
# This repo
git clone https://github.com/moven0831/slh-dsa-neo.git
cd slh-dsa-neo
cargo build --release --bin nifs_smoke

# Pre-built smoke artifacts live in slh-dsa-circuit (clone adjacent)
cd ..
git clone https://github.com/moven0831/slh-dsa-circuit.git
cd slh-dsa-circuit
git checkout 03e7acc
# (assumes circuits already built — see CLAUDE.md for the bootstrap recipe)

# Run the smoke
cd ../slh-dsa-neo
./target/release/nifs_smoke \
  --r1cs ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/bench_poseidon_gl_reduce2.r1cs \
  --wtns ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/all_zeros.wtns
```

Expected output: passes through R1CS parse + lift + row-wise satisfaction check + preprocess, then fails at NIFS prove with `CCS instance: ‖z‖_∞ ≥ b at index 1 (b = 2)`. Total wall-time <0.3 s.

## Pivots from here

The original Phases 3–7 are not viable as stated. The three pivots discussed in `research/folding/week3_findings.md §7`:

- **A — Measure production-params `r1cs_f_prime`.** ~1 engineer-week. Settles the wall-clock question with a real number. Risk: 24 GB may not be sufficient at SLH-DSA scale.
- **B — Monolithic Spartan2-GL bench, no folding.** ~3–5 engineer-days. Shows the Goldilocks field speedup honestly. Reuses the existing Goldilocks Poseidon port. Lowest risk; complements the companion repo well.
- **C — Fix LatticeFold gadget-norm at verify.** ~1 engineer-day. LatticeFold's 5× decomposition factor is more favorable than Nightstream's 64×. If the fix lands, pivot A becomes feasible on LatticeFold's NIFS instead.

Pivots B + C run in parallel are the safest delivery of "real folding numbers" within a bounded budget.

## Methodology (carry-over for whichever pivot lands)

For consistency with the companion repo `slh-dsa-128s-poseidon-bench`:

- **Host:** M3 / 24 GB, macOS 14+, single-thread
- **Reporting:** median ± stdev over 3 cold + 3 warm runs
- **Cold:** fresh process, OS file caches dropped via `sync && sudo purge` between runs
- **Warm:** three consecutive iterations after one untimed warm-up
- **Wall-clock:** `Instant::now()` brackets in Rust
- **Peak RSS:** sampled via `getrusage(RUSAGE_SELF)`; cross-checked against `/usr/bin/time -l`
- **Proof size:** serialized bytes (no further compression)

## References

- Full findings: [`slh-dsa-circuit/research/folding/week3_findings.md`](https://github.com/moven0831/slh-dsa-circuit/blob/main/research/folding/week3_findings.md)
- Companion repo (secq256r1 monolithic): [`slh-dsa-128s-poseidon-bench`](https://github.com/moven0831/slh-dsa-128s-poseidon-bench)
- Source circuit repo (pin `03e7acc`): [`slh-dsa-circuit`](https://github.com/moven0831/slh-dsa-circuit)
- Nightstream (pin `755c1595`): [LFDT-Nightstream/Nightstream](https://github.com/LFDT-Nightstream/Nightstream)
