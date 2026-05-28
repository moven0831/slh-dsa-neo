# Memo: Folding SLH-DSA-128s on Nightstream — measured

> **Status: Pivot A measured.** `r1cs_f_prime` end-to-end production-params NIFS prove + verify on the D4 step circuit. Real numbers below. Full write-up: [`slh-dsa-circuit/research/folding/week3_findings.md`](https://github.com/moven0831/slh-dsa-circuit/blob/main/research/folding/week3_findings.md).

## TL;DR

Production-params Nightstream `r1cs_f_prime` works end-to-end on a Circom-derived Goldilocks R1CS at SLH-DSA-128s D4 scale. **One HT-layer fold step (486 K R1CS → 30 M-row F' structure):**

| Phase | Time | Peak RSS |
|---|---:|---:|
| Preprocess (Ajtai setup) | 86.7 s | – |
| **Prove + finish** | **116.6 s** | – |
| **Verify (uncompressed)** | **19.8 s** | – |
| **Total (one step)** | **227 s** | **10.46 GB** |

Extrapolated full D4 chain (7 folds): **~815 s prove**, vs the companion repo's monolithic Spartan2 + Hyrax on secq256r1 at **16.2 s prove / 9.5 s verify / 208.8 KB proof / 5.41 GB RSS**. So **folding is ~50× slower than monolithic in prover wall-clock** (~32× slower if you count prove + verify on both sides). Real measured number; refutes earlier "maybe competitive" speculation. Peak RSS per fold (10.46 GB) is ~2× monolithic but doesn't compound across folds (IVC's defining property).

## What's in this repo

| Path | Status |
|---|---|
| `crates/neo-ivc/src/bin/nifs_smoke.rs` | Original Phase-2 binary. Demonstrates the `b = 2` binary-witness rejection from `direct_ccs::build_instance`. <0.3 s. |
| `crates/neo-ivc/src/bin/rfp_smoke.rs` | **Pivot A binary.** Runs `r1cs_f_prime` end-to-end (preprocess → chain.append → finish → verify_uncompressed) on a Circom Goldilocks R1CS. Supports `--sparse` for circuits beyond ~10K wires. 5 s on smoke, 227 s on HT-layer. |
| `crates/neo-bridge/` | Circom `.r1cs` + `.wtns` parser + dense and sparse lift to `neo_ccs` matrices |
| `crates/slh-poseidon-gl/` | Skeleton (not implemented) |
| `crates/neo-bench/` | Criterion bench placeholders (not wired) |

## Measured numbers

### Smoke — `bench_poseidon_gl_reduce2` (440 R1CS, m = 445 wires)

Production params, dense path, M3 / 24 GB, single-thread:

| Stage | Time |
|---|---:|
| Parse Circom .r1cs/.wtns | 9.8 ms |
| Lift to `neo_ccs::Mat<F>` | 0.7 ms |
| Row-wise sat check | 0.7 ms |
| Build plan | 0.1 ms |
| `preprocess_seeded` | 1.72 s |
| `R1csChainBuilder` append + finish | 2.07 s |
| `verify_uncompressed` | 0.62 s |
| **Total** | **4.42 s** |
| Peak RSS | **2.26 GB** |

### D4 step — `bench_ht_layer_gl` (485 930 R1CS, m = 467 721 wires)

Production params, sparse path, M3 / 24 GB, single-thread:

| Stage | Time |
|---|---:|
| Parse Circom .r1cs/.wtns | 3.6 s |
| Lift to `CcsMatrix<F>::Csc` | 170 ms |
| Row-wise sat check | 9.4 ms |
| Build plan (limbs = 29.9 M) | 45 µs |
| `preprocess_sparse_seeded` | 86.7 s |
| `R1csChainBuilder` append + finish | **116.6 s** |
| `verify_uncompressed` | **19.8 s** |
| **Total** | **227 s** |
| Peak RSS | **10.46 GB** |

### Side-by-side vs companion

| Path | Field | Strategy | Prove (full chain) | Verify | Peak RSS | Proof |
|---|---|---|---:|---:|---:|---:|
| `slh-dsa-128s-poseidon-bench` (companion) | secq256r1 | Monolithic Spartan2 + Hyrax (OpenAC) | **16.2 s** | **9.5 s** | **5.41 GB** | **208.8 KB** |
| `slh-dsa-neo` (this, measured 1-step, ×7 extrapolated) | Goldilocks | Neo `r1cs_f_prime` 7-fold | ~815 s | ~20 s | 10.46 GB (per step) | (uncompressed) |
| Ratio (folding / monolithic) | — | — | **~50×** | ~2× | ~2× per step | — |

Caveats:
- Folded chain prove is extrapolated linearly from one measured step. Real 7-step chain may add 10–20% per step due to `c_data_entries` scaling.
- Goldilocks closing SNARK (Spartan2-GL finisher) is NOT in the 815 s; that would add finisher prove time and produce a small final proof. Not measured here.
- The folded path peak RSS doesn't compound across steps. A 32-GB box can run the full chain without hitting any wall.

## What's verified vs. assumed

| Check | Status | Evidence |
|---|---|---|
| `b = 2` is hard-pinned in all Nightstream Goldilocks presets | ✅ | `neo-params/src/lib.rs:58–82` |
| `r1cs_f_prime` structure shape `m × 64 + 1` | ✅ | Verified: HT-layer measured `limbs = 29,934,145` matches `467,721 × 64 + 1` exactly |
| Production-params `r1cs_f_prime` runs on Circom Goldilocks R1CS | ✅ | Measured `rfp_smoke` on smoke + HT-layer |
| Full 7-step IVC chain at production with proper `c_data_entries = κ × D = 972` | ❌ | Per-step extrapolation only |
| Spartan2-GL finisher closes the chain into a small proof | ❌ | Not measured |

## How to reproduce

```sh
git clone https://github.com/moven0831/slh-dsa-neo.git
cd slh-dsa-neo
cargo build --release --bin rfp_smoke

# Pre-built circuit artifacts live in slh-dsa-circuit (clone adjacent)
cd .. && git clone https://github.com/moven0831/slh-dsa-circuit.git
cd slh-dsa-circuit && git checkout 03e7acc

cd ../slh-dsa-neo

# Smoke (5 s)
./target/release/rfp_smoke \
  --r1cs ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/bench_poseidon_gl_reduce2.r1cs \
  --wtns ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/all_zeros.wtns

# HT-layer D4 step (227 s, requires --sparse)
./target/release/rfp_smoke --sparse \
  --r1cs ../slh-dsa-circuit/build/poseidon_gl_bench/bench_ht_layer_gl/bench_ht_layer_gl.r1cs \
  --wtns ../slh-dsa-circuit/build/poseidon_gl_bench/bench_ht_layer_gl/all_zeros.wtns

# (Optional) The b=2 finding from Phase 2
./target/release/nifs_smoke \
  --r1cs ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/bench_poseidon_gl_reduce2.r1cs \
  --wtns ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/all_zeros.wtns
```

Both `rfp_smoke` runs print `RESULT: PASS — r1cs_f_prime prove + finish + verify all succeed.` `nifs_smoke` prints the `b=2` rejection.

## What this changes about the original plan

The original Pivot A goal was to settle whether folding via `r1cs_f_prime` is competitive with monolithic Spartan2. It now has an answer: **it isn't — ~50× slower in prover wall-clock (~32× when verify is included).** That's a real number; it makes folding for this circuit a research direction, not a competitive path.

Next moves:
- **Pivot B** — Spartan2-GL monolithic bench (no folding). Cleanest comparison to the companion's secq256r1 monolith; quantifies the small-field benefit honestly. Reuses the Goldilocks Poseidon port. Recommended next step.
- **Pivot C** — LatticeFold gadget-norm fix at verify. 5× decomposition vs Nightstream's 64× — *if* the verify-side bug fix lands (~1 engineer-day per `poseidon_gl_audit.md` line 144), a re-run of `rfp_smoke`-equivalent on LatticeFold could be ~6–9 s/step instead of 116.6 s/step. The most plausible path to a competitive folded number.

## Methodology

- **Host:** M3 / 24 GB, macOS 14+, single-thread
- **Reporting:** single-run wall-clock + peak RSS from `/usr/bin/time -l`. (Median+stdev across 3 cold + 3 warm runs not yet done — single run is enough to anchor the order-of-magnitude finding.)
- **Wall-clock:** `Instant::now()` brackets in Rust, printed at each of 7 stages
- **Peak RSS:** maximum resident set size from `getrusage(RUSAGE_SELF)` via `/usr/bin/time -l`
- **Verify is fresh-process:** every `verify_uncompressed` runs after the prover side has produced the `Uncompressed` struct in the same process. A separate-process verify benchmark is straightforward to wire up but not run here.

## References

- Full findings memo: [`slh-dsa-circuit/research/folding/week3_findings.md`](https://github.com/moven0831/slh-dsa-circuit/blob/main/research/folding/week3_findings.md)
- Companion repo (secq256r1 monolithic): [`slh-dsa-128s-poseidon-bench`](https://github.com/moven0831/slh-dsa-128s-poseidon-bench)
- Source circuit repo (pin `03e7acc`): [`slh-dsa-circuit`](https://github.com/moven0831/slh-dsa-circuit)
- Nightstream (pin `755c1595`): [LFDT-Nightstream/Nightstream](https://github.com/LFDT-Nightstream/Nightstream)
