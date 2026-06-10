# Memo: Folding SLH-DSA-128s on Nightstream — measured

> **New here? Start with the [README](README.md)** for the concise wrap-up (result, what's in the
> repo, how to reproduce). This memo is the deep-dive appendix: every measured number, methodology,
> and session log.
>
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
| `crates/neo-ivc/src/{step,chain,finisher}.rs` | **Library API** (Session 2026-05-28). `step::build_plan` + `step::preprocess_sparse` extract the rfp_smoke plan-construction. `chain::run_chain` appends multiple witnesses against one preprocessing then finishes. `finisher::close_chain` uses the audit-mode `compress` path to produce a `Compressed` proof + verifier. Builds clean; multi-step run not yet measured. |
| `crates/neo-bridge/` | Circom `.r1cs` + `.wtns` parser + dense and sparse lift to `neo_ccs` matrices |
| `crates/slh-poseidon-gl/` | **Full SLH-DSA-128s signer + verifier** (Session 2026-05-28). Plonky2 Poseidon t=12 byte-matches 4 reference vectors; F/H/T_k/T_len/H_msg byte-match Circom bench witnesses. `signer.rs` ports the FIPS 205 control flow (keygen/WOTS+/FORS/XMSS/HT) from `poseidon_sign.mjs` onto the Goldilocks primitives; `verify()` mirrors the circuit. **Validated end-to-end**: `cli emit-monolithic` → the real `main_poseidon_gl.circom` WASM witness generator returns `valid == 1` (and a tampered input fails the `xmss_root === pk_root` asserts). Leaf loops parallelized with rayon; sign ≈ 6 s on M3. |
| `crates/neo-bench/` | Criterion bench placeholders (not wired) |

## Real-witness monolithic baseline (Row 2) — Session 2026-05-28

The signer now produces a **real** witness for the monolithic Goldilocks
verifier, so the companion repo's Row 2 (Goldilocks + Hash-MLE PCS) is
measured end-to-end instead of setup-only. M3 / 24 GB, real witness
(`valid == 1`):

| Phase | Time | Peak RSS | Artifact | Size |
|---|---:|---:|---|---:|
| Witness (circom WASM) | 3.08 s | 264 MB | proof | **575,198 B (562 KiB)** |
| Setup | 17.6 s | 4.47 GB | pk | 571 MB |
| Prove | 6.18 s | 4.47 GB | vk | 571 MB |
| Verify | 0.27 s | – | R1CS | 446 MB |

vs Row 1 (secq256r1 + Hyrax) at the same scale: prove **~2.6× faster**,
verify **~35× faster**, proof **~2.75× larger**. **This gap is field *and*
PCS** (secq256r1+Hyrax → Goldilocks+Hash-MLE), not pure field — the verify
speedup and larger proof are mostly the PCS swap. Timings carry ±25%
run-to-run variance on the loaded 24 GB box; artifact sizes are deterministic.

**Latent bug found + fixed in the Track 2.2 adapter.** The setup-only path
never exercised prove/verify, hiding a bug: `Circom2SpartanCircuit::public_values()`
declared one public output (the circuit's `valid` wire) but `synthesize` never
`inputize()`d it. Prove succeeded but verify returned `InvalidSumcheckProof`
(prover transcript vs verifier public-IO sum-check disagreed). Fix: `inputize`
each `wires[1..=n_pub_out]` in `synthesize`, matching the `CubicCircuit`
example in spartan2. Verify passes after the fix. The `w0_is_one` constant-wire
pinning is independently sound (w0 is aux, constrained `= 1`).

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
| **Real SLH-DSA signature layer folds + verifies** (1 HT-layer step) | ✅ | `emit-layers` → `layer_0.wtns` → `rfp_smoke_full --n-steps 1`: R1CS-sat ✓, preprocess 90.6 s, prove+finish 139.2 s, verify_uncompressed 28.9 s — **PASS**. All 7 layers chain to `pk_root` in the per-layer circuit. |
| Multi-step real chain at HT-layer scale + production accumulator (`c=972`) | ❌ (memory-bound) | `rfp_smoke_full` multi-`--wtns` parses 7 real witnesses, sat-checks all, builds the plan (`r_len = 26`, surfaced via `PostParentShapeMismatch`), and preprocesses cleanly — but the fold phase exceeds the 24 GB box. Even a 2-step chain peaked **14.24 GB RSS / 130 GB committed** before a macOS memory-pressure kill; 7-step SIGKILLed. The `c=972` accumulator completes on the 440-R1CS smoke circuit (9.99 GB) but not the 486K-R1CS HT-layer shell (30M F' rows). **Needs 32 GB+** — machinery + shapes are correct, it's a RAM ceiling. |
| Spartan2-GL finisher closes the chain into a small proof | ❌ | Not measured — `Decider(Unsupported)` at Nightstream 755c1595 |

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

## Session 2026-05-28 — Pivot A "Finish" track progress

User-approved scope: complete Pivot A (slh-dsa-neo) + add Spartan2-GL baseline
to the companion repo. This session covered T1.1.a/b + T1.2/T1.3/T1.4 of the
12-task plan in `~/.claude/plans/is-there-anything-we-glittery-unicorn.md`.

**Implemented and tested:**

- `slh-poseidon-gl::poseidon` — Plonky2 v1.1.0 Poseidon-Goldilocks permutation
  (t=12, 30 rounds, x⁷ S-box). Byte-matches all 4 Plonky2 reference vectors
  (`zeros`, `range`, `neg_one`, `random`) from
  `slh-dsa-circuit/scripts/check_poseidon_gl.py`. Naive u128-mod-P reduction
  (correctness over speed — reference signer, not a hot path).
- `slh-poseidon-gl::poseidon` — `PoseidonGl(N)` (N ≤ 12), `PoseidonGlSponge14`
  (rate-8 sponge for arity-14 hashes), `PoseidonGlReduce(N)` (binary Merkle
  tree), `pack_bytes16_to_2fe` / `unpack_fe2_to_bytes16`.
- `slh-poseidon-gl::primitives` — `SlhF` (arity-12), `SlhH` (arity-14 sponge),
  `SlhTk` (Merkle reduce of 14 leaves + mix), `SlhTlen` (35 leaves + mix).
  Validated **byte-for-byte against Circom witnesses** from
  `build/poseidon_gl_bench/bench_slh_{f,h,tk}_gl/witness.wtns` (input.json
  = pk_seed [1..16], all-zero ADRS, m [17..]). SlhTlen structurally validated
  (no Circom witness exists yet for it).
- `neo-ivc::step` — `build_plan(m, m_in, opts)` + `preprocess_sparse(r1cs, plan, seed)`.
  Hoists the F'-shell plan construction out of `bin/rfp_smoke.rs`.
  `StepPlanOptions::PRODUCTION` = `c_data_entries = 972` (κ × D).
- `neo-ivc::chain` — `run_chain(prep, witnesses) → Uncompressed`. Multi-step
  IVC chain that threads N witnesses through one `R1csChainBuilder` and
  finishes. Compiles; not yet measured end-to-end on real data.
- `neo-ivc::finisher` — `close_chain(prep, witnesses) → Compressed`. Uses the
  audit-mode flow (`finish_with_audit` + `lifecycle::compress`) to produce
  a closed proof.

**API gap surfaced (revises plan):**

- The original plan's Track 1.4 referenced `neo_fold_prototype::lifecycle::finish_direct_ccs_with_spartan`
  as the Spartan2-GL closer. Verification: that entry point exists only for
  the `direct_ccs` and `rv32im` frontends. **There is no
  `finish_r1cs_f_prime_with_spartan` in Nightstream `755c1595`.** The
  canonical close for `r1cs_f_prime` is `lifecycle::compress` →
  `Compressed`. A true Spartan2-GL final SNARK on `r1cs_f_prime` would need
  custom plumbing: `lifecycle::build_decider_statement` →
  `decider::Statement` → standalone `spartan2::R1CSSNARK<GoldilocksP3MerkleMleEngine>`.
  Track 1.4 in this session implements the `compress` path. A true
  Spartan2-GL closing SNARK measurement remains separate work.

- **Runtime test of `compress` (Session 2026-05-28)**: smoke single-step
  `--close` returns `Decider(Unsupported)` at runtime. `compress.rs:4-5`
  confirms: *"the PR5 decider is not implemented yet, so public `compress`
  / compressed `verify` return `decider::Error::Unsupported`"*. So at
  Nightstream `755c1595`, **there is no functional closing-SNARK path for
  `r1cs_f_prime`** — only `Uncompressed` is verifiable. The `close_chain`
  / `verify_compressed` library functions are kept in place for when
  upstream lands the decider, with the top-of-file note in
  `crates/neo-ivc/src/finisher.rs` documenting the gap. Track 1.4-bis
  options: (a) upgrade Nightstream to a commit where `decider::prove`
  works, or (b) custom-plumb `build_decider_statement` →
  `decider::Statement` → standalone Spartan2-GL adapter (same adapter
  Track 2.2 will need).

**First multi-step measurement (Session 2026-05-28, smoke circuit):**

Ran `rfp_smoke_full --n-steps 2 --profile production --r-len 23` on
`bench_poseidon_gl_reduce2` (440 R1CS, 445 wires). The Nightstream
recursive-compile probe required the full production-params accumulator
shape (`c_data_entries = 972 = κ × D`, `child_count = 14 = K_RHO`,
`x_rows = 54`, `x_active_cols = 5`, `y_ring_inner_lens = [64; 8]`,
`y_zcol_len = 64`, `r_len = s_col_len = 23` for this m). Constants
extracted from the `PostParentShapeMismatch` error (the same
"probe-and-extract" pattern Nightstream's `make_tiny_lifecycle_plan` uses
at `r1cs_compiler.rs:580`).

| Stage | Time |
|---|---:|
| Preprocess (Ajtai setup, c=972) | **14.4 s** |
| 2 × append + finish | **89.8 s** (≈ 44.9 s / step) |
| `verify_uncompressed` | 5.2 s |
| **Total** | **109.4 s** |
| Peak RSS | **9.99 GB** |

Compare with Pivot A's single-step smoke at c=2: 2.07 s prove+finish per
step. Per-step prove cost grew **~22×** on the 440-R1CS smoke when
switching c=2 → c=972. The Ajtai-setup grew **~8.5×** (1.7 s → 14.4 s).
This is the **first measured floor overhead** for the production-params
accumulator on a real Circom Goldilocks R1CS — the 10–20% per-step growth
flagged in `week3_findings.md` §1 was correct *as a percentage of the
underlying-row cost*, but in absolute terms the smoke circuit's
44.9 s/step is dominated by accumulator overhead, not underlying-row work.
On the HT-layer (m=467K, limbs=30M) the underlying-row cost (3.9 µs/row ×
30M ≈ 117 s) should still dominate, so the multi-step per-step prove may
land closer to 130–140 s/step than 22× × 116.6 s. Open question pending
the HT-layer run.

**Done since the last memo:**

- T1.1.c — full SLH-DSA-128s signer + verifier (`signer.rs`), validated
  end-to-end against `main_poseidon_gl.circom` (`valid == 1`). ✓
- T1.1.d — signer CLI (`emit-monolithic`, `self-check`). ✓ (emits the
  monolithic witness; per-XMSS-layer emission for the folded path is the one
  remaining CLI sub-feature — see below.)
- T2.1/T2.2/T2.3 — monolithic Goldilocks circuit, Spartan2-GL bench crate,
  and the now-real three-row table. ✓ (Row 2 prove/verify measured; the
  `inputize` adapter bug was found and fixed here.)

- T1.1.d `emit-layers` — per-XMSS-layer witness JSONs in the
  `bench_ht_layer_gl.circom` layout. ✓ All 7 layers validated against the
  per-layer circuit (chain to `pk_root`) and layer 0 folded + verified
  through `r1cs_f_prime`.

**Still open:**

- Full multi-step folded chain on the **real** per-layer witnesses at
  `c_data_entries = 972`. The plumbing is **done** — `rfp_smoke_full` takes
  repeated `--wtns` (the 7 real `.wtns` from `emit-layers`), and the
  `r_len = 26` shape is fixed. But it's **memory-bound on 24 GB**: the fold
  phase OOMs (2-step peaked 14.24 GB RSS / 130 GB committed before a
  memory-pressure kill; 7-step SIGKILLed). The `c=972` accumulator fits the
  440-R1CS smoke circuit but not the 486K-R1CS HT-layer shell. **Needs a
  32 GB+ box** — re-run `rfp_smoke_full --profile production --r-len 26
  --wtns layer_0.wtns … --wtns layer_6.wtns` there. Per-step cost is already
  real-measured (139 s/step); only the full-chain total is gated on RAM.
- Track 1.4-bis — true Spartan2-GL closing SNARK on `r1cs_f_prime`
  (`Decider(Unsupported)` at Nightstream 755c1595; needs custom plumbing
  through `build_decider_statement` + the standalone Spartan2-GL adapter
  Track 2.2 already built).

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
