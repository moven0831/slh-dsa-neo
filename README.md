# SLH-DSA-128s + Neo folding — production-params measurements

The **folding prover** in a three-repo study of proving SLH-DSA-128s (Poseidon hash) cheaply:

- **this repo** — folds SLH-DSA-128s verification via [Nightstream](https://github.com/LFDT-Nightstream/Nightstream) / Neo on Goldilocks.
- [`slh-dsa-128s-poseidon-bench`](https://github.com/moven0831/slh-dsa-128s-poseidon-bench) — the monolithic Spartan2 prover benchmark (the baseline we compare against, **and where the actual win lives**).
- [`slh-dsa-circuit`](https://github.com/moven0831/slh-dsa-circuit) — the Circom R1CS benchmark + folding research notes.

## Result (read this first)

**Folding is the wrong tool at this scale — a clean negative result.** At production params, one D4
fold step is **~50× slower** than the whole monolithic prover and uses **~2× the memory**; the
multi-step chain OOMs on a 24 GB box. The feasibility win we were after turned out to live in the
sibling repo instead: the **monolithic Goldilocks + Hash-MLE stack** (6.18 s prove / 0.27 s verify).
The Goldilocks SLH-DSA signer we built here (`crates/slh-poseidon-gl`) is exactly what made that
monolithic result measurable, so the work paid off — just in a different place.

Why folding loses (structural, not a bug): Poseidon emits full-range 64-bit witnesses, but
post-quantum lattice folding can only commit to bit-sized values, so it bit-decomposes every wire —
a **64× row blow-up** (486K-row step → `m×64+1 = 29,934,145`-row F' structure). Full reasoning and
per-stage breakdown in [`MEMO.md`](MEMO.md); the cross-repo comparison lives in the
[companion benchmark](https://github.com/moven0831/slh-dsa-128s-poseidon-bench) and the
[research memo](https://github.com/moven0831/slh-dsa-circuit/blob/main/research/folding/week3_findings.md).

## Headline (M3 / 24 GB, single-thread)

Production-params `r1cs_f_prime` on the D4 step circuit (486 K R1CS / 467 K wires → 30 M-row F' structure):

| Phase | Time | Peak RSS |
|---|---:|---:|
| Preprocess (Ajtai setup) | 86.7 s | – |
| **Prove + finish** | **116.6 s** | – |
| **Verify (uncompressed)** | **19.8 s** | – |
| **Total (one step)** | **227 s** | **10.46 GB** |

Full 7-step D4 chain extrapolated: **~815 s prove vs companion's 16.2 s monolithic — ~50× slower in
prover wall-clock** (~32× slower when verify is included on both sides).

## How the pieces fit

```
slh-poseidon-gl (real witness) → Circom D4 step circuit → neo-bridge (lift to CCS) → neo-ivc (fold)
```

The signer produces a real SLH-DSA-128s signature, decomposes it into per-XMSS-layer witnesses,
`neo-bridge` lifts the Circom `.r1cs`/`.wtns` into Nightstream CCS matrices, and `neo-ivc` folds them
through `r1cs_f_prime`.

## What's here

| Path | Status |
|---|---|
| `crates/slh-poseidon-gl/` | **Full FIPS 205 SLH-DSA-128s signer + verifier** on Plonky2 Goldilocks Poseidon (t=12, 30 rounds, x⁷), byte-exact vs Circom. Validated end-to-end; emits witnesses for both the monolithic and folded paths (`emit-monolithic`, `emit-layers`, `self-check`). |
| `crates/neo-ivc/src/bin/rfp_smoke.rs` | **Main folding binary.** Runs `r1cs_f_prime` end-to-end at production params. `--sparse` for HT-layer scale. |
| `crates/neo-ivc/` (`step`/`chain`/`finisher`) | Multi-step library API: `step::preprocess_sparse`, `chain::run_chain`, `finisher::close_chain`. (Finisher returns `Decider(Unsupported)` at Nightstream `755c1595` — see limitation.) |
| `crates/neo-ivc/src/bin/nifs_smoke.rs` | Phase-2 binary; demonstrates the `b = 2` rejection from `direct_ccs::build_instance` in <0.3 s. Historical / superseded. |
| `crates/neo-bridge/` | Working Circom `.r1cs` + `.wtns` parser; dense + sparse lift to `neo_ccs` matrices. |
| `crates/neo-bench/` | Criterion bench placeholders (not wired) — use the `rfp_smoke` binary for measured numbers. |
| `Cargo.toml` | Workspace with Nightstream commit `755c1595` pinned identically to `slh-dsa-circuit/tools/nightstream-spike`. |

## Known limitations

- **Multi-step folded chain is memory-bound on 24 GB.** A single HT-layer step (`c=2`) fits at
  10.46 GB, but folding the 7 real per-layer witnesses into the production accumulator (`c=972`)
  exceeds memory in the append/fold phase (a 2-step chain already peaked ~14 GB RSS / ~130 GB
  committed before a macOS memory-pressure kill). The shapes and sat-checks are correct — it dies in
  the memory-heavy fold, not on any correctness check. **The full multi-step real chain needs a
  32 GB+ box**; the `~815 s` full-chain figure stays a per-step projection.
- **Closing SNARK is blocked upstream.** `finisher::close_chain` returns `Decider(Unsupported)` at
  Nightstream `755c1595`.

## Reproduce in 5 minutes

```sh
git clone https://github.com/moven0831/slh-dsa-neo.git
cd slh-dsa-neo
cargo build --release --bin rfp_smoke

# Pre-built circuit artifacts live in slh-dsa-circuit
cd .. && git clone https://github.com/moven0831/slh-dsa-circuit.git
cd slh-dsa-circuit && git checkout 03e7acc

cd ../slh-dsa-neo

# Smoke (~5 s) — production params on 440 R1CS
./target/release/rfp_smoke \
  --r1cs ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/bench_poseidon_gl_reduce2.r1cs \
  --wtns ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/all_zeros.wtns

# HT-layer D4 step (~227 s) — production params on 486 K R1CS
./target/release/rfp_smoke --sparse \
  --r1cs ../slh-dsa-circuit/build/poseidon_gl_bench/bench_ht_layer_gl/bench_ht_layer_gl.r1cs \
  --wtns ../slh-dsa-circuit/build/poseidon_gl_bench/bench_ht_layer_gl/all_zeros.wtns
```

Both runs end with `RESULT: PASS — r1cs_f_prime prove + finish + verify all succeed.`

> Note: the multi-step `rfp_smoke_full` binary OOMs at HT-layer scale on 24 GB (see limitations) —
> don't run it expecting the full 7-step chain to complete on a 24 GB machine.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.
