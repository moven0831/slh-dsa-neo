# SLH-DSA-128s + Neo folding — Pivot A: production-params measurements

Sibling to [`moven0831/slh-dsa-128s-poseidon-bench`](https://github.com/moven0831/slh-dsa-128s-poseidon-bench) (the monolithic Spartan2 + Hyrax bench on secq256r1).

Goal: measure end-to-end folded SLH-DSA-128s verification via [Nightstream](https://github.com/LFDT-Nightstream/Nightstream) / Neo on Goldilocks, and compare to the companion repo's monolithic baseline.

## Headline (M3 / 24 GB, single-thread)

Production-params `r1cs_f_prime` on the D4 step circuit (486 K R1CS / 467 K wires → 30 M-row F' structure):

| Phase | Time | Peak RSS |
|---|---:|---:|
| Preprocess (Ajtai setup) | 86.7 s | – |
| **Prove + finish** | **116.6 s** | – |
| **Verify (uncompressed)** | **19.8 s** | – |
| **Total (one step)** | **227 s** | **10.46 GB** |

Full 7-step D4 chain extrapolated: **~815 s prove vs companion's 16.2 s monolithic — ~50× slower in prover wall-clock** (~32× slower when verify is included on both sides). Full write-up + per-stage breakdown in [`MEMO.md`](MEMO.md) and the [research memo](https://github.com/moven0831/slh-dsa-circuit/blob/main/research/folding/week3_findings.md).

## What's here

| Path | Status |
|---|---|
| `crates/neo-ivc/src/bin/rfp_smoke.rs` | **Pivot A binary.** Runs `r1cs_f_prime` end-to-end at production params. Supports `--sparse` for HT-layer scale. |
| `crates/neo-ivc/src/bin/nifs_smoke.rs` | Phase-2 binary. Demonstrates the `b = 2` rejection from `direct_ccs::build_instance` in <0.3 s. |
| `crates/neo-bridge/` | Working Circom `.r1cs` + `.wtns` parser; dense + sparse lift to `neo_ccs` matrices |
| `crates/slh-poseidon-gl/` | Skeleton (not implemented) |
| `crates/neo-bench/` | Criterion bench placeholders (not wired) |
| `Cargo.toml` | Workspace with Nightstream commit `755c1595` pinned identically to `slh-dsa-circuit/tools/nightstream-spike` |

## Reproduce in 5 minutes

```sh
git clone https://github.com/moven0831/slh-dsa-neo.git
cd slh-dsa-neo
cargo build --release --bin rfp_smoke

# Pre-built circuit artifacts live in slh-dsa-circuit
cd .. && git clone https://github.com/moven0831/slh-dsa-circuit.git
cd slh-dsa-circuit && git checkout 03e7acc

cd ../slh-dsa-neo

# Smoke (5 s) — production params on 440 R1CS
./target/release/rfp_smoke \
  --r1cs ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/bench_poseidon_gl_reduce2.r1cs \
  --wtns ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/all_zeros.wtns

# HT-layer D4 step (227 s) — production params on 486 K R1CS
./target/release/rfp_smoke --sparse \
  --r1cs ../slh-dsa-circuit/build/poseidon_gl_bench/bench_ht_layer_gl/bench_ht_layer_gl.r1cs \
  --wtns ../slh-dsa-circuit/build/poseidon_gl_bench/bench_ht_layer_gl/all_zeros.wtns
```

Expected output: both runs end with `RESULT: PASS — r1cs_f_prime prove + finish + verify all succeed.`

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.
