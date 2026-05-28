# SLH-DSA-128s + Neo folding — exploratory PoC + Week-3 findings

Sibling to [`moven0831/slh-dsa-128s-poseidon-bench`](https://github.com/moven0831/slh-dsa-128s-poseidon-bench) (the monolithic Spartan2 + Hyrax bench on secq256r1).

This repo was set up to deliver "end-to-end folded SLH-DSA-128s on Nightstream/Neo with real prover numbers" as a complement to the companion repo's monolithic baseline. Phase-2 smoke testing surfaced a structural issue that **changed the deliverable**: every Nightstream Goldilocks parameter preset hard-pins the witness ℓ∞ norm bound at `b = 2` (binary), so Circom-derived Goldilocks R1CS (with full-range wires) cannot be folded directly. The supported workaround (`r1cs_f_prime` frontend, with 64-bit per-wire decomposition) inflates the foldable CCS structure by ~64× the underlying R1CS — and Nightstream's own integration tests don't run this regime at production security.

**Read the full memo:** [`MEMO.md`](MEMO.md) (summary) + [`slh-dsa-circuit/research/folding/week3_findings.md`](https://github.com/moven0831/slh-dsa-circuit/blob/main/research/folding/week3_findings.md) (full write-up with code citations).

## What's here

| Path | Status |
|---|---|
| `crates/slh-poseidon-gl/` | Skeleton (Phase 1 placeholder; not implemented) |
| `crates/neo-bridge/` | Working Circom `.r1cs` + `.wtns` parser → `neo_ccs::Mat<F>` adapter |
| `crates/neo-ivc/src/bin/nifs_smoke.rs` | Phase-2 smoke binary. Reproduces the `b=2` rejection in <0.3 s |
| `crates/neo-bench/` | Criterion bench placeholders (not wired up) |
| `Cargo.toml` | Workspace with Nightstream commit `755c1595` pinned identically to `slh-dsa-circuit/tools/nightstream-spike` |

## Reproduce the Phase-2 smoke

```sh
git clone https://github.com/moven0831/slh-dsa-neo.git
cd slh-dsa-neo
cargo build --release --bin nifs_smoke

# Pre-built smoke artifacts live in slh-dsa-circuit
cd .. && git clone https://github.com/moven0831/slh-dsa-circuit.git
cd slh-dsa-circuit && git checkout 03e7acc
# (assumes circuits already built per slh-dsa-circuit/CLAUDE.md)

cd ../slh-dsa-neo
./target/release/nifs_smoke \
  --r1cs ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/bench_poseidon_gl_reduce2.r1cs \
  --wtns ../slh-dsa-circuit/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/all_zeros.wtns
```

Expected: passes 4/6 stages (parse, lift, row-wise sat check, preprocess), then fails at NIFS prove with `CCS instance: ‖z‖_∞ ≥ b at index 1 (b = 2)`.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.
