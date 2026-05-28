# SLH-DSA-128s + Neo folding, end-to-end benchmark

End-to-end prove + verify numbers for the [SLH-DSA-128s Poseidon-hash verifier](https://github.com/moven0831/slh-dsa-circuit/blob/main/circuits/poseidon_gl/bench/bench_ht_layer_gl.circom), folded across 7 XMSS layers with [Nightstream / Neo](https://github.com/LFDT-Nightstream/Nightstream) on Goldilocks, closed with Nightstream's native Spartan2-Goldilocks finisher.

Sibling to [`moven0831/slh-dsa-128s-poseidon-bench`](https://github.com/moven0831/slh-dsa-128s-poseidon-bench) (monolithic Spartan2 on secq256r1, OpenAC stack). Same SLH-DSA verifier semantics, different field and proving strategy.

> **Status: work in progress.** Numbers below are placeholders until Phase 6 lands. See [`MEMO.md`](MEMO.md) for methodology and the latest state.

## Results (M3 / 24 GB, single-thread) — TODO

| Phase          |  Time | Peak RSS | Artifact      |  Size |
| -------------- | ----: | -------: | ------------- | ----: |
| Setup          | TODO  | TODO     | Proving key   | TODO  |
| Witness        | TODO  | –        | Verifying key | TODO  |
| Fold × 7       | TODO  | TODO     | Accumulator   | TODO  |
| Finisher prove | TODO  | TODO     | **Proof**     | TODO  |
| Verify         | TODO  | TODO     | –             | –     |

For the per-layer step circuit (`ht_layer_step.circom`): **485,930 R1CS · 467,721 wires** (Goldilocks).

## Run it

> ⚠️ This repo depends on circuit sources from [`moven0831/slh-dsa-circuit`](https://github.com/moven0831/slh-dsa-circuit). Numbers in `MEMO.md` are pinned to commit `03e7acc`.

### 1. Clone

```sh
git clone https://github.com/moven0831/slh-dsa-neo.git
cd slh-dsa-neo
```

### 2. Reproduce numbers

```sh
bash scripts/repro.sh        # compiles circuits → signs → benches → emits results/tables/*
```

### 3. Spot-check one phase

```sh
cargo bench --bench single_fold        # per-fold-step number
cargo bench --bench ivc_chain          # 7-step IVC total
cargo bench --bench finisher           # Spartan2-GL finisher
cargo bench --bench end_to_end         # headline number
cargo test --test verifier             # fresh-process verifier returns Ok
```

## Layout

```
slh-dsa-neo/
├── crates/
│   ├── slh-poseidon-gl/   # Rust Goldilocks Poseidon SLH-DSA signer (reference oracle)
│   ├── neo-bridge/        # Circom .r1cs + .wtns  →  Nightstream CCS
│   ├── neo-ivc/           # 7-step IVC orchestrator + Spartan2-GL finisher
│   └── neo-bench/         # Criterion + RSS harness, memo-number generator
├── circuits/              # copied from slh-dsa-circuit @ 03e7acc
├── scripts/
└── results/
    ├── raw/               # Criterion JSON + RSS traces (committed)
    └── tables/            # generated tables for MEMO.md (gitignored)
```

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.
