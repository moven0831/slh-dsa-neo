# Memo: Folded SLH-DSA-128s on Neo — Real Numbers

> **Status: work in progress.** This memo will be backfilled by `scripts/repro.sh` once Phases 1–6 land. The skeleton documents what we will measure and how; numbers below are TODO until then.

## TL;DR

TODO — one paragraph headline: prove time, peak RSS, proof size, verifier time vs the companion-repo secq256r1 monolithic Spartan2 baseline (16.18 s prove / 5.41 GB RSS / 208.8 KB proof).

## Setup

- **Host:** M3 / 24 GB, macOS 14+, single-thread
- **Toolchain:** Rust stable 1.88+
- **Circom:** 2.2.3
- **Nightstream commit:** `755c1595f3b34b5c2bc9eaa50417cdf9dfb871ec`
- **slh-dsa-circuit commit:** `03e7acc3593ff7b7e16180e092f677904ac22d07`
- **Step circuit:** `ht_layer_step.circom` — 485,930 R1CS, 467,721 wires (Goldilocks Poseidon, Plonky2 t=12 / 30 rounds)
- **Fold depth:** 7 (D4: one fold per XMSS layer)
- **Closing SNARK:** Nightstream Spartan2 over Goldilocks

## Methodology

Each measurement is reported as median ± stdev over **3 cold + 3 warm runs**, mirroring the protocol used by the companion repo `slh-dsa-128s-poseidon-bench`.

- **Cold:** fresh process, OS file caches dropped via `sync && sudo purge` between runs
- **Warm:** same process, three consecutive iterations after one untimed warm-up
- **Wall-clock:** `Instant::now()` brackets in Rust
- **Peak RSS:** sampled via `getrusage(RUSAGE_SELF)` at phase boundaries; cross-checked against `/usr/bin/time -l`
- **Proof size:** serialized bytes via Nightstream's native `to_bytes()` (no further compression)

## Numbers

### Per-fold-step (HT-layer, 486K R1CS)

TODO — Phase 3 output.

| Phase | Time (median ± stdev) | Peak RSS | Notes |
|---|---|---|---|
| Witness gen (circom) | TODO | – | per-layer |
| R1CS → CCS lift | TODO | TODO | one-shot |
| NIFS prove | TODO | TODO | `FoldingMode::Optimized` |
| NIFS verify | TODO | TODO | |

### 7-step IVC chain

TODO — Phase 4 output.

| Step | Cumulative time | Per-step delta | Peak RSS | Accumulator size |
|---|---|---|---|---|
| z₀ → z₁ | TODO | TODO | TODO | TODO |
| z₁ → z₂ | TODO | TODO | TODO | TODO |
| z₂ → z₃ | TODO | TODO | TODO | TODO |
| z₃ → z₄ | TODO | TODO | TODO | TODO |
| z₄ → z₅ | TODO | TODO | TODO | TODO |
| z₅ → z₆ | TODO | TODO | TODO | TODO |
| z₆ → z₇ | TODO | TODO | TODO | TODO |

### Spartan2-GL finisher

TODO — Phase 5 output.

| Phase | Time | Peak RSS | Artifact | Size |
|---|---|---|---|---|
| Setup (one-time) | TODO | TODO | Proving key | TODO |
| Prove | TODO | TODO | **Proof** | TODO |
| Verify (fresh process) | TODO | TODO | – | – |

### Side-by-side vs companion

| Path | Field | Strategy | Prove | Peak RSS | Proof | Verify |
|---|---|---|---|---|---|---|
| `slh-dsa-128s-poseidon-bench` (companion) | secq256r1 | Monolithic Spartan2+Hyrax (OpenAC) | 16,184 ms | 5.41 GB | 208.8 KB | 9,522 ms |
| `slh-dsa-neo` (this) | Goldilocks | Neo 7-fold + Spartan2-GL | TODO | TODO | TODO | TODO |

> **Caveat — not apples-to-apples.** The two paths verify the same SLH-DSA-128s semantics but on different fields, with different Poseidon variants in-circuit, different commitment schemes, and different closing SNARK engineering. The comparison is "two viable Poseidon-SLH-DSA approaches", not "fold beats monolith on identical config".

## Open Questions

- Real-witness coefficient magnitude vs lattice gadget norms — does the folding prover cost depend on witness L∞ in a measurable way at this scale?
- Per-step prove time variance across the 7 layers (each layer's authentication path has different active bits)
- Spartan2-GL setup cost amortization — is the proving key reusable across signatures or per-witness?

## Reproduction Recipe

```sh
git clone https://github.com/moven0831/slh-dsa-neo.git
cd slh-dsa-neo
bash scripts/repro.sh   # ~30 min on M3, produces all numbers in this memo from scratch
```

For full methodology see [`README.md`](README.md). For the planning trail see `slh-dsa-circuit/research/folding/` at commit `03e7acc`.
