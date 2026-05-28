//! 7-step IVC orchestrator over Nightstream/Neo + Spartan2-Goldilocks finisher.
//!
//! Folding boundary = D4 (per-XMSS-layer). Step circuit = `ht_layer_step.circom`
//! (485,930 R1CS, see `slh-dsa-circuit/circuits/poseidon_gl/bench/`).
//! State `z_i` = (layer index, current node hash, authentication path tail).
//!
//! Phases:
//!     2. Smoke gate     — single NIFS prove+verify on 440-R1CS smoke circuit
//!     3. Single fold    — one HT-layer step at 486K R1CS
//!     4. 7-step chain   — fold all 7 XMSS layers into one CeClaim
//!     5. Finisher       — Spartan2-GL close on accumulated CeClaim

pub mod step;
pub mod chain;
pub mod finisher;

// TODO: Phases 2–5.
