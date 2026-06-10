//! Closing the IVC chain into a verifiable compressed proof.
//!
//! **Status at Nightstream `755c1595`**: the `lifecycle::compress` seam is
//! wired but **the PR5 decider is intentionally stubbed** —
//! `compress(prep, audit)` returns `decider::Error::Unsupported` at
//! runtime. From `neo-fold-clean/src/lifecycle/compress.rs:4-5`:
//!
//! > "The seam is wired, but the PR5 decider is not implemented yet, so
//! >  public `compress` / compressed `verify` return
//! >  `decider::Error::Unsupported`."
//!
//! So at this pinned commit, the only verifiable artifact for an
//! `r1cs_f_prime` chain is the `Uncompressed` accumulator (via
//! `chain.finish()` + `verify_uncompressed`, see `chain.rs`).
//!
//! `close_chain` below preserves the API for when upstream lands the
//! decider, and surfaces a clear runtime error today.
//!
//! Forward plan (Track 1.4-bis):
//! - **Either** upgrade Nightstream to a tag/commit where `decider::prove`
//!   is implemented, OR
//! - **Custom-plumb** `lifecycle::build_decider_statement` →
//!   `decider::Statement` → standalone
//!   `spartan2::R1CSSNARK<GoldilocksP3MerkleMleEngine>` (the same Spartan2-GL
//!   adapter Track 2.2 builds for the monolithic baseline). The
//!   `build_decider_statement` function IS implemented (just `compress`
//!   isn't wired through to a real prover).
//!
//! Nightstream's own `finish_*_with_spartan` entry points only exist for
//! `direct_ccs` and `rv32im` — there's no analog for `r1cs_f_prime`.

use anyhow::Result;
use neo_fold_clean::frontends::r1cs_f_prime::R1csFPrimePreprocessing;
use neo_fold_clean::lifecycle::{compress, verify, Compressed};
use neo_math::F;

use crate::chain::build_and_append;

/// Run the chain and produce a `Compressed` proof in one go. Mirrors
/// [`chain::run_chain`](crate::chain::run_chain) but uses
/// `finish_with_audit` instead of `finish`, then `compress` to close into a
/// verifiable compressed artifact.
pub fn close_chain(prep: &R1csFPrimePreprocessing, witnesses: Vec<Vec<F>>) -> Result<Compressed> {
    let audit = build_and_append(prep, "close_chain", witnesses)?
        .finish_with_audit()
        .map_err(|e| anyhow::anyhow!("chain.finish_with_audit: {e:?}"))?;
    compress(&prep.prep, audit).map_err(|e| anyhow::anyhow!("compress: {e:?}"))
}

/// Verify a compressed chain proof.
pub fn verify_compressed(prep: &R1csFPrimePreprocessing, proof: &Compressed) -> Result<()> {
    verify(&prep.prep, proof).map_err(|e| anyhow::anyhow!("verify(Compressed): {e:?}"))
}
