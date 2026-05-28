//! Multi-step IVC chain orchestrator: appends each witness into one
//! `R1csChainBuilder`, calls `finish()`, returns the verifiable
//! `Uncompressed` accumulator.
//!
//! For the SLH-DSA-128s D4 fold (7 XMSS layers per signature), each
//! witness is a per-layer witness emitted by `slh-poseidon-gl` against the
//! same `bench_ht_layer_gl.r1cs` step shape. All 7 share one preprocessed
//! plan.

use anyhow::Result;
use neo_fold_clean::frontends::r1cs_f_prime::{R1csChainBuilder, R1csFPrimePreprocessing};
use neo_fold_clean::lifecycle::Uncompressed;
use neo_fold_clean::verify_uncompressed;
use neo_math::F;

/// Build a chain and append every witness. Shared between `run_chain` and
/// `close_chain` (`finisher.rs`) — the only thing that differs after this is
/// the closing call (`finish` vs `finish_with_audit`).
pub(crate) fn build_and_append<'a>(
    prep: &'a R1csFPrimePreprocessing,
    caller: &'static str,
    witnesses: Vec<Vec<F>>,
) -> Result<R1csChainBuilder<'a>> {
    if witnesses.is_empty() {
        anyhow::bail!("{caller}: witnesses must be non-empty");
    }
    let mut chain = R1csChainBuilder::new(prep)
        .map_err(|e| anyhow::anyhow!("R1csChainBuilder::new: {e:?}"))?;
    for (i, z) in witnesses.into_iter().enumerate() {
        chain
            .append_assignment(z)
            .map_err(|e| anyhow::anyhow!("append_assignment[{i}]: {e:?}"))?;
    }
    Ok(chain)
}

/// Run a multi-step chain: append each witness, then finish. Returns the
/// uncompressed accumulator (verifiable in O(1) via [`verify_chain`]).
///
/// One-step usage matches the current `rfp_smoke` behaviour. Multi-step
/// usage is the Track 1.3 deliverable — the same `prep` is shared across
/// all appends because the step circuit shape is fixed.
pub fn run_chain(
    prep: &R1csFPrimePreprocessing,
    witnesses: Vec<Vec<F>>,
) -> Result<Uncompressed> {
    build_and_append(prep, "run_chain", witnesses)?
        .finish()
        .map_err(|e| anyhow::anyhow!("chain.finish: {e:?}"))
}

/// Verify a chain output (`Uncompressed`).
pub fn verify_chain(prep: &R1csFPrimePreprocessing, finished: &Uncompressed) -> Result<()> {
    verify_uncompressed(&prep.prep, finished)
        .map_err(|e| anyhow::anyhow!("verify_uncompressed: {e:?}"))
}
