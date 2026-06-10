//! Single fold-step utilities — plan construction + R1CS preprocessing.
//!
//! Extracted from the inline body of `bin/rfp_smoke.rs` so the chain
//! orchestrator (`chain.rs`) and the end-to-end binary (`bin/rfp_smoke_full.rs`)
//! can both reach the same primitives without duplicating the F'-shell
//! configuration.
//!
//! The "step" itself is one call to `R1csChainBuilder::append_assignment` —
//! see `chain.rs` for the orchestrator that threads multiple appends through
//! one `R1csFPrimePreprocessing`.

use anyhow::Result;

use neo_fold_clean::engine::ccs_native::poseidon2::POSEIDON2_GOLDILOCKS_BITS;
use neo_fold_clean::frontends::f_prime::image::{
    FPrimeImageLayout, NifsCeClaimShape, NifsPayloadShape,
};
use neo_fold_clean::frontends::f_prime::recursive_plan::{
    build_recursive_step_image_config, AccumulatorPlanOptions, RecursiveStepImagePlan,
    StateXOutPlanOptions,
};
use neo_fold_clean::frontends::r1cs_f_prime::{self, R1csFPrimePreprocessing, SparseR1cs};
use neo_fold_clean::paper::f_prime::ring_action_trace::{LowNormEncoding, RingActionTraceLayout};

/// Mirror `BOUNDARY_BITS` from the Nightstream test (4 × 64 = 256).
pub const BOUNDARY_BITS: usize = 4 * POSEIDON2_GOLDILOCKS_BITS;

/// Plan options for the F'-shell.
///
/// Two profiles:
/// - **Single-step** ([`Self::SMOKE`]) — `c_data_entries = 2`, single-child
///   accumulator. Matches `make_small_plan` from
///   `nightstream/crates/neo-fold-clean/tests/system/r1cs_compiler.rs:75`.
///   Only valid for one `append_assignment` call before `finish`.
/// - **Multi-step** ([`Self::PRODUCTION_MULTISTEP`]) — production-params
///   accumulator (`c_data_entries = κ × D = 972`, `child_count = 14 =
///   K_RHO`) with the fully-populated `NifsCeClaimShape` parent fields.
///   Required as soon as N > 1; otherwise the second `append_assignment`
///   panics with `PostParentShapeMismatch`. Constants extracted from the
///   error surfaced by Nightstream's recursive-compile probe (the same
///   technique `make_tiny_lifecycle_plan` uses at line 580 of
///   `r1cs_compiler.rs`).
#[derive(Debug, Clone)]
pub struct StepPlanOptions {
    pub c_data_entries: usize,
    /// Child-count for the accumulator (1 for single-step, K_RHO=14 for multi-step).
    pub child_count: u64,
    /// Filled-in CeClaim shape (parent shape that subsequent
    /// `append_assignment` calls must match).
    pub parent_x_rows: usize,
    pub parent_x_active_cols: usize,
    pub parent_r_len: usize,
    pub parent_y_ring_inner_lens: Vec<usize>,
    pub parent_y_zcol_len: usize,
    pub parent_s_col_len: usize,
}

impl StepPlanOptions {
    /// Smallest single-child accumulator (one-step chains, smoke tests).
    pub fn smoke() -> Self {
        Self {
            c_data_entries: 2,
            child_count: 1,
            parent_x_rows: 0,
            parent_x_active_cols: 0,
            parent_r_len: 0,
            parent_y_ring_inner_lens: vec![],
            parent_y_zcol_len: 0,
            parent_s_col_len: 0,
        }
    }

    /// Production-params multi-step accumulator. Constants surfaced from
    /// `PostParentShapeMismatch` at production params:
    /// `c_data_entries = κ × D = 18 × 54 = 972`, `child_count = K_RHO = 14`,
    /// `x_rows = 54`, `x_active_cols = 5`, `r_len = s_col_len = 20`,
    /// `y_ring_inner_lens = [64; 8]`, `y_zcol_len = 64`.
    ///
    /// NOTE: `r_len` / `s_col_len` are **circuit-shape dependent** — the `20`
    /// here matches the shape this preset was originally probed against, but
    /// the actual value the second `append_assignment` produces depends on the
    /// step circuit. The `bench_ht_layer_gl` D4 step (m = 467,721) needs
    /// `r_len = s_col_len = 26`; pass `rfp_smoke_full --r-len 26` (which
    /// overrides both fields). When in doubt, run once and read the `actual`
    /// shape from the `PostParentShapeMismatch` error, then re-run with it.
    pub fn production_multistep() -> Self {
        Self {
            c_data_entries: 972,
            child_count: 14,
            parent_x_rows: 54,
            parent_x_active_cols: 5,
            parent_r_len: 20,
            parent_y_ring_inner_lens: vec![64; 8],
            parent_y_zcol_len: 64,
            parent_s_col_len: 20,
        }
    }
}

/// Build the `RecursiveStepImagePlan` for a fold step over an R1CS with
/// `m` wires and `m_in` public inputs. Bit-decomposes every wire (`limbs =
/// m × 64 + 1`) per the `r1cs_f_prime` frontend.
pub fn build_plan(m: usize, m_in: usize, opts: StepPlanOptions) -> RecursiveStepImagePlan {
    let limbs = m * POSEIDON2_GOLDILOCKS_BITS + 1;
    let ce_shape = NifsCeClaimShape {
        c_data_entries: opts.c_data_entries,
        x_rows: opts.parent_x_rows,
        x_active_cols: opts.parent_x_active_cols,
        r_len: opts.parent_r_len,
        y_ring_inner_lens: opts.parent_y_ring_inner_lens.clone(),
        y_zcol_len: opts.parent_y_zcol_len,
        s_col_len: opts.parent_s_col_len,
    };
    let probe_plan = RecursiveStepImagePlan {
        limbs,
        boundary_bits: BOUNDARY_BITS,
        kmul_count: 0,
        ring_action_pair_count: 0,
        ring_action_pair_layout: RingActionTraceLayout::new(
            LowNormEncoding::U64,
            LowNormEncoding::U64,
            LowNormEncoding::U64,
            LowNormEncoding::U64,
        ),
        sponge_transcript_permutes: 0,
        nifs_payload_shapes: vec![NifsPayloadShape::CeClaim(ce_shape)],
        accumulator: Some(AccumulatorPlanOptions {
            ce_claim_payload_index: 0,
            c_data_entries: opts.c_data_entries,
            child_count: opts.child_count,
            unified: true,
        }),
        state_x_out: None,
    };
    let probe_layout = FPrimeImageLayout::new(build_recursive_step_image_config(&probe_plan));
    let boundary_start = probe_layout.boundary.offset;
    let public_x_out_lane_bit_starts: [usize; 4] =
        std::array::from_fn(|i| boundary_start + i * POSEIDON2_GOLDILOCKS_BITS);

    let mut plan = probe_plan;
    plan.state_x_out = Some(StateXOutPlanOptions {
        pc: 1,
        public_x_out_lane_bit_starts,
        app_public_input_var_indices: (0..m_in).collect(),
    });
    plan
}

/// Preprocess a sparse R1CS for fold-step proving. Wraps Nightstream's
/// `r1cs_f_prime::preprocess_sparse_seeded` and translates its error type.
///
/// At HT-layer scale (486K R1CS, 467K wires → ~30M-row F'-shell), this is
/// the 86.7 s Ajtai-setup phase reported in `MEMO.md`.
pub fn preprocess_sparse(
    r1cs: &SparseR1cs,
    plan: &RecursiveStepImagePlan,
    seed: u64,
) -> Result<R1csFPrimePreprocessing> {
    r1cs_f_prime::preprocess_sparse_seeded(r1cs, plan, seed)
        .map_err(|e| anyhow::anyhow!("preprocess_sparse_seeded: {e:?}"))
}
