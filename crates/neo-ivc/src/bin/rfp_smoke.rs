//! Pivot A: r1cs_f_prime end-to-end smoke. Same Circom-derived R1CS as
//! `nifs_smoke`, but goes through the bit-decomposing `r1cs_f_prime`
//! frontend rather than `direct_ccs`. Goal: confirm the protocol actually
//! runs prove → finish → verify on a Circom Goldilocks R1CS at production
//! security params, and measure the wall-clock + peak RSS for one fold step.
//!
//! Plan construction mirrors `make_small_plan` from
//! `nightstream/crates/neo-fold-clean/tests/system/r1cs_compiler.rs`
//! (TEST_C_DATA_ENTRIES = 2, single-child accumulator).
//!
//! API trail:
//!   parse Circom .r1cs/.wtns
//!   → neo_bridge::circom_to_neo_mats (Mat<F> triplet)
//!   → direct_ccs::R1cs { a, b, c, m_in }
//!   → r1cs_f_prime::preprocess_seeded(&r1cs, &plan, seed)
//!   → R1csChainBuilder::new(&prep).append_assignment(z)
//!   → chain.finish() → Uncompressed
//!   → lifecycle::verify_uncompressed(&prep.prep, &finished)

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::time::Instant;

use neo_fold_clean::engine::ccs_native::poseidon2::POSEIDON2_GOLDILOCKS_BITS;
use neo_fold_clean::frontends::direct_ccs::R1cs;
use neo_fold_clean::frontends::f_prime::image::{
    FPrimeImageLayout, NifsCeClaimShape, NifsPayloadShape,
};
use neo_fold_clean::frontends::f_prime::recursive_plan::{
    build_recursive_step_image_config, AccumulatorPlanOptions, RecursiveStepImagePlan,
    StateXOutPlanOptions,
};
use neo_fold_clean::frontends::r1cs_f_prime::{self, R1csChainBuilder, SparseR1cs};
use neo_fold_clean::paper::f_prime::ring_action_trace::{LowNormEncoding, RingActionTraceLayout};
use neo_fold_clean::verify_uncompressed;

use neo_bridge::{
    circom_to_neo_mats, circom_to_neo_sparse_mats, circom_witness_to_f, parse_circom_r1cs,
    parse_circom_wtns,
};

/// Mirror `BOUNDARY_BITS` from the Nightstream test (4 × 64 = 256).
const BOUNDARY_BITS: usize = 4 * POSEIDON2_GOLDILOCKS_BITS;

/// Mirror `TEST_C_DATA_ENTRIES` from `make_small_plan`. Smallest single-child
/// accumulator the F'-shell will accept.
const TEST_C_DATA_ENTRIES: usize = 2;

#[derive(Debug, Parser)]
#[command(
    name = "rfp_smoke",
    about = "r1cs_f_prime prove + finish + verify smoke on a Circom Goldilocks R1CS."
)]
struct Args {
    #[arg(long)]
    r1cs: PathBuf,
    #[arg(long)]
    wtns: PathBuf,
    #[arg(long, default_value_t = 0x71C5_0001)]
    seed: u64,
    /// Use the sparse R1CS path (required for circuits beyond ~10K wires;
    /// dense Mat<F> would OOM at HT-layer scale).
    #[arg(long)]
    sparse: bool,
}

/// Adapted from `make_small_plan` in nightstream-{rev 755c1595}'s
/// `crates/neo-fold-clean/tests/system/r1cs_compiler.rs:75`. Sizes the F'
/// shell minimally for one fold step over an R1CS with `m` variables and
/// `m_in` public inputs.
fn make_small_plan(m: usize, m_in: usize) -> RecursiveStepImagePlan {
    // Bit-decompose every variable: limbs = m × 64 + 1.
    let limbs = m * POSEIDON2_GOLDILOCKS_BITS + 1;
    let ce_shape = NifsCeClaimShape {
        c_data_entries: TEST_C_DATA_ENTRIES,
        x_rows: 0,
        x_active_cols: 0,
        r_len: 0,
        y_ring_inner_lens: vec![],
        y_zcol_len: 0,
        s_col_len: 0,
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
            c_data_entries: TEST_C_DATA_ENTRIES,
            child_count: 1,
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

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let t_total = Instant::now();

    println!("=== 1/7 Parse Circom .r1cs + .wtns ===");
    let t = Instant::now();
    let circom_r1cs = parse_circom_r1cs(&args.r1cs)
        .with_context(|| format!("parsing {}", args.r1cs.display()))?;
    let circom_wtns = parse_circom_wtns(&args.wtns)
        .with_context(|| format!("parsing {}", args.wtns.display()))?;
    println!(
        "  parsed in {:?}: n_constraints={}, n_wires={}, n_pub_out={}, n_pub_in={}",
        t.elapsed(),
        circom_r1cs.n_constraints,
        circom_r1cs.n_wires,
        circom_r1cs.n_pub_out,
        circom_r1cs.n_pub_in,
    );
    if circom_r1cs.n_wires != circom_wtns.n_wires {
        anyhow::bail!(
            "wire count mismatch: r1cs={}, wtns={}",
            circom_r1cs.n_wires,
            circom_wtns.n_wires
        );
    }

    println!(
        "=== 2/7 Lift to neo_ccs {} + build R1cs shape ===",
        if args.sparse {
            "CcsMatrix (sparse CSC)"
        } else {
            "Mat<F> (dense)"
        }
    );
    let t = Instant::now();
    let z = circom_witness_to_f(&circom_wtns)?;
    if args.sparse {
        let (a, b, c, n, m, m_in) = circom_to_neo_sparse_mats(&circom_r1cs)?;
        let r1cs = SparseR1cs::new(a, b, c, n, m, m_in)
            .map_err(|e| anyhow::anyhow!("SparseR1cs::new: {e:?}"))?;
        println!(
            "  built in {:?}: rows={}, cols={}, m_in={}, |z|={}",
            t.elapsed(),
            r1cs.n,
            r1cs.m,
            r1cs.m_in,
            z.len(),
        );

        println!("=== 3/7 Sanity: R1CS row-wise satisfaction check ===");
        let t = Instant::now();
        r1cs.is_satisfied_by(&z)
            .context("Circom witness does not satisfy parsed R1CS row-wise — parser/witness bug")?;
        println!("  passed in {:?}", t.elapsed());

        let m_used = r1cs.m;
        let m_in_used = r1cs.m_in;
        println!(
            "=== 4/7 Build RecursiveStepImagePlan (m_in={}, m={}) ===",
            m_in_used, m_used
        );
        let t = Instant::now();
        let plan = make_small_plan(m_used, m_in_used);
        println!(
            "  plan limbs={} (=m×64+1), boundary_bits={}, c_data_entries={}",
            plan.limbs, plan.boundary_bits, TEST_C_DATA_ENTRIES,
        );
        println!("  built in {:?}", t.elapsed());

        println!("=== 5/7 r1cs_f_prime::preprocess_sparse_seeded (production params) ===");
        let t = Instant::now();
        let prep = r1cs_f_prime::preprocess_sparse_seeded(&r1cs, &plan, args.seed)
            .map_err(|e| anyhow::anyhow!("r1cs_f_prime::preprocess_sparse_seeded: {e:?}"))?;
        println!("  preprocessed in {:?}", t.elapsed());

        return run_chain(prep, z, t_total);
    } else {
        let (a, b, c, m_in) = circom_to_neo_mats(&circom_r1cs)?;
        let r1cs = R1cs { a, b, c, m_in };
        println!(
            "  built in {:?}: rows={}, cols={}, m_in={}, |z|={}",
            t.elapsed(),
            r1cs.n(),
            r1cs.m(),
            r1cs.m_in,
            z.len(),
        );

        println!("=== 3/7 Sanity: R1CS row-wise satisfaction check ===");
        let t = Instant::now();
        r1cs.is_satisfied_by(&z)
            .context("Circom witness does not satisfy parsed R1CS row-wise — parser/witness bug")?;
        println!("  passed in {:?}", t.elapsed());

        let m_used = r1cs.m();
        let m_in_used = m_in;
        println!(
            "=== 4/7 Build RecursiveStepImagePlan (m_in={}, m={}) ===",
            m_in_used, m_used
        );
        let t = Instant::now();
        let plan = make_small_plan(m_used, m_in_used);
        println!(
            "  plan limbs={} (=m×64+1), boundary_bits={}, c_data_entries={}",
            plan.limbs, plan.boundary_bits, TEST_C_DATA_ENTRIES,
        );
        println!("  built in {:?}", t.elapsed());

        println!("=== 5/7 r1cs_f_prime::preprocess_seeded (production params) ===");
        let t = Instant::now();
        let prep = r1cs_f_prime::preprocess_seeded(&r1cs, &plan, args.seed)
            .map_err(|e| anyhow::anyhow!("r1cs_f_prime::preprocess_seeded: {e:?}"))?;
        println!("  preprocessed in {:?}", t.elapsed());

        return run_chain(prep, z, t_total);
    }
}

fn run_chain(
    prep: r1cs_f_prime::R1csFPrimePreprocessing,
    z: Vec<neo_math::F>,
    t_total: Instant,
) -> Result<()> {
    println!("=== 6/7 R1csChainBuilder: append_assignment → finish ===");
    let t = Instant::now();
    let mut chain = R1csChainBuilder::new(&prep)
        .map_err(|e| anyhow::anyhow!("R1csChainBuilder::new: {e:?}"))?;
    let _compiled = chain
        .append_assignment(z)
        .map_err(|e| anyhow::anyhow!("append_assignment: {e:?}"))?;
    let finished = chain
        .finish()
        .map_err(|e| anyhow::anyhow!("finish: {e:?}"))?;
    println!("  prove+finish in {:?}", t.elapsed());

    println!("=== 7/7 lifecycle::verify_uncompressed ===");
    let t = Instant::now();
    verify_uncompressed(&prep.prep, &finished)
        .map_err(|e| anyhow::anyhow!("verify_uncompressed: {e:?}"))?;
    println!("  verify_uncompressed returned Ok in {:?}", t.elapsed());

    println!();
    println!("RESULT: PASS — r1cs_f_prime prove + finish + verify all succeed.");
    println!("Total wall-clock: {:?}", t_total.elapsed());
    Ok(())
}
