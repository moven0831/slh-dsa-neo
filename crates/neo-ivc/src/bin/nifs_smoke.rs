//! Phase-2 smoke gate: Nightstream NIFS prove + verify on a Circom-derived
//! Goldilocks R1CS. This is the **Week-3 forcing condition** — if this passes
//! at the smoke scale (440 R1CS), we promote to the 486K HT-layer-step circuit
//! in Phase 3.
//!
//! Pattern lifted from Nightstream's own
//! `crates/neo-fold-clean/tests/nifs/r1cs_isolated.rs` (the canonical isolated
//! NIFS round-trip test the Nightstream maintainers wrote to diagnose the
//! lifecycle bug they were chasing).

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::time::Instant;

use neo_fold_clean::engine::transcript::Transcript;
use neo_fold_clean::frontends::direct_ccs::{self, R1cs};
use neo_fold_clean::paper::construction2::RunningInstance;
use neo_fold_clean::paper::nifs;

use neo_bridge::{circom_to_neo_mats, circom_witness_to_f, parse_circom_r1cs, parse_circom_wtns};

#[derive(Debug, Parser)]
#[command(
    name = "nifs_smoke",
    about = "Nightstream NIFS prove+verify smoke gate on a Circom .r1cs/.wtns pair."
)]
struct Args {
    #[arg(long)]
    r1cs: PathBuf,
    #[arg(long)]
    wtns: PathBuf,
    /// Preprocessing seed (any u64 works; tests use 42).
    #[arg(long, default_value_t = 42)]
    seed: u64,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    println!("=== 1/6 Parse Circom .r1cs + .wtns ===");
    let t = Instant::now();
    let circom_r1cs = parse_circom_r1cs(&args.r1cs)
        .with_context(|| format!("parsing {}", args.r1cs.display()))?;
    let circom_wtns = parse_circom_wtns(&args.wtns)
        .with_context(|| format!("parsing {}", args.wtns.display()))?;
    println!(
        "  parsed in {:?}: n_constraints={}, n_wires={}/{}, n_pub_out={}, n_pub_in={}",
        t.elapsed(),
        circom_r1cs.n_constraints,
        circom_r1cs.n_wires,
        circom_wtns.n_wires,
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

    println!("=== 2/6 Lift to neo_ccs Mat<F> + build direct_ccs::R1cs ===");
    let t = Instant::now();
    let (a, b, c, m_in) = circom_to_neo_mats(&circom_r1cs)?;
    let z = circom_witness_to_f(&circom_wtns)?;
    let r1cs = R1cs { a, b, c, m_in };
    println!(
        "  built in {:?}: rows={}, cols={}, m_in={}, |z|={}",
        t.elapsed(),
        r1cs.n(),
        r1cs.m(),
        r1cs.m_in,
        z.len(),
    );

    println!("=== 3/6 Sanity: R1CS row-wise satisfaction check ===");
    let t = Instant::now();
    r1cs.is_satisfied_by(&z)
        .context("Circom witness does not satisfy parsed R1CS row-wise — parser or witness bug")?;
    println!("  passed in {:?}", t.elapsed());

    println!("=== 4/6 Preprocess (Ajtai setup, seed = {}) ===", args.seed);
    let t = Instant::now();
    let prep =
        direct_ccs::preprocess_seeded(&r1cs, args.seed).context("direct_ccs::preprocess_seeded")?;
    println!("  preprocessed in {:?}", t.elapsed());

    println!("=== 5/6 NIFS prove ===");
    let t = Instant::now();
    let instance = direct_ccs::build_instance(&prep, &r1cs, &z)
        .context("direct_ccs::build_instance — z does not satisfy R1CS")?;
    let fresh_claims = vec![instance.claim.clone()];
    let running = RunningInstance::default();

    let mut prover_tr = Transcript::session();
    let (next_running, proof) = nifs::prove(
        &mut prover_tr,
        &prep.params,
        prep.structure(),
        prep.optimized_cache(),
        &prep.log,
        prep.mix_rhos_commits,
        prep.combine_b_pows,
        vec![instance],
        &running,
    )
    .context("NIFS prove")?;
    println!("  prove succeeded in {:?}", t.elapsed());

    println!("=== 6/6 NIFS verify ===");
    let t = Instant::now();
    let mut verifier_tr = Transcript::session();
    let verified = nifs::verify(
        &mut verifier_tr,
        &prep.params,
        prep.structure(),
        prep.optimized_cache(),
        prep.mix_rhos_commits,
        prep.combine_b_pows,
        &fresh_claims,
        &running,
        &proof,
    )
    .context("NIFS verify")?;
    println!("  verify returned Ok in {:?}", t.elapsed());

    if verified.claims != next_running.claims {
        println!();
        println!(
            "RESULT: FAIL — verifier returned Ok but verified.claims != next_running.claims (transcript divergence)."
        );
        std::process::exit(1);
    }

    println!();
    println!(
        "RESULT: PASS — Nightstream NIFS prove + verify both succeed on the smoke circuit."
    );
    println!("        Week-3 forcing condition CLEARED. Phase 3 (486K HT-layer) is unblocked.");
    Ok(())
}
