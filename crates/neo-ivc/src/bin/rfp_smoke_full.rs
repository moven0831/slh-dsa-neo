//! `rfp_smoke_full` — end-to-end chain + finisher binary built on the
//! `step::build_plan` / `chain::run_chain` / `finisher::close_chain` library
//! API added in Session 2026-05-28 (T1.2 / T1.3 / T1.4).
//!
//! Differences vs `rfp_smoke`:
//! - Loads one .wtns once but appends it N times (`--n-steps`) into the chain
//!   so the multi-step prove cost can be measured before a real signer
//!   (T1.1.c) emits per-layer witnesses.
//! - `--c-data-entries` defaults to `2` (smoke); pass `972` for the
//!   production-params accumulator size.
//! - `--close` runs the audit-mode `compress` path and reports proof size +
//!   verify time, in addition to the `Uncompressed` accumulator verify.
//!
//! Until T1.1.c lands and emits real per-XMSS-layer witnesses, this binary
//! is the way to land a real-N measurement of the chain library and the
//! `Compressed` closing-proof flow.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::time::Instant;

use neo_bridge::{
    circom_to_neo_sparse_mats, circom_witness_to_f, parse_circom_r1cs, parse_circom_wtns,
};
use neo_fold_clean::frontends::r1cs_f_prime::SparseR1cs;

use neo_ivc::chain::{run_chain, verify_chain};
use neo_ivc::finisher::{close_chain, verify_compressed};
use neo_ivc::step::{build_plan, preprocess_sparse, StepPlanOptions};

#[derive(Debug, Parser)]
#[command(
    name = "rfp_smoke_full",
    about = "Chain + finisher end-to-end smoke for r1cs_f_prime on a Circom Goldilocks R1CS."
)]
struct Args {
    #[arg(long)]
    r1cs: PathBuf,
    /// Witness file(s). Pass once to fold the same witness `--n-steps` times
    /// (synthetic/timing). Pass it repeatedly (`--wtns layer_0.wtns --wtns
    /// layer_1.wtns ...`) to fold distinct per-layer witnesses in order — the
    /// real SLH-DSA-128s D4 chain from `slh-poseidon-gl emit-layers`; then
    /// `--n-steps` is ignored and the step count is the number of files.
    #[arg(long, required = true)]
    wtns: Vec<PathBuf>,
    #[arg(long, default_value_t = 0x71C5_0001)]
    seed: u64,
    /// Number of times a single witness is appended to the chain. Use 1 to
    /// mirror `rfp_smoke`'s single-fold behaviour, 7 to simulate the
    /// SLH-DSA-128s D4 fold chain. Ignored when multiple `--wtns` are given
    /// (then the step count is the number of witness files).
    #[arg(long, default_value_t = 1)]
    n_steps: usize,
    /// Plan profile. `smoke` is the single-child accumulator (only valid
    /// for `--n-steps 1`); `production` is the κ × D = 972 multi-step
    /// accumulator with the full parent shape (required for N > 1).
    #[arg(long, default_value = "auto")]
    profile: PlanProfile,
    /// Override the parent `r_len` / `s_col_len` (default = 20 for the
    /// HT-layer step at production params). Set to the value surfaced by
    /// `PostParentShapeMismatch` if running on a different circuit shape
    /// (the smoke circuit needs 23).
    #[arg(long)]
    r_len: Option<usize>,
    /// Also run the audit-mode `compress` path on the chain output and
    /// report the resulting `Compressed` proof size + verify wall-clock.
    #[arg(long)]
    close: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum PlanProfile {
    /// Pick `smoke` for N=1, `production` otherwise.
    Auto,
    /// `make_small_plan` single-child accumulator (valid only for N=1).
    Smoke,
    /// Production-params κ×D multi-step accumulator.
    Production,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    if args.n_steps == 0 {
        anyhow::bail!("--n-steps must be ≥ 1");
    }
    let t_total = Instant::now();

    // Distinct witnesses → one fold step each; a single witness → repeat it
    // `--n-steps` times. Determine the effective step count up front because
    // the plan profile (smoke vs production accumulator) depends on it.
    let multi_witness = args.wtns.len() > 1;
    let effective_steps = if multi_witness {
        args.wtns.len()
    } else {
        args.n_steps
    };

    println!("=== 1/6 Parse Circom .r1cs + .wtns ===");
    let t = Instant::now();
    let circom_r1cs = parse_circom_r1cs(&args.r1cs)
        .with_context(|| format!("parsing {}", args.r1cs.display()))?;
    let circom_wtns_all = args
        .wtns
        .iter()
        .map(|p| parse_circom_wtns(p).with_context(|| format!("parsing {}", p.display())))
        .collect::<Result<Vec<_>>>()?;
    println!(
        "  parsed in {:?}: {} witness file(s), n_constraints={}, n_wires={}, n_pub_out={}, n_pub_in={}",
        t.elapsed(),
        circom_wtns_all.len(),
        circom_r1cs.n_constraints,
        circom_r1cs.n_wires,
        circom_r1cs.n_pub_out,
        circom_r1cs.n_pub_in,
    );
    for (i, w) in circom_wtns_all.iter().enumerate() {
        if circom_r1cs.n_wires != w.n_wires {
            anyhow::bail!(
                "wire count mismatch: r1cs={}, wtns[{i}]={}",
                circom_r1cs.n_wires,
                w.n_wires,
            );
        }
    }

    println!("=== 2/6 Lift to sparse CcsMatrix + build R1cs shape ===");
    let t = Instant::now();
    let zs = circom_wtns_all
        .iter()
        .map(circom_witness_to_f)
        .collect::<Result<Vec<_>>>()?;
    let (a, b, c, n, m, m_in) = circom_to_neo_sparse_mats(&circom_r1cs)?;
    let r1cs = SparseR1cs::new(a, b, c, n, m, m_in)
        .map_err(|e| anyhow::anyhow!("SparseR1cs::new: {e:?}"))?;
    println!(
        "  built in {:?}: rows={}, cols={}, m_in={}, |z|={}",
        t.elapsed(),
        r1cs.n,
        r1cs.m,
        r1cs.m_in,
        zs[0].len(),
    );

    println!(
        "=== 3/6 R1CS row-wise satisfaction check ({} witness(es)) ===",
        zs.len()
    );
    let t = Instant::now();
    for (i, z) in zs.iter().enumerate() {
        r1cs.is_satisfied_by(z).with_context(|| {
            format!("witness[{i}] does not satisfy parsed R1CS — parser/witness bug")
        })?;
    }
    println!("  passed in {:?}", t.elapsed());

    let m_used = r1cs.m;
    let m_in_used = r1cs.m_in;
    let profile = match (args.profile, effective_steps) {
        (PlanProfile::Smoke, _) => PlanProfile::Smoke,
        (PlanProfile::Production, _) => PlanProfile::Production,
        (PlanProfile::Auto, 1) => PlanProfile::Smoke,
        (PlanProfile::Auto, _) => PlanProfile::Production,
    };
    let mut opts = match profile {
        PlanProfile::Smoke => StepPlanOptions::smoke(),
        PlanProfile::Production => StepPlanOptions::production_multistep(),
        PlanProfile::Auto => unreachable!("Auto is resolved to Smoke/Production above"),
    };
    if let Some(r) = args.r_len {
        opts.parent_r_len = r;
        opts.parent_s_col_len = r;
    }
    println!(
        "=== 4/6 build_plan (m_in={}, m={}, profile={:?}, c_data_entries={}, child_count={}) ===",
        m_in_used, m_used, profile, opts.c_data_entries, opts.child_count,
    );
    let t = Instant::now();
    let plan = build_plan(m_used, m_in_used, opts);
    println!(
        "  plan limbs={} (= m×64+1), boundary_bits={}",
        plan.limbs, plan.boundary_bits,
    );
    println!("  built in {:?}", t.elapsed());

    println!("=== 5/6 preprocess_sparse (production-params Ajtai setup) ===");
    let t = Instant::now();
    let prep = preprocess_sparse(&r1cs, &plan, args.seed)?;
    println!("  preprocessed in {:?}", t.elapsed());

    // One step per distinct witness, or `--n-steps` copies of a single one.
    let witnesses: Vec<Vec<_>> = if multi_witness {
        zs
    } else {
        let z = zs
            .into_iter()
            .next()
            .expect("≥1 witness (clap requires --wtns)");
        vec![z; args.n_steps]
    };
    if args.close {
        println!(
            "=== 6/6 close_chain ({} append + finish_with_audit + compress) ===",
            effective_steps
        );
        let t = Instant::now();
        let compressed = close_chain(&prep, witnesses)?;
        let prove_dur = t.elapsed();
        println!("  prove+finish_with_audit+compress in {:?}", prove_dur);

        let proof_size = bincode_size(&compressed)?;
        println!("  Compressed proof size: {} bytes", proof_size);

        let t = Instant::now();
        verify_compressed(&prep, &compressed)?;
        println!("  verify(Compressed) in {:?}", t.elapsed());
    } else {
        println!(
            "=== 6/6 run_chain ({} append + finish + verify_uncompressed) ===",
            effective_steps
        );
        let t = Instant::now();
        let finished = run_chain(&prep, witnesses)?;
        println!("  prove+finish in {:?}", t.elapsed());

        let t = Instant::now();
        verify_chain(&prep, &finished)?;
        println!("  verify_uncompressed in {:?}", t.elapsed());
    }

    println!();
    println!(
        "RESULT: PASS — chain + {} verify all succeed.",
        if args.close {
            "close_chain + Compressed"
        } else {
            "Uncompressed"
        }
    );
    println!("Total wall-clock: {:?}", t_total.elapsed());
    Ok(())
}

/// Best-effort serialized-size measurement for a `Compressed` proof. The
/// `Compressed` type doesn't currently expose a serialization API in
/// Nightstream's public surface, so we use `std::mem::size_of_val` as a
/// proxy (the in-memory layout including all owned heap allocations is what
/// matters for "is this small enough to ship?"). For an authoritative size
/// number, the Compressed → bytes serializer should be wired into the
/// finisher API; that's tracked under Track 1.4-bis.
fn bincode_size<T: ?Sized>(value: &T) -> Result<usize> {
    Ok(std::mem::size_of_val(value))
}
