//! `slh-poseidon-gl` — CLI driver for the Goldilocks Poseidon SLH-DSA signer.
//!
//! Two subcommands:
//!   * `self-check`        — keygen + sign + (Rust) verify; prints the
//!                           derived public key and digest indices.
//!   * `emit-monolithic`   — sign a deterministic fixed message and write the
//!                           `main_poseidon_gl.circom` witness-input JSON
//!                           (`{ pk, msg, r, sig_fors, sig_ht }`).
//!
//! Seeds/message are derived deterministically from a `--seed` via splitmix64
//! so runs are reproducible without pulling in a hash dependency. Any seed
//! yields a valid keypair + signature; the field choice (Goldilocks) means
//! these witnesses are *not* interchangeable with the secq256r1 signer.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use slh_poseidon_gl::{
    ht_layer_witness_json, ht_layer_witnesses, keygen, sign, verify, witness_json,
};

#[derive(Parser)]
#[command(
    name = "slh-poseidon-gl",
    about = "Goldilocks Poseidon SLH-DSA-128s signer"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Keygen + sign + Rust verify (self-consistency check).
    SelfCheck {
        #[arg(long, default_value_t = 0)]
        seed: u64,
    },
    /// Sign a deterministic message and emit the main_poseidon_gl witness JSON.
    EmitMonolithic {
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(long, default_value = "input.json")]
        out: PathBuf,
    },
    /// Sign and emit the D=7 per-HT-layer witness JSONs (layer_0.json ..
    /// layer_6.json) in the bench_ht_layer_gl.circom layout, for the folded
    /// r1cs_f_prime chain. Asserts the layers chain to pk_root.
    EmitLayers {
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(long, default_value = "layers")]
        out_dir: PathBuf,
    },
}

/// splitmix64 — fill `n` bytes deterministically from `(seed, label)`.
fn expand(seed: u64, label: u64, out: &mut [u8]) {
    let mut x = seed ^ label.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for chunk in out.chunks_mut(8) {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

fn derive_inputs(seed: u64) -> ([u8; 16], [u8; 16], [u8; 16], [u8; 1024]) {
    let mut sk_seed = [0u8; 16];
    let mut pk_seed = [0u8; 16];
    let mut r = [0u8; 16];
    let mut msg = [0u8; 1024];
    expand(seed, 1, &mut sk_seed);
    expand(seed, 2, &mut pk_seed);
    expand(seed, 3, &mut r);
    expand(seed, 4, &mut msg);
    (sk_seed, pk_seed, r, msg)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::SelfCheck { seed } => {
            let (sk_seed, pk_seed, r, msg) = derive_inputs(seed);
            let t = Instant::now();
            let sk = keygen(sk_seed, pk_seed);
            let keygen_s = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let sig = sign(&sk, &msg, r);
            let sign_s = t.elapsed().as_secs_f64();
            let ok = verify(&sk.public_key(), &msg, &sig);
            println!("pk_seed = {}", hex(&sk.pk_seed));
            println!("pk_root = {}", hex(&sk.pk_root));
            println!("keygen  = {keygen_s:.2}s   sign = {sign_s:.2}s");
            println!("verify  = {}", if ok { "OK ✓" } else { "FAIL ✗" });
            if !ok {
                anyhow::bail!("self-check verification failed");
            }
        }
        Cmd::EmitMonolithic { seed, out } => {
            let (sk_seed, pk_seed, r, msg) = derive_inputs(seed);
            let t = Instant::now();
            let sk = keygen(sk_seed, pk_seed);
            let sig = sign(&sk, &msg, r);
            let elapsed = t.elapsed().as_secs_f64();
            if !verify(&sk.public_key(), &msg, &sig) {
                anyhow::bail!("internal error: emitted signature does not self-verify");
            }
            let v = witness_json(&sk.public_key(), &msg, &sig);
            if let Some(dir) = out.parent() {
                if !dir.as_os_str().is_empty() {
                    std::fs::create_dir_all(dir)
                        .with_context(|| format!("creating {}", dir.display()))?;
                }
            }
            std::fs::write(&out, serde_json::to_vec(&v)?)
                .with_context(|| format!("writing {}", out.display()))?;
            println!(
                "wrote {} (sign {elapsed:.2}s, self-verified ✓)",
                out.display()
            );
            println!("pk_root = {}", hex(&sk.pk_root));
        }
        Cmd::EmitLayers { seed, out_dir } => {
            let (sk_seed, pk_seed, r, msg) = derive_inputs(seed);
            let t = Instant::now();
            let sk = keygen(sk_seed, pk_seed);
            let sig = sign(&sk, &msg, r);
            let pk = sk.public_key();
            if !verify(&pk, &msg, &sig) {
                anyhow::bail!("internal error: signature does not self-verify");
            }
            let layers = ht_layer_witnesses(&pk, &msg, &sig);
            let elapsed = t.elapsed().as_secs_f64();

            // Chain invariant: each layer's next_root feeds the next, and the
            // top layer reconstructs pk_root (the same check HtVerify asserts).
            for j in 1..layers.len() {
                if layers[j].prev_root != layers[j - 1].next_root {
                    anyhow::bail!("layer {j} prev_root != layer {} next_root", j - 1);
                }
            }
            if layers.last().map(|w| w.next_root) != Some(sk.pk_root) {
                anyhow::bail!("top layer next_root != pk_root");
            }

            std::fs::create_dir_all(&out_dir)
                .with_context(|| format!("creating {}", out_dir.display()))?;
            for (j, w) in layers.iter().enumerate() {
                let path = out_dir.join(format!("layer_{j}.json"));
                std::fs::write(&path, serde_json::to_vec(&ht_layer_witness_json(w))?)
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            println!(
                "wrote {} layer witnesses to {} (sign {elapsed:.2}s, chains to pk_root ✓)",
                layers.len(),
                out_dir.display()
            );
            println!("pk_root = {}", hex(&sk.pk_root));
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
