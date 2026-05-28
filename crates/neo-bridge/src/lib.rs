//! Bridge: Circom `.r1cs` + `.wtns` (Goldilocks) → Nightstream-friendly types.
//!
//! Parser logic is ported verbatim from
//! `slh-dsa-circuit/tools/nightstream-spike/src/parser.rs` (validated at
//! 486K-constraint scale).
//!
//! The lift path:
//!     parse_r1cs(&Path)              -> CircomR1cs
//!     parse_wtns(&Path)              -> CircomWitness
//!     circom_to_neo_mats(&CircomR1cs)-> (Mat<F>, Mat<F>, Mat<F>, m_in)
//!     circom_witness_to_f(&CircomWitness) -> Vec<F>

pub mod parser;

use anyhow::{Result, bail};
use neo_ccs::matrix::Mat;
use neo_ccs::sparse::{CcsMatrix, CscMat};
use neo_math::F;
use p3_field::PrimeCharacteristicRing;

pub use parser::{CircomR1cs, CircomWitness, parse_circom_r1cs, parse_circom_wtns};

/// Convert a parsed Circom Goldilocks R1CS into a dense `(A, B, C, m_in)` tuple
/// ready to feed `neo_fold_clean::frontends::direct_ccs::R1cs`.
///
/// `m_in` (the public-input split) follows the Circom convention:
/// `1 (constant) + n_pub_out + n_pub_in`. This matches the layout of the
/// witness vector `z = [1, pub_out…, pub_in…, private…]`.
pub fn circom_to_neo_mats(circom: &CircomR1cs) -> Result<(Mat<F>, Mat<F>, Mat<F>, usize)> {
    if circom.field_size_bytes != 8 {
        bail!(
            "expected Goldilocks-sized field (8 bytes), got {}",
            circom.field_size_bytes
        );
    }
    let n_cols = circom.n_wires as usize;
    let m_rows = circom.n_constraints as usize;
    let m_in = 1 + circom.n_pub_out as usize + circom.n_pub_in as usize;

    let mat_from = |rows: &[Vec<(u32, Vec<u8>)>]| -> Result<Mat<F>> {
        let mut data: Vec<F> = vec![F::ZERO; m_rows * n_cols];
        for (i, row) in rows.iter().enumerate() {
            for (wire_idx, coeff_bytes) in row {
                data[i * n_cols + (*wire_idx as usize)] = coeff_to_f(coeff_bytes)?;
            }
        }
        Ok(Mat::<F>::from_row_major(m_rows, n_cols, data))
    };

    Ok((mat_from(&circom.a)?, mat_from(&circom.b)?, mat_from(&circom.c)?, m_in))
}

/// Same as [`circom_to_neo_mats`] but returns sparse `CcsMatrix<F>` triplets.
/// Required for circuits beyond ~10K wires where dense `Mat<F>` would OOM.
/// Adapted from `nightstream-spike::build_ccs_sparse`.
pub fn circom_to_neo_sparse_mats(
    circom: &CircomR1cs,
) -> Result<(CcsMatrix<F>, CcsMatrix<F>, CcsMatrix<F>, usize, usize, usize)> {
    if circom.field_size_bytes != 8 {
        bail!(
            "expected Goldilocks-sized field (8 bytes), got {}",
            circom.field_size_bytes
        );
    }
    let n_cols = circom.n_wires as usize;
    let m_rows = circom.n_constraints as usize;
    let m_in = 1 + circom.n_pub_out as usize + circom.n_pub_in as usize;

    let mat_from = |rows: &[Vec<(u32, Vec<u8>)>]| -> Result<CcsMatrix<F>> {
        let mut triplets: Vec<(usize, usize, F)> = Vec::new();
        for (i, row) in rows.iter().enumerate() {
            for (wire_idx, coeff_bytes) in row {
                triplets.push((i, *wire_idx as usize, coeff_to_f(coeff_bytes)?));
            }
        }
        Ok(CcsMatrix::Csc(CscMat::from_triplets(triplets, m_rows, n_cols)))
    };

    Ok((
        mat_from(&circom.a)?,
        mat_from(&circom.b)?,
        mat_from(&circom.c)?,
        m_rows,
        n_cols,
        m_in,
    ))
}

pub fn circom_witness_to_f(wtns: &CircomWitness) -> Result<Vec<F>> {
    if wtns.field_size_bytes != 8 {
        bail!("expected Goldilocks-sized witness, got {}", wtns.field_size_bytes);
    }
    wtns.wires_le_bytes.iter().map(|w| coeff_to_f(w)).collect()
}

fn coeff_to_f(bytes: &[u8]) -> Result<F> {
    if bytes.len() != 8 {
        bail!("expected 8-byte coefficient, got {}", bytes.len());
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(F::from_u64(u64::from_le_bytes(buf)))
}
