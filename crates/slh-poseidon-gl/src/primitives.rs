//! SLH-DSA primitives F, H, T_k, T_len, H_msg via Goldilocks Poseidon.
//!
//! Mirrors `circuits/poseidon_gl/hashes_gl.circom`. Domain-separation tags:
//!   F = 0, H = 1, T_k = 2, T_len = 3, H_msg = 4.
//!
//! T_k / T_len are implemented as binary Merkle trees of `PoseidonGl(4)`
//! nodes (the spec deviation documented in slh-dsa-circuit/CLAUDE.md). The
//! 7-element ADRS slot abstracts FIPS 205's 32-byte address into seven
//! Goldilocks sub-fields: layer, tree_high (upper 8B of tree), tree_low
//! (lower 4B), type, keypair, chain (or tree_height for FORS), hash (or
//! tree_index for FORS).
//!
//! `slh_hmsg` is deferred to T1.1.c — `hashes_gl.circom` does not define
//! `SlhHMsg` (D4 fold doesn't need it); the Rust signer will port the
//! construction used by the secq256r1 Poseidon family.

use crate::poseidon::{
    pack_bytes16_to_2fe, poseidon_gl, poseidon_gl_hash30, poseidon_gl_reduce,
    poseidon_gl_sponge14, unpack_fe2_to_bytes16,
};

const TAG_F: u64 = 0;
const TAG_H: u64 = 1;
const TAG_TK: u64 = 2;
const TAG_TLEN: u64 = 3;
// TAG_HMSG = 4 is documented in the Circom hashes_gl.circom header but the
// secq256r1 SlhHMsg construction (which Goldilocks mirrors) embeds its own
// sub-tags 0/1 inside PoseidonGlHash30 rather than passing an outer tag.

/// FIPS 205 ADRS (32 bytes) projected into 7 Goldilocks field elements.
/// Field names match the unsuffixed Circom signals in `hashes_gl.circom`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Adrs {
    pub layer: u64,
    pub tree_high: u64,
    pub tree_low: u64,
    pub type_: u64,
    pub keypair: u64,
    pub chain: u64,
    pub hash: u64,
}

/// SLH `F` primitive: F(pk_seed, ADRS, M) where M is 16 bytes.
/// One `PoseidonGl(12)` over tag‖seed‖ADRS‖M.
pub fn slh_f(pk_seed: &[u8; 16], adrs: &Adrs, m: &[u8; 16]) -> [u8; 16] {
    let (pk_lo, pk_hi) = pack_bytes16_to_2fe(pk_seed);
    let (m_lo, m_hi) = pack_bytes16_to_2fe(m);
    let (out_lo, out_hi) = poseidon_gl(&[
        TAG_F,
        pk_lo, pk_hi,
        adrs.layer, adrs.tree_high, adrs.tree_low,
        adrs.type_, adrs.keypair, adrs.chain, adrs.hash,
        m_lo, m_hi,
    ]);
    unpack_fe2_to_bytes16(out_lo, out_hi)
}

/// SLH `H` primitive: H(pk_seed, ADRS, M1‖M2) where each Mi is 16 bytes.
/// One `PoseidonGlSponge14` (arity-14, two permutations) over tag‖seed‖ADRS‖M1‖M2.
pub fn slh_h(pk_seed: &[u8; 16], adrs: &Adrs, m: &[u8; 32]) -> [u8; 16] {
    let (pk_lo, pk_hi) = pack_bytes16_to_2fe(pk_seed);
    let (m1_lo, m1_hi) = pack_bytes16_to_2fe(m[..16].try_into().unwrap());
    let (m2_lo, m2_hi) = pack_bytes16_to_2fe(m[16..].try_into().unwrap());
    let (out_lo, out_hi) = poseidon_gl_sponge14(&[
        TAG_H,
        pk_lo, pk_hi,
        adrs.layer, adrs.tree_high, adrs.tree_low,
        adrs.type_, adrs.keypair, adrs.chain, adrs.hash,
        m1_lo, m1_hi, m2_lo, m2_hi,
    ]);
    unpack_fe2_to_bytes16(out_lo, out_hi)
}

fn slh_tk_or_tlen(pk_seed: &[u8; 16], adrs: &Adrs, leaves: &[[u8; 16]], tag: u64) -> [u8; 16] {
    assert!(!leaves.is_empty(), "T_k / T_len need at least one leaf");
    let (leaves_lo, leaves_hi): (Vec<u64>, Vec<u64>) =
        leaves.iter().map(pack_bytes16_to_2fe).unzip();
    let (red_lo, red_hi) = poseidon_gl_reduce(&leaves_lo, &leaves_hi);

    let (pk_lo, pk_hi) = pack_bytes16_to_2fe(pk_seed);
    let (out_lo, out_hi) = poseidon_gl(&[
        tag,
        pk_lo, pk_hi,
        adrs.layer, adrs.tree_high, adrs.tree_low,
        adrs.type_, adrs.keypair, adrs.chain, adrs.hash,
        red_lo, red_hi,
    ]);
    unpack_fe2_to_bytes16(out_lo, out_hi)
}

/// SLH `T_k` primitive: FORS k-tree-roots compression (k = 14 for SLH-DSA-128s).
/// Binary Merkle reduce of `leaves` (each 16 B) via `PoseidonGl(4)`, then
/// `PoseidonGl(12)` over tag‖seed‖ADRS‖reduce_out.
pub fn slh_tk(pk_seed: &[u8; 16], adrs: &Adrs, leaves: &[[u8; 16]]) -> [u8; 16] {
    slh_tk_or_tlen(pk_seed, adrs, leaves, TAG_TK)
}

/// SLH `T_len` primitive: WOTS+ chain-pubkey compression (len = 35 for SLH-DSA-128s, w=16).
/// Same construction as `slh_tk` but with `TAG_TLEN`.
pub fn slh_tlen(pk_seed: &[u8; 16], adrs: &Adrs, leaves: &[[u8; 16]]) -> [u8; 16] {
    slh_tk_or_tlen(pk_seed, adrs, leaves, TAG_TLEN)
}

/// SLH `H_msg` primitive: message-digest used by the full verifier.
/// Mirrors `SlhHMsg` in `circuits/poseidon_gl/hashes_gl.circom`:
///   - Pack r / pk_seed / pk_root each into a `(lo, hi)` Goldilocks pair.
///   - Pack the 1024-byte message into 64 such pairs.
///   - Merkle-reduce the 64 pairs via `poseidon_gl_reduce`.
///   - Feed [r, pk_seed, pk_root, msg_digest] (4 pairs = 8 FEs) into
///     `poseidon_gl_hash30(4)` → 30 bytes.
///
/// Domain separation: `poseidon_gl_hash30` uses internal sub-tags 0/1 — no
/// outer HMsg=4 tag, matching the secq256r1 family's convention.
pub fn slh_hmsg(
    r: &[u8; 16],
    pk_seed: &[u8; 16],
    pk_root: &[u8; 16],
    m: &[u8; 1024],
) -> [u8; 30] {
    let (r_lo, r_hi) = pack_bytes16_to_2fe(r);
    let (pk_seed_lo, pk_seed_hi) = pack_bytes16_to_2fe(pk_seed);
    let (pk_root_lo, pk_root_hi) = pack_bytes16_to_2fe(pk_root);

    // Pack m[1024] into 64 (lo, hi) pairs.
    let (m_lo, m_hi): (Vec<u64>, Vec<u64>) = (0..64)
        .map(|i| {
            let chunk: &[u8; 16] = (&m[i * 16..(i + 1) * 16])
                .try_into()
                .expect("16-byte slice");
            pack_bytes16_to_2fe(chunk)
        })
        .unzip();
    let (red_lo, red_hi) = poseidon_gl_reduce(&m_lo, &m_hi);

    poseidon_gl_hash30(
        &[r_lo, pk_seed_lo, pk_root_lo, red_lo],
        &[r_hi, pk_seed_hi, pk_root_hi, red_hi],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pk_seed = [1, 2, ..., 16] — matches build/poseidon_gl_bench/bench_slh_*_gl/input.json.
    fn make_pk_seed() -> [u8; 16] {
        let mut pk = [0u8; 16];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        pk
    }

    /// m = [17, 18, ..., 32]
    fn make_m16() -> [u8; 16] {
        let mut m = [0u8; 16];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i + 17) as u8;
        }
        m
    }

    /// m = [17, 18, ..., 48]
    fn make_m32() -> [u8; 32] {
        let mut m = [0u8; 32];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i + 17) as u8;
        }
        m
    }

    /// 14 leaves of bytes [17, ...] (matches bench_slh_tk_gl input.json)
    fn make_leaves_14() -> [[u8; 16]; 14] {
        let mut leaves = [[0u8; 16]; 14];
        for i in 0..14 {
            for j in 0..16 {
                leaves[i][j] = (i * 16 + j + 17) as u8;
            }
        }
        leaves
    }

    // Expected outputs come from `snarkjs wtns export json` on the existing
    // witness.wtns files in slh-dsa-circuit/build/poseidon_gl_bench. The .wtns
    // layout is: w[0]=1, w[1..17]=out[0..16], then inputs+internals.

    #[test]
    fn slh_f_matches_circom_witness() {
        let pk_seed = make_pk_seed();
        let adrs = Adrs::default();
        let m = make_m16();
        let got = slh_f(&pk_seed, &adrs, &m);
        let expected: [u8; 16] = [
            5, 218, 204, 1, 93, 95, 43, 5, 151, 141, 5, 11, 63, 71, 184, 43,
        ];
        assert_eq!(got, expected, "SlhF output mismatch vs Circom witness");
    }

    #[test]
    fn slh_h_matches_circom_witness() {
        let pk_seed = make_pk_seed();
        let adrs = Adrs::default();
        let m = make_m32();
        let got = slh_h(&pk_seed, &adrs, &m);
        let expected: [u8; 16] = [
            62, 172, 188, 151, 104, 142, 124, 217, 245, 206, 242, 138, 165, 47, 60, 70,
        ];
        assert_eq!(got, expected, "SlhH output mismatch vs Circom witness");
    }

    #[test]
    fn slh_tk_matches_circom_witness() {
        let pk_seed = make_pk_seed();
        let adrs = Adrs::default();
        let leaves = make_leaves_14();
        let got = slh_tk(&pk_seed, &adrs, &leaves);
        let expected: [u8; 16] = [
            39, 15, 78, 107, 241, 142, 239, 30, 33, 19, 86, 174, 143, 207, 241, 11,
        ];
        assert_eq!(got, expected, "SlhTk output mismatch vs Circom witness");
    }

    // No Circom witness for bench_slh_tlen_gl exists yet (only .r1cs is built).
    // Validate structurally: deterministic, ADRS-dependent, and TAG-distinct from T_k.
    #[test]
    fn slh_hmsg_matches_circom_witness() {
        // Inputs match `build/poseidon_gl_bench/bench_slh_hmsg_gl/`'s
        // generate_witness.js run with input.json = {r: 1..16, pk_seed: [9;16],
        // pk_root: [42;16], m: [0;1024]}. Expected bytes via `snarkjs wtns export
        // json /tmp/slh_hmsg.wtns` taking w[1..=30].
        let r = make_pk_seed();         // [1..=16]
        let pk_seed = [9u8; 16];
        let pk_root = [42u8; 16];
        let m = [0u8; 1024];
        let got = slh_hmsg(&r, &pk_seed, &pk_root, &m);
        let expected: [u8; 30] = [
            71, 45, 32, 230, 198, 15, 38, 186, 91, 58,
            126, 130, 6, 89, 5, 212, 159, 209, 9, 176,
            184, 29, 191, 94, 114, 85, 197, 22, 98, 173,
        ];
        assert_eq!(got, expected, "SlhHMsg output mismatch vs Circom witness");
    }

    #[test]
    fn slh_hmsg_each_input_matters() {
        // Vary each input independently — a slot-swap or ignored-slot bug
        // in poseidon_gl_hash30 would let two of these come out equal.
        let r = make_pk_seed();
        let pk_seed = [9u8; 16];
        let pk_root = [42u8; 16];
        let m = [0u8; 1024];

        let baseline = slh_hmsg(&r, &pk_seed, &pk_root, &m);

        let mut r2 = r;       r2[0] ^= 1;
        let mut pk_seed2 = pk_seed; pk_seed2[0] ^= 1;
        let mut pk_root2 = pk_root; pk_root2[0] ^= 1;
        let mut m2 = m;       m2[123] = 7;

        assert_ne!(baseline, slh_hmsg(&r2, &pk_seed,  &pk_root,  &m),  "r ignored");
        assert_ne!(baseline, slh_hmsg(&r,  &pk_seed2, &pk_root,  &m),  "pk_seed ignored");
        assert_ne!(baseline, slh_hmsg(&r,  &pk_seed,  &pk_root2, &m),  "pk_root ignored");
        assert_ne!(baseline, slh_hmsg(&r,  &pk_seed,  &pk_root,  &m2), "m ignored");

        // Slot-swap: r vs pk_seed should yield different outputs.
        assert_ne!(
            slh_hmsg(&r, &pk_seed, &pk_root, &m),
            slh_hmsg(&pk_seed, &r, &pk_root, &m),
            "swapping r and pk_seed should change the digest"
        );
    }

    #[test]
    fn slh_tlen_deterministic_and_distinguishable() {
        let pk_seed = make_pk_seed();
        let mut leaves = vec![[0u8; 16]; 35];
        for i in 0..35 {
            for j in 0..16 {
                leaves[i][j] = (i * 16 + j + 17) as u8;
            }
        }
        let adrs0 = Adrs::default();
        let adrs_layer1 = Adrs { layer: 1, ..Adrs::default() };

        let out_a = slh_tlen(&pk_seed, &adrs0, &leaves);
        let out_b = slh_tlen(&pk_seed, &adrs0, &leaves);
        let out_c = slh_tlen(&pk_seed, &adrs_layer1, &leaves);
        assert_eq!(out_a, out_b, "slh_tlen not deterministic");
        assert_ne!(out_a, out_c, "slh_tlen does not depend on ADRS.layer");

        let leaves14: Vec<[u8; 16]> = leaves[..14].to_vec();
        let tk = slh_tk(&pk_seed, &adrs0, &leaves14);
        let tlen14 = slh_tlen(&pk_seed, &adrs0, &leaves14);
        assert_ne!(tk, tlen14, "TAG_TK and TAG_TLEN must domain-separate");
    }
}
