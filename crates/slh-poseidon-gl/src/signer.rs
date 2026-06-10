//! FIPS 205 SLH-DSA-128s signer + verifier with Goldilocks Poseidon.
//!
//! Control flow mirrors `slh-dsa-circuit/scripts/poseidon_sign.mjs` (the
//! Poseidon-family signer that drives the secq256r1 `main_poseidon.circom`),
//! with the secq256r1 hash family swapped for the Goldilocks Poseidon
//! primitives in [`crate::primitives`]. Those primitives are byte-validated
//! against `circuits/poseidon_gl/bench/bench_slh_*_gl.circom`, so a faithful
//! port of the control flow produces a witness the monolithic
//! `main_poseidon_gl.circom` verifier accepts (`valid == 1`).
//!
//! The signer and the circuit share the *same* `circuits/common/` verifier
//! templates (`wots / fors / xmss / ht / digest`); the only swap is the hash
//! family. Every ADRS field, auth-path direction and tree-index expression
//! below is matched to those templates — see the per-function references.
//!
//! `verify` re-implements the circuit's verification (H_msg → ParseDigest →
//! ForsPkFromSig → HtVerify) purely in Rust as a fast self-check. The
//! authoritative oracle remains the compiled circuit's witness generator.

use rayon::prelude::*;

use crate::poseidon::{pack_bytes16_to_2fe, poseidon_gl, unpack_fe2_to_bytes16};
use crate::primitives::{slh_f, slh_h, slh_hmsg, slh_tk, slh_tlen, Adrs};

// ---------------------------------------------------------------------------
// SLH-DSA-128s parameters (FIPS 205 Table 2, the "small" Category-1 set).
// ---------------------------------------------------------------------------

/// Hash output length in bytes (n).
pub const N: usize = 16;
/// Hypertree layers (d).
pub const D: usize = 7;
/// XMSS tree height per layer (h').
pub const HPRIME: usize = 9;
/// FORS tree height (a).
pub const A_FORS: usize = 12;
/// Number of FORS trees (k).
pub const K_FORS: usize = 14;
/// WOTS+ chain count (len), for w = 16.
pub const LEN: usize = 35;
/// WOTS+ chain length minus one (w - 1).
const WOTS_MAX: usize = 15;

// ADRS `type` codes — match `circuits/common/adrs.circom` / the verifier
// templates. WOTS_PRF / FORS_PRF / PRF_TAG are signer-private (the verifier
// never recomputes the PRF; it consumes the chain-start / leaf-sk values
// directly), so their exact values only need to be self-consistent here.
const WOTS_HASH: u64 = 0;
const WOTS_PK: u64 = 1;
const TREE: u64 = 2;
const FORS_TREE: u64 = 3;
const FORS_ROOTS: u64 = 4;
const WOTS_PRF: u64 = 5;
const FORS_PRF: u64 = 6;
/// Domain tag for the signer-private secret-key PRF.
const PRF_TAG: u64 = 99;

// ---------------------------------------------------------------------------
// Key + signature types
// ---------------------------------------------------------------------------

/// SLH-DSA-128s secret key: the two 16-byte seeds plus the cached public
/// root (so signing doesn't re-run keygen).
#[derive(Clone, Debug)]
pub struct SecretKey {
    pub sk_seed: [u8; N],
    pub pk_seed: [u8; N],
    pub pk_root: [u8; N],
}

/// SLH-DSA-128s public key: `pk_seed || pk_root` (32 bytes total).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub pk_seed: [u8; N],
    pub pk_root: [u8; N],
}

impl SecretKey {
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            pk_seed: self.pk_seed,
            pk_root: self.pk_root,
        }
    }
}

/// SLH-DSA-128s signature in the layout `main_poseidon_gl.circom` consumes:
/// `R[16] || sig_fors[14][13][16] || sig_ht[7][44][16]`.
#[derive(Clone, Debug)]
pub struct Signature {
    /// H_msg randomizer.
    pub r: [u8; N],
    /// FORS signature: 14 trees, each `leaf_sk + 12 auth-path nodes` = 13 × 16B.
    pub sig_fors: Vec<[[u8; N]; A_FORS + 1]>,
    /// Hypertree signature: 7 layers, each `35 WOTS chains + 9 XMSS auth nodes` = 44 × 16B.
    pub sig_ht: Vec<[[u8; N]; LEN + HPRIME]>,
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/// Signer-private secret-value PRF: `PoseidonGl(PRF_TAG ‖ sk_seed ‖ ADRS)`,
/// low 128 bits as 16 bytes. Not part of the verifier (FIPS 205 PRF is
/// signing-only — see slh-dsa-circuit CLAUDE.md §"Spec deviations").
fn prf_sk(sk_seed: &[u8; N], adrs: &Adrs) -> [u8; N] {
    let (sk_lo, sk_hi) = pack_bytes16_to_2fe(sk_seed);
    let (out_lo, out_hi) = poseidon_gl(&[
        PRF_TAG,
        sk_lo,
        sk_hi,
        adrs.layer,
        adrs.tree_high,
        adrs.tree_low,
        adrs.type_,
        adrs.keypair,
        adrs.chain,
        adrs.hash,
    ]);
    unpack_fe2_to_bytes16(out_lo, out_hi)
}

/// Concatenate two 16-byte halves into the 32-byte input `slh_h` expects.
#[inline]
fn join(left: &[u8; N], right: &[u8; N]) -> [u8; 2 * N] {
    let mut m = [0u8; 2 * N];
    m[..N].copy_from_slice(left);
    m[N..].copy_from_slice(right);
    m
}

/// Full WOTS+ public key for one leaf: chain all `LEN` chains the full
/// `WOTS_MAX` steps (hash addresses `0..15`), then compress with T_len.
/// Matches `WotsPkFromSig` (chain pubkey = position 15) + the chain-start
/// PRF used by the signer.
fn wots_pk_full(
    pk_seed: &[u8; N],
    sk_seed: &[u8; N],
    layer: u64,
    tree_low: u64,
    keypair: u64,
) -> [u8; N] {
    let mut ends = [[0u8; N]; LEN];
    for (i, end) in ends.iter_mut().enumerate() {
        let prf_adrs = Adrs {
            layer,
            tree_high: 0,
            tree_low,
            type_: WOTS_PRF,
            keypair,
            chain: i as u64,
            hash: 0,
        };
        let mut cur = prf_sk(sk_seed, &prf_adrs);
        for k in 0..WOTS_MAX as u64 {
            let adrs = Adrs {
                layer,
                tree_high: 0,
                tree_low,
                type_: WOTS_HASH,
                keypair,
                chain: i as u64,
                hash: k,
            };
            cur = slh_f(pk_seed, &adrs, &cur);
        }
        *end = cur;
    }
    let pk_adrs = Adrs {
        layer,
        tree_high: 0,
        tree_low,
        type_: WOTS_PK,
        keypair,
        chain: 0,
        hash: 0,
    };
    slh_tlen(pk_seed, &pk_adrs, &ends)
}

/// Build the full XMSS Merkle tree at `(layer, tree_low)` and return all
/// levels (level 0 = the 512 WOTS pubkeys). Node `n` at level `z` carries
/// ADRS `{type=TREE, chain=z, hash=n}` and combines children `2n‖2n+1` —
/// matching `XmssPkFromSig`'s walk. Leaves are computed in parallel
/// (the ~2M-permutation hot path).
fn xmss_levels(
    pk_seed: &[u8; N],
    sk_seed: &[u8; N],
    layer: u64,
    tree_low: u64,
) -> Vec<Vec<[u8; N]>> {
    let num_leaves = 1usize << HPRIME;
    let leaves: Vec<[u8; N]> = (0..num_leaves)
        .into_par_iter()
        .map(|kp| wots_pk_full(pk_seed, sk_seed, layer, tree_low, kp as u64))
        .collect();

    let mut levels = vec![leaves];
    for z in 1..=HPRIME {
        let prev = &levels[z - 1];
        let cur: Vec<[u8; N]> = (0..prev.len() / 2)
            .map(|n| {
                let adrs = Adrs {
                    layer,
                    tree_high: 0,
                    tree_low,
                    type_: TREE,
                    keypair: 0,
                    chain: z as u64,
                    hash: n as u64,
                };
                slh_h(pk_seed, &adrs, &join(&prev[2 * n], &prev[2 * n + 1]))
            })
            .collect();
        levels.push(cur);
    }
    levels
}

/// XMSS auth path for `idx_leaf`: at level `k` the sibling of the path node
/// (whose index is `idx_leaf >> k`) is `levels[k][(idx_leaf >> k) ^ 1]`.
fn xmss_auth_path(levels: &[Vec<[u8; N]>], idx_leaf: u64) -> [[u8; N]; HPRIME] {
    let mut auth = [[0u8; N]; HPRIME];
    let mut idx = idx_leaf as usize;
    for (k, entry) in auth.iter_mut().enumerate() {
        *entry = levels[k][idx ^ 1];
        idx >>= 1;
    }
    auth
}

/// Build a full FORS tree (`fors_idx`) and return all levels. Leaf `j` =
/// `F(sk_j)` with global tree-index `fors_idx*4096 + j`; internal node `n`
/// at level `z` carries `{type=FORS_TREE, chain=z, hash=fors_idx*(4096>>z)+n}`
/// — matching `ForsPkFromSig`'s `tree_index_shifted`. Leaves in parallel.
fn fors_levels(
    pk_seed: &[u8; N],
    sk_seed: &[u8; N],
    idx_tree: u64,
    keypair: u64,
    fors_idx: u64,
) -> Vec<Vec<[u8; N]>> {
    let num_leaves = 1usize << A_FORS;
    let leaves: Vec<[u8; N]> = (0..num_leaves)
        .into_par_iter()
        .map(|j| {
            let prf_adrs = Adrs {
                layer: 0,
                tree_high: 0,
                tree_low: idx_tree,
                type_: FORS_PRF,
                keypair,
                chain: fors_idx,
                hash: j as u64,
            };
            let sk = prf_sk(sk_seed, &prf_adrs);
            let leaf_adrs = Adrs {
                layer: 0,
                tree_high: 0,
                tree_low: idx_tree,
                type_: FORS_TREE,
                keypair,
                chain: 0,
                hash: fors_idx * num_leaves as u64 + j as u64,
            };
            slh_f(pk_seed, &leaf_adrs, &sk)
        })
        .collect();

    let mut levels = vec![leaves];
    for z in 1..=A_FORS {
        let prev = &levels[z - 1];
        let cur: Vec<[u8; N]> = (0..prev.len() / 2)
            .map(|n| {
                let adrs = Adrs {
                    layer: 0,
                    tree_high: 0,
                    tree_low: idx_tree,
                    type_: FORS_TREE,
                    keypair,
                    chain: z as u64,
                    hash: fors_idx * (num_leaves as u64 >> z) + n as u64,
                };
                slh_h(pk_seed, &adrs, &join(&prev[2 * n], &prev[2 * n + 1]))
            })
            .collect();
        levels.push(cur);
    }
    levels
}

/// `Base2bWithCsum` (digest.circom): 16-byte digest → 35 4-bit WOTS chunks
/// (32 message nibbles MSB-first + 3 checksum nibbles).
fn base2b_with_csum(digest: &[u8; N]) -> [u8; LEN] {
    let mut chunks = [0u8; LEN];
    for i in 0..N {
        chunks[2 * i] = (digest[i] >> 4) & 0xf;
        chunks[2 * i + 1] = digest[i] & 0xf;
    }
    let mut csum: u32 = 0;
    for c in &chunks[..32] {
        csum += (WOTS_MAX as u32) - *c as u32;
    }
    chunks[32] = ((csum >> 8) & 0x1) as u8;
    chunks[33] = ((csum >> 4) & 0xf) as u8;
    chunks[34] = (csum & 0xf) as u8;
    chunks
}

/// `ParseDigest` (digest.circom): 30-byte H_msg digest → 14 12-bit FORS
/// indices, 54-bit `idx_tree`, 9-bit `idx_leaf`.
fn parse_digest(digest: &[u8; 30]) -> ([u64; K_FORS], u64, u64) {
    let mut md = [0u64; K_FORS];
    for (c, slot) in md.iter_mut().enumerate() {
        let mut val = 0u64;
        for j in 0..12 {
            let be_pos = 12 * c + j;
            let byte_idx = be_pos >> 3;
            let bit_le = 7 - (be_pos & 7);
            let bit = (digest[byte_idx] >> bit_le) & 1;
            val += (bit as u64) << (11 - j);
        }
        *slot = val;
    }
    let mut idx_tree: u64 = 0;
    for i in 0..7 {
        idx_tree = (idx_tree << 8) | digest[21 + i] as u64;
    }
    idx_tree &= (1u64 << 54) - 1;
    let idx_leaf = (((digest[28] as u64) << 8) | digest[29] as u64) & 0x1ff;
    (md, idx_tree, idx_leaf)
}

// ---------------------------------------------------------------------------
// Public API: keygen / sign / verify
// ---------------------------------------------------------------------------

/// Generate a keypair from the two seeds. `pk_root` is the root of the top
/// XMSS tree (layer d-1, tree address 0) — FIPS 205 §6.1 slh_keygen_internal.
pub fn keygen(sk_seed: [u8; N], pk_seed: [u8; N]) -> SecretKey {
    let levels = xmss_levels(&pk_seed, &sk_seed, (D - 1) as u64, 0);
    let pk_root = levels[HPRIME][0];
    SecretKey {
        sk_seed,
        pk_seed,
        pk_root,
    }
}

/// Sign `msg` (fixed 1024 bytes) with randomizer `r`. FIPS 205 §10.2
/// slh_sign_internal: H_msg → FORS sign → HT sign.
pub fn sign(sk: &SecretKey, msg: &[u8; 1024], r: [u8; N]) -> Signature {
    let pk_seed = &sk.pk_seed;
    let sk_seed = &sk.sk_seed;

    // H_msg → indices.
    let digest = slh_hmsg(&r, pk_seed, &sk.pk_root, msg);
    let (md_indices, idx_tree, idx_leaf) = parse_digest(&digest);

    // FORS sign: one tree per md index; collect roots for pk_fors.
    let mut sig_fors: Vec<[[u8; N]; A_FORS + 1]> = Vec::with_capacity(K_FORS);
    let mut fors_roots: Vec<[u8; N]> = Vec::with_capacity(K_FORS);
    for i in 0..K_FORS {
        let levels = fors_levels(pk_seed, sk_seed, idx_tree, idx_leaf, i as u64);
        let leaf_idx = md_indices[i] as usize;

        let mut sig_i = [[0u8; N]; A_FORS + 1];
        let prf_adrs = Adrs {
            layer: 0,
            tree_high: 0,
            tree_low: idx_tree,
            type_: FORS_PRF,
            keypair: idx_leaf,
            chain: i as u64,
            hash: md_indices[i],
        };
        sig_i[0] = prf_sk(sk_seed, &prf_adrs);
        let mut idx = leaf_idx;
        for z in 0..A_FORS {
            sig_i[z + 1] = levels[z][idx ^ 1];
            idx >>= 1;
        }
        sig_fors.push(sig_i);
        fors_roots.push(levels[A_FORS][0]);
    }

    // pk_fors = T_k(fors_roots).
    let fors_adrs = Adrs {
        layer: 0,
        tree_high: 0,
        tree_low: idx_tree,
        type_: FORS_ROOTS,
        keypair: idx_leaf,
        chain: 0,
        hash: 0,
    };
    let pk_fors = slh_tk(pk_seed, &fors_adrs, &fors_roots);

    // HT sign: WOTS-sign layer_msg at each layer, append the XMSS auth path.
    let mut sig_ht: Vec<[[u8; N]; LEN + HPRIME]> = Vec::with_capacity(D);
    let mut layer_msg = pk_fors;
    let mut cur_idx_tree = idx_tree;
    let mut cur_idx_leaf = idx_leaf;
    for j in 0..D {
        let levels = xmss_levels(pk_seed, sk_seed, j as u64, cur_idx_tree);
        let chunks = base2b_with_csum(&layer_msg);

        let mut sig_j = [[0u8; N]; LEN + HPRIME];
        for i in 0..LEN {
            let prf_adrs = Adrs {
                layer: j as u64,
                tree_high: 0,
                tree_low: cur_idx_tree,
                type_: WOTS_PRF,
                keypair: cur_idx_leaf,
                chain: i as u64,
                hash: 0,
            };
            let mut cur = prf_sk(sk_seed, &prf_adrs);
            // WOTS sig value = chain position `chunks[i]` (hash addresses 0..chunks[i]-1).
            for k in 0..chunks[i] as u64 {
                let adrs = Adrs {
                    layer: j as u64,
                    tree_high: 0,
                    tree_low: cur_idx_tree,
                    type_: WOTS_HASH,
                    keypair: cur_idx_leaf,
                    chain: i as u64,
                    hash: k,
                };
                cur = slh_f(pk_seed, &adrs, &cur);
            }
            sig_j[i] = cur;
        }
        let auth = xmss_auth_path(&levels, cur_idx_leaf);
        sig_j[LEN..].copy_from_slice(&auth);
        sig_ht.push(sig_j);

        if j < D - 1 {
            layer_msg = levels[HPRIME][0];
            cur_idx_leaf = cur_idx_tree & 0x1ff;
            cur_idx_tree >>= HPRIME;
        }
    }

    Signature {
        r,
        sig_fors,
        sig_ht,
    }
}

// ---------------------------------------------------------------------------
// Verification — Rust mirror of the circuit (self-check; circuit is oracle).
// ---------------------------------------------------------------------------

/// `WotsPkFromSig`: continue each chain from `sig[i]` (at position
/// `chunks[i]`) to position 15, then T_len.
fn wots_pk_from_sig(
    pk_seed: &[u8; N],
    layer: u64,
    tree_low: u64,
    keypair: u64,
    chunks: &[u8; LEN],
    sig: &[[u8; N]],
) -> [u8; N] {
    let mut ends = [[0u8; N]; LEN];
    for (i, end) in ends.iter_mut().enumerate() {
        let mut cur = sig[i];
        let start = chunks[i] as u64;
        for k in 0..(WOTS_MAX as u64 - start) {
            let adrs = Adrs {
                layer,
                tree_high: 0,
                tree_low,
                type_: WOTS_HASH,
                keypair,
                chain: i as u64,
                hash: start + k,
            };
            cur = slh_f(pk_seed, &adrs, &cur);
        }
        *end = cur;
    }
    let pk_adrs = Adrs {
        layer,
        tree_high: 0,
        tree_low,
        type_: WOTS_PK,
        keypair,
        chain: 0,
        hash: 0,
    };
    slh_tlen(pk_seed, &pk_adrs, &ends)
}

/// `XmssPkFromSig`: walk the leaf up `HPRIME` levels with the auth path.
fn xmss_root_from_sig(
    pk_seed: &[u8; N],
    layer: u64,
    tree_low: u64,
    idx_leaf: u64,
    leaf: &[u8; N],
    auth: &[[u8; N]],
) -> [u8; N] {
    let mut node = *leaf;
    for k in 0..HPRIME {
        let bit = (idx_leaf >> k) & 1;
        let (left, right) = if bit == 0 {
            (node, auth[k])
        } else {
            (auth[k], node)
        };
        let adrs = Adrs {
            layer,
            tree_high: 0,
            tree_low,
            type_: TREE,
            keypair: 0,
            chain: (k + 1) as u64,
            hash: idx_leaf >> (k + 1),
        };
        node = slh_h(pk_seed, &adrs, &join(&left, &right));
    }
    node
}

/// `ForsPkFromSig`: reconstruct each FORS root then T_k.
fn fors_pk_from_sig(
    pk_seed: &[u8; N],
    idx_tree: u64,
    idx_leaf: u64,
    md_indices: &[u64; K_FORS],
    sig_fors: &[[[u8; N]; A_FORS + 1]],
) -> [u8; N] {
    let mut roots: Vec<[u8; N]> = Vec::with_capacity(K_FORS);
    for i in 0..K_FORS {
        let leaf_adrs = Adrs {
            layer: 0,
            tree_high: 0,
            tree_low: idx_tree,
            type_: FORS_TREE,
            keypair: idx_leaf,
            chain: 0,
            hash: i as u64 * 4096 + md_indices[i],
        };
        let mut node = slh_f(pk_seed, &leaf_adrs, &sig_fors[i][0]);
        for z in 1..=A_FORS {
            let bit = (md_indices[i] >> (z - 1)) & 1;
            let (left, right) = if bit == 0 {
                (node, sig_fors[i][z])
            } else {
                (sig_fors[i][z], node)
            };
            let adrs = Adrs {
                layer: 0,
                tree_high: 0,
                tree_low: idx_tree,
                type_: FORS_TREE,
                keypair: idx_leaf,
                chain: z as u64,
                hash: i as u64 * (1 << (12 - z)) + (md_indices[i] >> z),
            };
            node = slh_h(pk_seed, &adrs, &join(&left, &right));
        }
        roots.push(node);
    }
    let adrs = Adrs {
        layer: 0,
        tree_high: 0,
        tree_low: idx_tree,
        type_: FORS_ROOTS,
        keypair: idx_leaf,
        chain: 0,
        hash: 0,
    };
    slh_tk(pk_seed, &adrs, &roots)
}

/// Verify a signature exactly as `SlhDsaVerify` does, returning whether the
/// reconstructed top XMSS root equals `pk_root`.
pub fn verify(pk: &PublicKey, msg: &[u8; 1024], sig: &Signature) -> bool {
    if sig.sig_fors.len() != K_FORS || sig.sig_ht.len() != D {
        return false;
    }

    let digest = slh_hmsg(&sig.r, &pk.pk_seed, &pk.pk_root, msg);
    let (md_indices, idx_tree, idx_leaf) = parse_digest(&digest);

    let fors_pk = fors_pk_from_sig(&pk.pk_seed, idx_tree, idx_leaf, &md_indices, &sig.sig_fors);

    let mut layer_msg = fors_pk;
    let mut node = [0u8; N];
    for j in 0..D {
        let (tree_low, leaf) = if j == 0 {
            (idx_tree, idx_leaf)
        } else {
            (
                idx_tree >> (HPRIME * j),
                (idx_tree >> (HPRIME * (j - 1))) & 0x1ff,
            )
        };
        let chunks = base2b_with_csum(&layer_msg);
        let wots_pk = wots_pk_from_sig(
            &pk.pk_seed,
            j as u64,
            tree_low,
            leaf,
            &chunks,
            &sig.sig_ht[j][..LEN],
        );
        node = xmss_root_from_sig(
            &pk.pk_seed,
            j as u64,
            tree_low,
            leaf,
            &wots_pk,
            &sig.sig_ht[j][LEN..],
        );
        layer_msg = node;
    }
    node == pk.pk_root
}

// ---------------------------------------------------------------------------
// Witness emission for main_poseidon_gl.circom
// ---------------------------------------------------------------------------

/// Build the `main_poseidon_gl.circom` witness-input JSON:
/// `{ pk[32], msg[1024], r[16], sig_fors[14][13][16], sig_ht[7][44][16] }`,
/// byte values as JSON numbers. The circuit packs/reduces these identically
/// to the signer, so `valid == 1` iff the signature verifies.
pub fn witness_json(pk: &PublicKey, msg: &[u8; 1024], sig: &Signature) -> serde_json::Value {
    let pk_bytes: Vec<u8> = pk
        .pk_seed
        .iter()
        .chain(pk.pk_root.iter())
        .copied()
        .collect();
    let nest3 = |outer: &[&[[u8; N]]]| -> Vec<Vec<Vec<u8>>> {
        outer
            .iter()
            .map(|tree| tree.iter().map(|n| n.to_vec()).collect())
            .collect()
    };
    let sig_fors: Vec<&[[u8; N]]> = sig.sig_fors.iter().map(|t| t.as_slice()).collect();
    let sig_ht: Vec<&[[u8; N]]> = sig.sig_ht.iter().map(|t| t.as_slice()).collect();
    serde_json::json!({
        "pk": pk_bytes,
        "msg": msg.to_vec(),
        "r": sig.r.to_vec(),
        "sig_fors": nest3(&sig_fors),
        "sig_ht": nest3(&sig_ht),
    })
}

// ---------------------------------------------------------------------------
// Per-HT-layer witnesses for the folded path (bench_ht_layer_gl.circom)
// ---------------------------------------------------------------------------

/// One HT-layer step in the layout `bench_ht_layer_gl.circom` consumes:
/// given `prev_root` (the layer's input message) plus the layer's WOTS
/// signature and XMSS auth path, reconstruct `next_root`. This is exactly one
/// fold step of the D4 (per-XMSS-layer) decomposition the `r1cs_f_prime`
/// chain folds.
#[derive(Clone, Debug)]
pub struct HtLayerWitness {
    pub pk_seed: [u8; N],
    pub layer: u64,
    pub tree_low: u64,
    pub idx_leaf: u64,
    pub prev_root: [u8; N],
    pub wots_sig: [[u8; N]; LEN],
    pub xmss_auth: [[u8; N]; HPRIME],
    /// The circuit's output — absent from the input JSON, kept for chaining
    /// checks (layer j's `next_root` must equal layer j+1's `prev_root`, and
    /// the final layer's `next_root` must equal `pk_root`).
    pub next_root: [u8; N],
}

/// Decompose a signature into the `D` per-HT-layer step witnesses, exactly as
/// `HtVerify` walks them. Reuses the same per-layer reconstruction as
/// `verify`, so each `next_root` is what `bench_ht_layer_gl.circom` outputs.
pub fn ht_layer_witnesses(
    pk: &PublicKey,
    msg: &[u8; 1024],
    sig: &Signature,
) -> Vec<HtLayerWitness> {
    let digest = slh_hmsg(&sig.r, &pk.pk_seed, &pk.pk_root, msg);
    let (md_indices, idx_tree, idx_leaf) = parse_digest(&digest);
    let fors_pk = fors_pk_from_sig(&pk.pk_seed, idx_tree, idx_leaf, &md_indices, &sig.sig_fors);

    let mut out = Vec::with_capacity(D);
    let mut layer_msg = fors_pk;
    for j in 0..D {
        let (tree_low, leaf) = if j == 0 {
            (idx_tree, idx_leaf)
        } else {
            (
                idx_tree >> (HPRIME * j),
                (idx_tree >> (HPRIME * (j - 1))) & 0x1ff,
            )
        };
        let chunks = base2b_with_csum(&layer_msg);
        let wots_pk = wots_pk_from_sig(
            &pk.pk_seed,
            j as u64,
            tree_low,
            leaf,
            &chunks,
            &sig.sig_ht[j][..LEN],
        );
        let next_root = xmss_root_from_sig(
            &pk.pk_seed,
            j as u64,
            tree_low,
            leaf,
            &wots_pk,
            &sig.sig_ht[j][LEN..],
        );

        let mut wots_sig = [[0u8; N]; LEN];
        wots_sig.copy_from_slice(&sig.sig_ht[j][..LEN]);
        let mut xmss_auth = [[0u8; N]; HPRIME];
        xmss_auth.copy_from_slice(&sig.sig_ht[j][LEN..]);

        out.push(HtLayerWitness {
            pk_seed: pk.pk_seed,
            layer: j as u64,
            tree_low,
            idx_leaf: leaf,
            prev_root: layer_msg,
            wots_sig,
            xmss_auth,
            next_root,
        });
        layer_msg = next_root;
    }
    out
}

/// Build the `bench_ht_layer_gl.circom` witness-input JSON for one layer
/// (`next_root` is the circuit output, so it is intentionally absent). The
/// scalar fields are emitted as decimal **strings**: `tree_low` can reach
/// 2^54, past JS `Number.MAX_SAFE_INTEGER` (2^53), so a JSON number would lose
/// precision in the circom WASM witness calculator's `JSON.parse`.
pub fn ht_layer_witness_json(w: &HtLayerWitness) -> serde_json::Value {
    let nest = |rows: &[[u8; N]]| -> Vec<Vec<u8>> { rows.iter().map(|n| n.to_vec()).collect() };
    serde_json::json!({
        "pk_seed": w.pk_seed.to_vec(),
        "layer": w.layer.to_string(),
        "tree_low": w.tree_low.to_string(),
        "idx_leaf": w.idx_leaf.to_string(),
        "prev_root": w.prev_root.to_vec(),
        "wots_sig": nest(&w.wots_sig),
        "xmss_auth": nest(&w.xmss_auth),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds() -> ([u8; N], [u8; N]) {
        let mut sk = [0u8; N];
        let mut pk = [0u8; N];
        for i in 0..N {
            sk[i] = (i as u8).wrapping_mul(7).wrapping_add(3);
            pk[i] = (i as u8).wrapping_mul(5).wrapping_add(11);
        }
        (sk, pk)
    }

    fn msg() -> [u8; 1024] {
        let mut m = [0u8; 1024];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(i as u8 >> 3);
        }
        m
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let (sk_seed, pk_seed) = seeds();
        let sk = keygen(sk_seed, pk_seed);
        let m = msg();
        let r = [42u8; N];
        let sig = sign(&sk, &m, r);
        assert!(
            verify(&sk.public_key(), &m, &sig),
            "valid signature must verify"
        );
    }

    #[test]
    fn tampered_signature_fails() {
        let (sk_seed, pk_seed) = seeds();
        let sk = keygen(sk_seed, pk_seed);
        let m = msg();
        let mut sig = sign(&sk, &m, [42u8; N]);
        // Flip one byte of one WOTS chain value.
        sig.sig_ht[0][0][0] ^= 1;
        assert!(
            !verify(&sk.public_key(), &m, &sig),
            "tampered HT sig must not verify"
        );
    }

    #[test]
    fn wrong_message_fails() {
        let (sk_seed, pk_seed) = seeds();
        let sk = keygen(sk_seed, pk_seed);
        let sig = sign(&sk, &msg(), [42u8; N]);
        let mut m2 = msg();
        m2[500] ^= 0xff;
        assert!(
            !verify(&sk.public_key(), &m2, &sig),
            "signature must not verify a different message"
        );
    }

    #[test]
    fn witness_json_shape() {
        let (sk_seed, pk_seed) = seeds();
        let sk = keygen(sk_seed, pk_seed);
        let sig = sign(&sk, &msg(), [7u8; N]);
        let v = witness_json(&sk.public_key(), &msg(), &sig);
        assert_eq!(v["pk"].as_array().unwrap().len(), 32);
        assert_eq!(v["msg"].as_array().unwrap().len(), 1024);
        assert_eq!(v["r"].as_array().unwrap().len(), 16);
        assert_eq!(v["sig_fors"].as_array().unwrap().len(), 14);
        assert_eq!(v["sig_fors"][0].as_array().unwrap().len(), 13);
        assert_eq!(v["sig_ht"].as_array().unwrap().len(), 7);
        assert_eq!(v["sig_ht"][0].as_array().unwrap().len(), 44);
    }

    #[test]
    fn ht_layer_witnesses_chain_to_pk_root() {
        let (sk_seed, pk_seed) = seeds();
        let sk = keygen(sk_seed, pk_seed);
        let sig = sign(&sk, &msg(), [42u8; N]);
        let layers = ht_layer_witnesses(&sk.public_key(), &msg(), &sig);
        assert_eq!(layers.len(), D);
        // Each layer's next_root feeds the next layer's prev_root.
        for j in 1..D {
            assert_eq!(
                layers[j].prev_root,
                layers[j - 1].next_root,
                "layer {j} prev_root != prev next_root"
            );
        }
        // The top layer reconstructs pk_root — the same check HtVerify asserts.
        assert_eq!(
            layers[D - 1].next_root,
            sk.pk_root,
            "top layer next_root != pk_root"
        );
        // Layer 0's prev_root is the FORS pubkey, distinct from the input msg.
        assert_eq!(layers[0].layer, 0);
        assert_eq!(layers[D - 1].layer, (D - 1) as u64);
    }
}
