//! FIPS 205 SLH-DSA-128s signer + verifier with Goldilocks Poseidon.
//!
//! Control flow mirrors `slh-dsa-circuit/reference/src/main.rs`. This crate
//! also emits per-XMSS-layer witness JSONs in the layout consumed by
//! `bench_ht_layer_gl.circom` (one file per fold step).

pub struct KeyPair;
pub struct Signature;

pub fn sign(_msg: &[u8], _sk: &[u8]) -> Signature {
    // TODO: Phase 1
    unimplemented!("Phase 1 — Goldilocks Poseidon SLH-DSA-128s signer")
}

pub fn verify(_msg: &[u8], _sig: &Signature, _pk: &[u8]) -> bool {
    // TODO: Phase 1
    unimplemented!("Phase 1 — Goldilocks Poseidon SLH-DSA-128s verifier")
}
