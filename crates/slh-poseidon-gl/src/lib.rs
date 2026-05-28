//! Reference signer for SLH-DSA-128s with Goldilocks Poseidon hash family.
//!
//! Mirrors the Circom circuits at `slh-dsa-circuit/circuits/poseidon_gl/` and
//! the FIPS 205 control flow from `slh-dsa-circuit/reference/`. The output
//! signature is consumed by the bench step circuit
//! `bench_ht_layer_gl.circom` to produce real (non-all-zero) witnesses for
//! folding measurement.

pub mod poseidon;
pub mod primitives;
pub mod signer;

pub use signer::{keygen, sign, verify, witness_json, PublicKey, SecretKey, Signature};
