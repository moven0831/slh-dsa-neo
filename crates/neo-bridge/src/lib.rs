//! Bridge: Circom `.r1cs` + `.wtns` (Goldilocks) → Nightstream `CcsStructure`.
//!
//! Parser logic is ported verbatim from
//! `slh-dsa-circuit/tools/nightstream-spike/src/parser.rs` (validated at
//! 486K-constraint scale, ~21 ms relation-check on the HT-layer step).
//!
//! The lift path:
//!     parse_r1cs(&Path) -> SparseR1cs<F>
//!     parse_wtns(&Path) -> Vec<F>
//!     sparse_r1cs_to_ccs(a, b, c) -> CcsStructure<F>
//!     check_ccs_rowwise_zero(&ccs, &x, &w) -> Result<()>
//!
//! Phase 3 will extend this to:
//!     ccs + x + w -> CcsClaim<Cmt, F>  (Nightstream's input to NIFS prove)

pub mod parser;

// TODO: Phase 3 — wire CcsStructure → CcsClaim, expose helpers consumed by neo-ivc.
