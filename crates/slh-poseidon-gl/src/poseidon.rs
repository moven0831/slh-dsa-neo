//! Goldilocks Poseidon permutation (Plonky2 v1.1.0 constants, t=12, 30 rounds).
//!
//! Source of truth: `slh-dsa-circuit/circuits/poseidon_gl/poseidon_gl.circom`
//! and `poseidon_gl_constants.circom`. Output is byte-identical at the
//! permutation level — validated by 4 Plonky2 reference vectors mirrored
//! from `slh-dsa-circuit/scripts/check_poseidon_gl.py`.
//!
//! Reference: 0xPolygonZero/plonky2 @ v1.1.0 (Apache-2.0):
//!   plonky2/src/hash/poseidon.rs            — `ALL_ROUND_CONSTANTS[u64; 360]`
//!   plonky2/src/hash/poseidon_goldilocks.rs — `MDS_MATRIX_CIRC`, `MDS_MATRIX_DIAG`
//!
//! Permutation: t=12, full rounds=8 (4+4), partial rounds=22, S-box=x^7.
//! MDS layer: `result[k] = sum_i state[(i+k) mod 12]*CIRC[i] + state[k]*DIAG[k]`.
//!
//! Arithmetic note: naive `u128 % P` reduction. Correctness over speed —
//! this is a reference signer, not a prover-side hot path.

/// Goldilocks prime `p = 2^64 - 2^32 + 1`.
pub const P: u64 = 0xFFFFFFFF00000001;

const P_U128: u128 = P as u128;

#[inline]
const fn reduce(x: u128) -> u64 {
    (x % P_U128) as u64
}

/// Canonicalize a `u64` that may exceed `P` into `[0, P)`.
#[inline]
fn to_canonical(v: u64) -> u64 {
    if v < P { v } else { reduce(v as u128) }
}

#[inline]
fn add(a: u64, b: u64) -> u64 {
    reduce((a as u128) + (b as u128))
}

#[inline]
fn mul(a: u64, b: u64) -> u64 {
    reduce((a as u128) * (b as u128))
}

#[inline]
fn pow7(x: u64) -> u64 {
    let x2 = mul(x, x);
    let x4 = mul(x2, x2);
    let x3 = mul(x, x2);
    mul(x3, x4)
}

/// 30 rounds × 12 lanes of Plonky2 round constants.
/// Mirrors `getPoseidonGlRoundConstants()` in
/// `circuits/poseidon_gl/poseidon_gl_constants.circom`.
pub(crate) const ROUND_CONSTANTS: [[u64; 12]; 30] = [
    [0xb585f766f2144405, 0x7746a55f43921ad7, 0xb2fb0d31cee799b4, 0x0f6760a4803427d7, 0xe10d666650f4e012, 0x8cae14cb07d09bf1, 0xd438539c95f63e9f, 0xef781c7ce35b4c3d, 0xcdc4a239b0c44426, 0x277fa208bf337bff, 0xe17653a29da578a1, 0xc54302f225db2c76],
    [0x86287821f722c881, 0x59cd1a8a41c18e55, 0xc3b919ad495dc574, 0xa484c4c5ef6a0781, 0x308bbd23dc5416cc, 0x6e4a40c18f30c09c, 0x9a2eedb70d8f8cfa, 0xe360c6e0ae486f38, 0xd5c7718fbfc647fb, 0xc35eae071903ff0b, 0x849c2656969c4be7, 0xc0572c8c08cbbbad],
    [0xe9fa634a21de0082, 0xf56f6d48959a600d, 0xf7d713e806391165, 0x8297132b32825daf, 0xad6805e0e30b2c8a, 0xac51d9f5fcf8535e, 0x502ad7dc18c2ad87, 0x57a1550c110b3041, 0x66bbd30e6ce0e583, 0x0da2abef589d644e, 0xf061274fdb150d61, 0x28b8ec3ae9c29633],
    [0x92a756e67e2b9413, 0x70e741ebfee96586, 0x019d5ee2af82ec1c, 0x6f6f2ed772466352, 0x7cf416cfe7e14ca1, 0x61df517b86a46439, 0x85dc499b11d77b75, 0x4b959b48b9c10733, 0xe8be3e5da8043e57, 0xf5c0bc1de6da8699, 0x40b12cbf09ef74bf, 0xa637093ecb2ad631],
    [0x3cc3f892184df408, 0x2e479dc157bf31bb, 0x6f49de07a6234346, 0x213ce7bede378d7b, 0x5b0431345d4dea83, 0xa2de45780344d6a1, 0x7103aaf94a7bf308, 0x5326fc0d97279301, 0xa9ceb74fec024747, 0x27f8ec88bb21b1a3, 0xfceb4fda1ded0893, 0xfac6ff1346a41675],
    [0x7131aa45268d7d8c, 0x9351036095630f9f, 0xad535b24afc26bfb, 0x4627f5c6993e44be, 0x645cf794b8f1cc58, 0x241c70ed0af61617, 0xacb8e076647905f1, 0x3737e9db4c4f474d, 0xe7ea5e33e75fffb6, 0x90dee49fc9bfc23a, 0xd1b1edf76bc09c92, 0x0b65481ba645c602],
    [0x99ad1aab0814283b, 0x438a7c91d416ca4d, 0xb60de3bcc5ea751c, 0xc99cab6aef6f58bc, 0x69a5ed92a72ee4ff, 0x5e7b329c1ed4ad71, 0x5fc0ac0800144885, 0x32db829239774eca, 0x0ade699c5830f310, 0x7cc5583b10415f21, 0x85df9ed2e166d64f, 0x6604df4fee32bcb1],
    [0xeb84f608da56ef48, 0xda608834c40e603d, 0x8f97fe408061f183, 0xa93f485c96f37b89, 0x6704e8ee8f18d563, 0xcee3e9ac1e072119, 0x510d0e65e2b470c1, 0xf6323f486b9038f0, 0x0b508cdeffa5ceef, 0xf2417089e4fb3cbd, 0x60e75c2890d15730, 0xa6217d8bf660f29c],
    [0x7159cd30c3ac118e, 0x839b4e8fafead540, 0x0d3f3e5e82920adc, 0x8f7d83bddee7bba8, 0x780f2243ea071d06, 0xeb915845f3de1634, 0xd19e120d26b6f386, 0x016ee53a7e5fecc6, 0xcb5fd54e7933e477, 0xacb8417879fd449f, 0x9c22190be7f74732, 0x5d693c1ba3ba3621],
    [0xdcef0797c2b69ec7, 0x3d639263da827b13, 0xe273fd971bc8d0e7, 0x418f02702d227ed5, 0x8c25fda3b503038c, 0x2cbaed4daec8c07c, 0x5f58e6afcdd6ddc2, 0x284650ac5e1b0eba, 0x635b337ee819dab5, 0x9f9a036ed4f2d49f, 0xb93e260cae5c170e, 0xb0a7eae879ddb76d],
    [0xd0762cbc8ca6570c, 0x34c6efb812b04bf5, 0x40bf0ab5fa14c112, 0xb6b570fc7c5740d3, 0x5a27b9002de33454, 0xb1a5b165b6d2b2d2, 0x8722e0ace9d1be22, 0x788ee3b37e5680fb, 0x14a726661551e284, 0x98b7672f9ef3b419, 0xbb93ae776bb30e3a, 0x28fd3b046380f850],
    [0x30a4680593258387, 0x337dc00c61bd9ce1, 0xd5eca244c7a4ff1d, 0x7762638264d279bd, 0xc1e434bedeefd767, 0x0299351a53b8ec22, 0xb2d456e4ad251b80, 0x3e9ed1fda49cea0b, 0x2972a92ba450bed8, 0x20216dd77be493de, 0xadffe8cf28449ec6, 0x1c4dbb1c4c27d243],
    [0x15a16a8a8322d458, 0x388a128b7fd9a609, 0x2300e5d6baedf0fb, 0x2f63aa8647e15104, 0xf1c36ce86ecec269, 0x27181125183970c9, 0xe584029370dca96d, 0x4d9bbc3e02f1cfb2, 0xea35bc29692af6f8, 0x18e21b4beabb4137, 0x1e3b9fc625b554f4, 0x25d64362697828fd],
    [0x5a3f1bb1c53a9645, 0xdb7f023869fb8d38, 0xb462065911d4e1fc, 0x49c24ae4437d8030, 0xd793862c112b0566, 0xaadd1106730d8feb, 0xc43b6e0e97b0d568, 0xe29024c18ee6fca2, 0x5e50c27535b88c66, 0x10383f20a4ff9a87, 0x38e8ee9d71a45af8, 0xdd5118375bf1a9b9],
    [0x775005982d74d7f7, 0x86ab99b4dde6c8b0, 0xb1204f603f51c080, 0xef61ac8470250ecf, 0x1bbcd90f132c603f, 0x0cd1dabd964db557, 0x11a3ae5beb9d1ec9, 0xf755bfeea585d11d, 0xa3b83250268ea4d7, 0x516306f4927c93af, 0xddb4ac49c9efa1da, 0x64bb6dec369d4418],
    [0xf9cc95c22b4c1fcc, 0x08d37f755f4ae9f6, 0xeec49b613478675b, 0xf143933aed25e0b0, 0xe4c5dd8255dfc622, 0xe7ad7756f193198e, 0x92c2318b87fff9cb, 0x739c25f8fd73596d, 0x5636cac9f16dfed0, 0xdd8f909a938e0172, 0xc6401fe115063f5b, 0x8ad97b33f1ac1455],
    [0x0c49366bb25e8513, 0x0784d3d2f1698309, 0x530fb67ea1809a81, 0x410492299bb01f49, 0x139542347424b9ac, 0x9cb0bd5ea1a1115e, 0x02e3f615c38f49a1, 0x985d4f4a9c5291ef, 0x775b9feafdcd26e7, 0x304265a6384f0f2d, 0x593664c39773012c, 0x4f0a2e5fb028f2ce],
    [0xdd611f1000c17442, 0xd8185f9adfea4fd0, 0xef87139ca9a3ab1e, 0x3ba71336c34ee133, 0x7d3a455d56b70238, 0x660d32e130182684, 0x297a863f48cd1f43, 0x90e0a736a751ebb7, 0x549f80ce550c4fd3, 0x0f73b2922f38bd64, 0x16bf1f73fb7a9c3f, 0x6d1f5a59005bec17],
    [0x02ff876fa5ef97c4, 0xc5cb72a2a51159b0, 0x8470f39d2d5c900e, 0x25abb3f1d39fcb76, 0x23eb8cc9b372442f, 0xd687ba55c64f6364, 0xda8d9e90fd8ff158, 0xe3cbdc7d2fe45ea7, 0xb9a8c9b3aee52297, 0xc0d28a5c10960bd3, 0x45d7ac9b68f71a34, 0xeeb76e397069e804],
    [0x3d06c8bd1514e2d9, 0x9c9c98207cb10767, 0x65700b51aedfb5ef, 0x911f451539869408, 0x7ae6849fbc3a0ec6, 0x3bb340eba06afe7e, 0xb46e9d8b682ea65e, 0x8dcf22f9a3b34356, 0x77bdaeda586257a7, 0xf19e400a5104d20d, 0xc368a348e46d950f, 0x9ef1cd60e679f284],
    [0xe89cd854d5d01d33, 0x5cd377dc8bb882a2, 0xa7b0fb7883eee860, 0x7684403ec392950d, 0x5fa3f06f4fed3b52, 0x8df57ac11bc04831, 0x2db01efa1e1e1897, 0x54846de4aadb9ca2, 0xba6745385893c784, 0x541d496344d2c75b, 0xe909678474e687fe, 0xdfe89923f6c9c2ff],
    [0xece5a71e0cfedc75, 0x5ff98fd5d51fe610, 0x83e8941918964615, 0x5922040b47f150c1, 0xf97d750e3dd94521, 0x5080d4c2b86f56d7, 0xa7de115b56c78d70, 0x6a9242ac87538194, 0xf7856ef7f9173e44, 0x2265fc92feb0dc09, 0x17dfc8e4f7ba8a57, 0x9001a64209f21db8],
    [0x90004c1371b893c5, 0xb932b7cf752e5545, 0xa0b1df81b6fe59fc, 0x8ef1dd26770af2c2, 0x0541a4f9cfbeed35, 0x9e61106178bfc530, 0xb3767e80935d8af2, 0x0098d5782065af06, 0x31d191cd5c1466c7, 0x410fefafa319ac9d, 0xbdf8f242e316c4ab, 0x9e8cd55b57637ed0],
    [0xde122bebe9a39368, 0x4d001fd58f002526, 0xca6637000eb4a9f8, 0x2f2339d624f91f78, 0x6d1a7918c80df518, 0xdf9a4939342308e9, 0xebc2151ee6c8398c, 0x03cc2ba8a1116515, 0xd341d037e840cf83, 0x387cb5d25af4afcc, 0xbba2515f22909e87, 0x7248fe7705f38e47],
    [0x4d61e56a525d225a, 0x262e963c8da05d3d, 0x59e89b094d220ec2, 0x055d5b52b78b9c5e, 0x82b27eb33514ef99, 0xd30094ca96b7ce7b, 0xcf5cb381cd0a1535, 0xfeed4db6919e5a7c, 0x41703f53753be59f, 0x5eeea940fcde8b6f, 0x4cd1f1b175100206, 0x4a20358574454ec0],
    [0x1478d361dbbf9fac, 0x6f02dc07d141875c, 0x296a202ed8e556a2, 0x2afd67999bf32ee5, 0x7acfd96efa95491d, 0x6798ba0c0abb2c6d, 0x34c6f57b26c92122, 0x5736e1bad206b5de, 0x20057d2a0056521b, 0x3dea5bd5d0578bd7, 0x16e50d897d4634ac, 0x29bff3ecb9b7a6e3],
    [0x475cd3205a3bdcde, 0x18a42105c31b7e88, 0x023e7414af663068, 0x15147108121967d7, 0xe4a3dff1d7d6fef9, 0x01a8d1a588085737, 0x11b4c74eda62beef, 0xe587cc0d69a73346, 0x1ff7327017aa2a6e, 0x594e29c42473d06b, 0xf6f31db1899b12d5, 0xc02ac5e47312d3ca],
    [0xe70201e960cb78b8, 0x6f90ff3b6a65f108, 0x42747a7245e7fa84, 0xd1f507e43ab749b2, 0x1c86d265f15750cd, 0x3996ce73dd832c1c, 0x8e7fba02983224bd, 0xba0dec7103255dd4, 0x9e9cbd781628fc5b, 0xdae8645996edd6a5, 0xdebe0853b1a1d378, 0xa49229d24d014343],
    [0x7be5b9ffda905e1c, 0xa3c95eaec244aa30, 0x0230bca8f4df0544, 0x4135c2bebfe148c6, 0x166fc0cc438a3c72, 0x3762b59a8ae83efa, 0xe8928a4c89114750, 0x2a440b51a4945ee5, 0x80cefd2b7d99ff83, 0xbb9879c6e61fd62a, 0x6e7c8f1a84265034, 0x164bb2de1bbeddc8],
    [0xf3c12fe54d5c653b, 0x40b9e922ed9771e2, 0x551f5b0fbe7b1840, 0x25032aa7c4cb1811, 0xaaed34074b164346, 0x8ffd96bbf9c9c81d, 0x70fc91eb5937085c, 0x7f795e2a5f915440, 0x4543d9df5476d3cb, 0xf172d73e004fc90d, 0xdfd1c4febcc81238, 0xbc8dfb627fe558fc],
];

/// MDS circulant coefficients (lane offsets 0..11).
pub(crate) const MDS_CIRC: [u64; 12] = [17, 15, 41, 16, 2, 28, 13, 13, 39, 18, 34, 20];

/// MDS diagonal coefficients added on top of the circulant matrix.
pub(crate) const MDS_DIAG: [u64; 12] = [8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn mds_layer(post: &[u64; 12]) -> [u64; 12] {
    std::array::from_fn(|k| {
        let mut acc: u128 = 0;
        for i in 0..12 {
            acc += (post[(i + k) % 12] as u128) * (MDS_CIRC[i] as u128);
        }
        acc += (post[k] as u128) * (MDS_DIAG[k] as u128);
        reduce(acc)
    })
}

fn full_round(state: &mut [u64; 12], r: usize) {
    let post = std::array::from_fn(|i| pow7(add(state[i], ROUND_CONSTANTS[r][i])));
    *state = mds_layer(&post);
}

fn partial_round(state: &mut [u64; 12], r: usize) {
    let post = std::array::from_fn(|i| {
        let sum = add(state[i], ROUND_CONSTANTS[r][i]);
        if i == 0 { pow7(sum) } else { sum }
    });
    *state = mds_layer(&post);
}

/// Apply the Plonky2 v1.1.0 Goldilocks Poseidon permutation in-place.
///
/// Input state is 12 Goldilocks field elements in canonical form (< P).
/// Output is also canonical. Byte-identical to the Circom
/// `PoseidonGlPermute` template — see test vectors below.
pub fn permute(state: &mut [u64; 12]) {
    for r in 0..4 {
        full_round(state, r);
    }
    for r in 4..26 {
        partial_round(state, r);
    }
    for r in 26..30 {
        full_round(state, r);
    }
}

// ---------------------------------------------------------------------------
// Wrap helpers — mirror circuits/poseidon_gl/poseidon_gl_wrap.circom.
// ---------------------------------------------------------------------------

/// `PoseidonGl(nInputs)`: fixed-arity hash. Initializes state[0..nInputs] from
/// `inputs`, zero-pads to 12, applies one permutation, returns the first 2 lanes.
///
/// Panics if `inputs.len() > 12`.
pub fn poseidon_gl(inputs: &[u64]) -> (u64, u64) {
    assert!(inputs.len() <= 12, "PoseidonGl: arity must be <= 12, got {}", inputs.len());
    let mut state = [0u64; 12];
    for (i, &v) in inputs.iter().enumerate() {
        state[i] = to_canonical(v);
    }
    permute(&mut state);
    (state[0], state[1])
}

/// `PoseidonGlSponge14`: arity-14 sponge (Plonky2 rate=8, capacity=4 convention).
/// Two permutations: first absorbs inputs[0..8], second overwrite-absorbs inputs[8..14].
pub fn poseidon_gl_sponge14(inputs: &[u64; 14]) -> (u64, u64) {
    let mut state = [0u64; 12];
    for (s, &v) in state[..8].iter_mut().zip(&inputs[..8]) {
        *s = to_canonical(v);
    }
    permute(&mut state);
    for (s, &v) in state[..6].iter_mut().zip(&inputs[8..14]) {
        *s = to_canonical(v);
    }
    permute(&mut state);
    (state[0], state[1])
}

/// `PoseidonGlReduce(N)`: binary Merkle reduce of N 16-byte values (each as
/// `(lo, hi)` Goldilocks FE pair) down to a single 16-byte value. Tree node
/// is `PoseidonGl(4)` over `(left_lo, left_hi, right_lo, right_hi)`. Pads odd
/// levels with `(0, 0)` leaves. Iterative (not recursive) for clarity.
pub fn poseidon_gl_reduce(leaves_lo: &[u64], leaves_hi: &[u64]) -> (u64, u64) {
    assert_eq!(leaves_lo.len(), leaves_hi.len(), "reduce: lo/hi length mismatch");
    assert!(!leaves_lo.is_empty(), "reduce: must have ≥ 1 leaf");
    let mut cur_lo: Vec<u64> = leaves_lo.to_vec();
    let mut cur_hi: Vec<u64> = leaves_hi.to_vec();
    while cur_lo.len() > 1 {
        let n_pairs = (cur_lo.len() + 1) / 2;
        let (next_lo, next_hi): (Vec<u64>, Vec<u64>) = (0..n_pairs)
            .map(|i| {
                let (r_lo, r_hi) = if 2 * i + 1 < cur_lo.len() {
                    (cur_lo[2 * i + 1], cur_hi[2 * i + 1])
                } else {
                    (0, 0)
                };
                poseidon_gl(&[cur_lo[2 * i], cur_hi[2 * i], r_lo, r_hi])
            })
            .unzip();
        cur_lo = next_lo;
        cur_hi = next_hi;
    }
    (cur_lo[0], cur_hi[0])
}

/// `PackBytes16To2Fe`: 16 bytes (little-endian) → `(lo, hi)` Goldilocks FEs.
/// Matches the Circom assignment `lo <== sum bytes[i] * 256^i`, which implicitly
/// reduces mod P if the byte sum exceeds the field. So we reduce explicitly here.
pub fn pack_bytes16_to_2fe(bytes: &[u8; 16]) -> (u64, u64) {
    let lo_raw = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let hi_raw = u64::from_le_bytes(bytes[8..].try_into().unwrap());
    (reduce(lo_raw as u128), reduce(hi_raw as u128))
}

/// `UnpackFe2To16Bytes`: canonical Goldilocks `(lo, hi)` → 16 bytes (little-endian).
/// Assumes inputs are canonical (< P); Circom's `Num2Bits(64)` would fail otherwise.
pub fn unpack_fe2_to_bytes16(lo: u64, hi: u64) -> [u8; 16] {
    debug_assert!(lo < P, "unpack: lo = 0x{:016x} >= P", lo);
    debug_assert!(hi < P, "unpack: hi = 0x{:016x} >= P", hi);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&lo.to_le_bytes());
    out[8..].copy_from_slice(&hi.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(name: &str, input: [u64; 12], expected: [u64; 12]) {
        let mut state = input;
        permute(&mut state);
        for i in 0..12 {
            assert_eq!(
                state[i], expected[i],
                "vector {} lane {}: got 0x{:016x}, expected 0x{:016x}",
                name, i, state[i], expected[i]
            );
        }
    }

    #[test]
    fn plonky2_zeros_vector() {
        check("zeros", [0; 12], [
            0x3c18a9786cb0b359, 0xc4055e3364a246c3, 0x7953db0ab48808f4, 0xc71603f33a1144ca,
            0xd7709673896996dc, 0x46a84e87642f44ed, 0xd032648251ee0b3c, 0x1c687363b207df62,
            0xdf8565563e8045fe, 0x40f5b37ff4254dae, 0xd070f637b431067c, 0x1792b1c4342109d7,
        ]);
    }

    #[test]
    fn plonky2_range_vector() {
        check("range", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], [
            0xd64e1e3efc5b8e9e, 0x53666633020aaa47, 0xd40285597c6a8825, 0x613a4f81e81231d2,
            0x414754bfebd051f0, 0xcb1f8980294a023f, 0x6eb2a9e4d54a9d0f, 0x1902bc3af467e056,
            0xf045d5eafdc6021f, 0xe4150f77caaa3be5, 0xc9bfd01d39b50cce, 0x5c0a27fcb0e1459b,
        ]);
    }

    #[test]
    fn plonky2_neg_one_vector() {
        check("neg_one", [0xFFFFFFFF00000000; 12], [
            0xbe0085cfc57a8357, 0xd95af71847d05c09, 0xcf55a13d33c1c953, 0x95803a74f4530e82,
            0xfcd99eb30a135df1, 0xe095905e913a3029, 0xde0392461b42919b, 0x7d3260e24e81d031,
            0x10d3d0465d9deaa0, 0xa87571083dfc2a47, 0xe18263681e9958f8, 0xe28e96f1ae5e60d3,
        ]);
    }

    #[test]
    fn plonky2_random_vector() {
        check(
            "random",
            [
                0x8ccbbbea4fe5d2b7, 0xc2af59ee9ec49970, 0x90f7e1a9e658446a, 0xdcc0630a3ab8b1b8,
                0x7ff8256bca20588c, 0x5d99a7ca0c44ecfb, 0x48452b17a70fbee3, 0xeb09d654690b6c88,
                0x4a55d3a39c676a88, 0xc0407a38d2285139, 0xa234bac9356386d1, 0xe1633f2bad98a52f,
            ],
            [
                0xa89280105650c4ec, 0xab542d53860d12ed, 0x5704148e9ccab94f, 0xd3a826d4b62da9f5,
                0x8a7a6ca87892574f, 0xc7017e1cad1a674e, 0x1f06668922318e34, 0xa3b203bc8102676f,
                0xfcc781b0ce382bf2, 0x934c69ff3ed14ba5, 0x504688a5996e8f13, 0x401f3f2ed524a2ba,
            ],
        );
    }
}
