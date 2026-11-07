//! The parts of FIPS 204, Algorithm 27 (sigDecode) that read one component of a signature at a
//! time, so that the verifier never holds the whole of 𝐳 or 𝐡. The coefficient- and
//! polynomial-level functions of Section 7 are in `bouncycastle_mldsa_common::aux_functions`.

use crate::params::MLDSAParams;
use bouncycastle_mldsa_common::aux_functions::bit_unpack_gamma1;
use bouncycastle_mldsa_common::polynomial::Polynomial;
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// Part of unpacking the sig value
pub(crate) fn unpack_c_tilde<P: MLDSAParams>(sig: &[u8]) -> P::SigCTilde {
    let mut c_tilde = <P::SigCTilde as ZeroizablePrimitive>::ZEROED;
    c_tilde.as_mut().copy_from_slice(&sig[..P::C_TILDE_LEN]);
    c_tilde
}

/// Part of unpacking the sig value
pub(crate) fn unpack_z_row<P: MLDSAParams, const SIG_LEN: usize>(
    idx: usize,
    sig: &[u8; SIG_LEN],
) -> Option<Polynomial> {
    debug_assert!(idx < P::l);

    // skip to the start of the z's
    let pos = P::C_TILDE_LEN;
    let z = bit_unpack_gamma1::<P>(
        &sig[pos + idx * P::POLY_Z_PACKED_LEN..pos + (idx + 1) * P::POLY_Z_PACKED_LEN],
    );

    // Perform the norm check from
    // Alg 8; Line 13 (first half) return [[ ||𝐳||∞ < 𝛾1 − 𝛽]]
    if z.check_norm(P::gamma1_minus_beta) { None } else { Some(z) }
}
/// Part of unpacking the sig value
pub(crate) fn unpack_h_row<P: MLDSAParams, const SIG_LEN: usize>(
    row: usize,
    sig: &[u8; SIG_LEN],
) -> Option<Polynomial> {
    debug_assert!(row < P::k);

    let mut h = Polynomial::new();

    // skip over the other stuff in the encoded sig value
    let pos = P::C_TILDE_LEN + P::l * P::POLY_Z_PACKED_LEN;

    // This inlines Algorithm 21 HintBitUnpack(𝑦)

    // 2: Index ← 0
    //  ▷ Index for reading the first 𝜔 bytes of 𝑦
    // let mut idx = 0usize;
    // This row calc is a bit weird because technically it's supposed to be done at the end
    // of the previous loop
    let idx = if row == 0 { 0 } else { sig[pos + P::omega as usize + row - 1] as usize };

    // 3: for 𝑖 from 0 to 𝑘 − 1 do
    //  ▷ reconstruct 𝐡[𝑖]
    // for i in 0..k {
    // 4: if 𝑦[𝜔 + 𝑖] < Index or 𝑦[𝜔 + 𝑖] > 𝜔 then return ⊥
    // mutants note: don't have test vectors that exercise this condition
    if sig[pos + (P::omega as usize) + row] < (idx as u8)
        || sig[pos + (P::omega as usize) + row] > P::omega as u8
    {
        return None;
    }

    // 6: First ← Index
    // 7: while Index < 𝑦[𝜔 + 𝑖] do
    //   ▷ 𝑦[𝜔 + 𝑖] says how far one can advance Index
    for j in idx..sig[pos + P::omega as usize + row] as usize {
        // 8: if Index > First then
        // 9:   if 𝑦[Index − 1] ≥ 𝑦[Index] then return ⊥
        //       ▷ malformed input
        // mutants note: don't have test vectors that exercise this condition
        if j > idx && sig[pos + j - 1] >= sig[pos + j] {
            return None;
        }
        // 12: 𝐡[𝑖]_𝑦[Index] ← 1
        h[sig[pos + j] as usize] = 1;

        // 13: Index ← Index + 1
        //  > done by for loop
    }

    // ▷ read any leftover bytes in the first 𝜔 bytes of 𝑦 for malformed (nonzero) bytes
    // mutants note:
    if row == P::k - 1 {
        let idx = sig[pos + P::omega as usize + row] as usize;
        for j in idx..P::omega as usize {
            if sig[pos + j] != 0 {
                return None;
            }
        }
    }

    Some(h)
}
