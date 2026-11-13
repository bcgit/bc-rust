//! The auxiliary functions of FIPS 204, Section 7, over whole vectors and matrices. The
//! coefficient- and polynomial-level functions they are built from are in
//! `bouncycastle_mldsa_common::aux_functions`.

use crate::matrix::{MatrixTrait, VectorTrait};
use crate::mldsa::N;
use crate::params::MLDSAParams;
use bouncycastle_mldsa_common::aux_functions::{
    bit_unpack_gamma1, bitpack_gamma1, expand_mask_poly, power_2_round, rej_bounded_poly,
    rej_ntt_poly,
};
use bouncycastle_utils::secret::Secret;

/// Algorithm 26 sigEncode(̃𝑐_tilde, 𝐳, 𝐡)
/// Encodes a signature into a byte string.
/// Input: 𝑐_tilde ∈ 𝔹𝜆/4, 𝐳 ∈ 𝑅ℓ with coefficients in [−𝛾1 + 1, 𝛾1], 𝐡 ∈ 𝑅𝑘
/// Output: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
///
/// Returns the number of bytes written to the output buffer.
pub(crate) fn sig_encode<P: MLDSAParams, const SIG_LEN: usize>(
    c_tilde: &P::SigCTilde,
    z: &P::VecL,
    h: &P::VecK,
    output: &mut [u8; SIG_LEN],
) -> usize {
    debug_assert_eq!(SIG_LEN, P::SIG_LEN);
    output.fill(0);

    let mut pos = 0;

    output[..P::C_TILDE_LEN].copy_from_slice(c_tilde.as_ref());
    pos += P::C_TILDE_LEN;

    for i in 0..P::l {
        output[pos..pos + P::POLY_Z_PACKED_LEN]
            .copy_from_slice(bitpack_gamma1::<P>(&z.elems()[i]).as_ref());
        pos += P::POLY_Z_PACKED_LEN;
    }

    // This inlines Algorithm 20 HintBitPack(𝐡)

    // Algorithm 20
    // 2: Index ← 0
    let mut index: usize = 0;
    // 3: for 𝑖 from 0 to 𝑘 − 1 do
    for i in 0..P::k {
        // 4: for 𝑗 from 0 to 255 do
        for j in 0..N {
            // 5-8: if 𝐡[𝑖]_𝑗 ≠ 0 then 𝑦[Index] ← 𝑗; Index ← Index + 1
            if h.elems()[i][j] != 0 {
                output[pos + index] = j as u8;
                index += 1;
            }
        }
        // 10: 𝑦[𝜔 + 𝑖] ← Index
        output[pos + P::omega as usize + i] = index as u8;
    }

    SIG_LEN
}

/// Algorithm 27 sigDecode(𝜎)
/// Reverses the procedure sigEncode.
/// Input: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
/// Output: 𝑐 ∈ 𝔹𝜆/4, 𝐳 ∈ 𝑅ℓ with coefficients in \[−𝛾1 + 1, 𝛾1], 𝐡 ∈ 𝑅𝑘, or ⊥.
///   Output: (c_tilde, z, h)
///
/// Deviation from the FIPS: the outputs (c_tilde, z, h) are written into the caller's buffers
/// instead of being returned. Together they are several kB, and when this function is not inlined
/// a by-value return leaves up to three copies of them live at once (the local, the return slot
/// and the destructured bindings). `false` is ⊥; the buffers then hold a partial decode that the
/// caller must not use.
pub(crate) fn sig_decode<P: MLDSAParams, const SIG_LEN: usize>(
    sig: &[u8; SIG_LEN],
    c_tilde: &mut P::SigCTilde,
    z: &mut P::VecL,
    h: &mut P::VecK,
) -> bool {
    debug_assert_eq!(SIG_LEN, P::SIG_LEN);
    // HintBitUnpack below only ever sets bits, so 𝐡 has to start out all-zero.
    for h_i in h.elems_mut().iter_mut() {
        h_i.coeffs.fill(0);
    }

    let mut pos: usize = 0;

    c_tilde.as_mut().copy_from_slice(&sig[..P::C_TILDE_LEN]);
    pos += P::C_TILDE_LEN;

    for i in 0..P::l {
        z.elems_mut()[i] = bit_unpack_gamma1::<P>(&sig[pos..pos + P::POLY_Z_PACKED_LEN]);
        pos += P::POLY_Z_PACKED_LEN;
    }

    // This inlines Algorithm 21 HintBitUnpack(𝑦)

    // 2: Index ← 0
    //  ▷ Index for reading the first 𝜔 bytes of 𝑦
    let mut idx = 0usize;

    // 3: for 𝑖 from 0 to 𝑘 − 1 do
    //  ▷ reconstruct 𝐡[𝑖]
    for i in 0..P::k {
        // 4: if 𝑦[𝜔 + 𝑖] < Index or 𝑦[𝜔 + 𝑖] > 𝜔 then return ⊥
        // todo: this needs a specific test for malformed signature values. Maybe crucible coveres this case?
        //  ... could hide an assert here and see if it triggers.
        if sig[pos + (P::omega as usize) + i] < (idx as u8)
            || sig[pos + (P::omega as usize) + i] > P::omega as u8
        {
            return false;
        }

        // 6: First ← Index
        // 7: while Index < 𝑦[𝜔 + 𝑖] do
        //   ▷ 𝑦[𝜔 + 𝑖] says how far one can advance Index
        for j in idx..sig[pos + P::omega as usize + i] as usize {
            // 8: if Index > First then
            // 9:   if 𝑦[Index − 1] ≥ 𝑦[Index] then return ⊥
            //       ▷ malformed input
            if j > idx && sig[pos + j - 1] >= sig[pos + j] {
                return false;
            }
            // 12: 𝐡[𝑖]_𝑦[Index] ← 1
            h.elems_mut()[i][sig[pos + j] as usize] = 1;

            // 13: Index ← Index + 1
            //  > done by for loop
        }

        idx = sig[pos + P::omega as usize + i] as usize;
    }

    // ▷ read any leftover bytes in the first 𝜔 bytes of 𝑦 for malformed (nonzero) bytes
    for j in idx..P::omega as usize {
        if sig[pos + j] != 0 {
            return false;
        }
    }

    true
}

/// Algorithm 32 ExpandA(𝜌)
/// Samples a 𝑘 × ℓ matrix 𝐀̂ of elements of 𝑇𝑞.
/// in other words: derives the public matrix from the public seed.
/// Input: A seed 𝜌 ∈ 𝔹32 .̂
/// Output: Matrix Â ∈ (𝑇𝑞)𝑘×ℓ .
///
/// Deviation from the FIPS: 𝐀_hat is written into the caller's matrix instead of being returned.
/// Every element is overwritten, so `A_hat` need not be zeroed. A by-value return keeps a second
/// full copy of the matrix (up to 56 kB) alive in this frame while the caller's copy is filled.
pub(crate) fn expandA<P: MLDSAParams>(rho: &[u8; 32], A_hat: &mut P::MatrixA) {
    for r in 0..P::k {
        for s in 0..P::l {
            A_hat.set_elem(r, s, rej_ntt_poly(rho, &[s as u8, r as u8]));
        }
    }
}

/// Algorithm 33 ExpandS(𝜌)
/// Samples vectors 𝐬1 ∈ 𝑅ℓ and 𝐬2 ∈ 𝑅𝑘 , each with polynomial coordinates whose coefficients are
/// in the interval \[−𝜂, 𝜂].
/// Input: A seed 𝜌 ∈ 𝔹64 .
/// Output: Vectors 𝐬1, 𝐬2 of secret polynomials in 𝑅
/// Note that this returns Secret<Vector<k>> because s1, s2 are always part of a private key.
pub(crate) fn expandS<P: MLDSAParams>(rho: &[u8; 64]) -> (Secret<P::VecL>, Secret<P::VecK>) {
    let mut s1: Secret<P::VecL> = Secret::new();
    let mut s2: Secret<P::VecK> = Secret::new();

    for r in 0..P::l {
        s1.elems_mut()[r] = rej_bounded_poly::<P>(rho, &(r as u16).to_le_bytes());
    }

    for r in 0..P::k {
        s2.elems_mut()[r] = rej_bounded_poly::<P>(rho, &(r as u16 + P::l as u16).to_le_bytes());
    }

    (s1, s2)
}

/// Implements the meta-function described in FIPS 204 section 7.4 for applying power_2_round to a vector.
/// ((𝐫1\[𝑖])𝑗, (𝐫0\[𝑖])𝑗) = Power2Round((𝐫\[𝑖])𝑗).
pub(crate) fn power_2_round_vec<V: VectorTrait>(v: &V) -> (V, V) {
    let mut r1 = V::new();
    let mut r0 = V::new();

    for i in 0..V::LEN {
        for j in 0..N {
            (r1.elems_mut()[i][j], r0.elems_mut()[i][j]) = power_2_round(v.elems()[i][j]);
        }
    }

    (r1, r0)
}

/// Algorithm 34 ExpandMask(𝜌, 𝜇)
/// Samples a vector 𝐲 ∈ 𝑅ℓ such that each polynomial 𝐲[𝑟] has coefficients between −𝛾1 + 1 and 𝛾1.
/// Input: A seed 𝜌 ∈ 𝔹64 and a nonnegative integer 𝜇.
/// Output: Vector 𝐲 ∈ 𝑅ℓ .
pub(crate) fn expand_mask<P: MLDSAParams>(rho: &[u8; 64], mu: u16) -> P::VecL {
    let mut y = P::VecL::new();

    // 2: for 𝑟 from 0 to ℓ − 1 do
    // 3-5: lines 3 to 5 are one coordinate, see `expand_mask_poly`.
    for r in 0..P::l {
        y.elems_mut()[r] = expand_mask_poly::<P>(rho, mu + (r as u16));
    }

    y
}

/// Creates the hint vector from two Vector<k>'s, and also returns its hamming weight (ie the number of 1's).
pub(crate) fn make_hint_vecs<P: MLDSAParams>(r: &P::VecK, s: &P::VecK) -> (P::VecK, i32) {
    let mut out = P::VecK::new();
    let mut count = 0i32;

    for i in 0..P::k {
        let (w, c) = r.elems()[i].make_hint::<P>(&s.elems()[i]);
        out.elems_mut()[i] = w;

        // mutants note: this chains up to hint_hamming_weight > OMEGA and there is no test KAT that triggers this branch
        count += c;
    }

    (out, count)
}

/// Algorithm 40 UseHint(ℎ, 𝑟) applied to every coefficient of every coordinate.
pub(crate) fn use_hint_vecs<P: MLDSAParams>(h: &P::VecK, wp_approx: &P::VecK) -> P::VecK {
    let mut out = *wp_approx;
    for i in 0..P::k {
        out.elems_mut()[i].use_hint::<P>(&h.elems()[i]);
    }

    out
}
