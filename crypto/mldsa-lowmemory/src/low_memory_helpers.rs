//! This is a set of helper function to support a low-memory implementation that "streams" the private key
//! and other intermediate values by never holding the whole thing in memory at once, but re-constructing
//! what it needs in pieces, which generally means handling the matrices and vectors row-wise or entry-wise.

use crate::aux_functions::{bit_unpack_eta_out, expand_mask_poly, rej_ntt_poly, unpack_z_row};
use crate::params::MLDSAParams;
use crate::polynomial::Polynomial;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};

#[inline(always)]
pub(crate) fn expandA_elem(rho: &[u8; 32], i: usize, j: usize) -> Polynomial {
    rej_ntt_poly(&rho, &[j as u8, i as u8])
}

/// Compute a row of the core signing operation
/// Alg 7: 12: 𝐰 ← NTT−1(𝐀_hat ∘ NTT(𝐲))
pub(crate) fn compute_w_row<P: MLDSAParams>(
    rho: &[u8; 32],
    rho_p_p: &[u8; 64],
    kappa: u16,
    row: usize,
) -> Polynomial {
    let mut y_hat = expand_mask_poly::<P>(rho_p_p, kappa);
    y_hat.ntt();
    let mut acc = rej_ntt_poly(rho, &[0u8, row as u8]);
    acc.multiply_ntt(&y_hat);

    for col in 1..P::l {
        y_hat = expand_mask_poly::<P>(rho_p_p, kappa + col as u16);
        y_hat.ntt();
        let mut tmp = rej_ntt_poly(rho, &[col as u8, row as u8]);
        tmp.multiply_ntt(&y_hat);
        acc.add_ntt(&tmp);
    }

    acc.inv_ntt();
    acc.conditional_add_q();
    acc
}

/// Algorithm 8 Line 9
pub(crate) fn compute_wp_approx_row<P: MLDSAParams, const SIG_LEN: usize>(
    rho: &[u8; 32],
    sig: &[u8; SIG_LEN],
    t1: Polynomial,
    c_hat: &Polynomial,
    idx: usize,
) -> Result<Polynomial, ()> {
    // Algorithm 8: line 9: 𝐰′_approx ← NTT−1(𝐀_hat ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑))
    //   broken out for clarity:
    //   NTT−1(
    //      𝐀_hat ∘ NTT(𝐳) −
    //                  NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑)
    //   )
    // ▷ 𝐰'_approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2^𝑑

    let mut z_i = unpack_z_row::<P, SIG_LEN>(0, sig)?;
    z_i.ntt();
    let mut Az_acc = rej_ntt_poly(rho, &[0u8, idx as u8]);
    Az_acc.multiply_ntt(&z_i);

    for col in 1..P::l {
        z_i = unpack_z_row::<P, SIG_LEN>(col, sig)?;
        z_i.ntt();

        // [Optimization Note]:
        // this is reconstructing a row of the public matrix A_hat,
        // which nobody is proposing to keep in memory.
        let mut tmp = rej_ntt_poly(rho, &[col as u8, idx as u8]);
        tmp.multiply_ntt(&z_i);
        Az_acc.add_ntt(&tmp);
    }

    // NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑), computed in place in the buffer `t1` arrived in.
    let ct1 = {
        let mut ct1 = t1;
        ct1.shift_left_d();
        ct1.ntt();
        ct1.multiply_ntt(c_hat);

        ct1
    };

    Az_acc.sub(&ct1);
    Az_acc.inv_ntt();
    Az_acc.conditional_add_q();

    Ok(Az_acc)
}

/// 𝐳 is written into `z_out`, and `true` returned. `false` means the norm check rejected this
/// component, and `z_out` then holds a partial value that the caller must discard.
pub(crate) fn compute_z_component<P: MLDSAParams>(
    s1: Polynomial,
    rho_p_p: &[u8; 64],
    c_hat: &Polynomial,
    kappa: u16,
    col: usize,
    z_out: &mut Polynomial,
) -> bool {
    let y = expand_mask_poly::<P>(rho_p_p, kappa + col as u16);

    // 𝑐𝐬1 ← NTT−1(𝑐_hat ∘ NTT(𝐬1)), built in place in the caller's buffer.
    *z_out = s1;
    z_out.ntt();
    z_out.multiply_ntt(c_hat);
    z_out.inv_ntt();

    // 𝐳 ← 𝐲 + 𝑐𝐬1
    z_out.add_ntt(&y);

    !z_out.check_norm(P::gamma1_minus_beta)
}

pub(crate) fn compute_w0cs2_component<P: MLDSAParams>(
    s2: Polynomial,
    w: &Polynomial,
    c_hat: &Polynomial,
    w0cs2_out: &mut Polynomial,
) -> bool {
    let mut cs2 = s2;
    cs2.ntt();
    cs2.multiply_ntt(c_hat);
    cs2.inv_ntt();

    //  Note: this could be further optimized by using the optimization described in
    //  https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf section 5.1:
    //    "instead of computing (r1, r0) = Decomposeq (w − cs2, α)
    //      and checking whether ‖r0‖∞ < γ2 − β and r1 = w1, it is equivalent to just check that
    //      ‖w0 − cs2‖∞ < γ2 − β, where w0 is the low part of w. If this check passes, w0 − cs2
    //      is the low part of w − cs2."
    // `w` is still needed by the caller, so its low half is taken in the out-buffer.
    *w0cs2_out = *w;
    w0cs2_out.low_bits::<P>();
    w0cs2_out.sub(&cs2);

    !w0cs2_out.check_norm(P::gamma2_minus_beta)
}

pub(crate) fn compute_ct0_component<P: MLDSAParams>(
    t0_row: Polynomial,
    c_hat: &Polynomial,
    ct0_out: &mut Polynomial,
) -> bool {
    *ct0_out = t0_row;
    ct0_out.ntt();
    ct0_out.multiply_ntt(c_hat);
    ct0_out.inv_ntt();

    !ct0_out.check_norm(P::gamma2)
}

/// Unpack a single s value from the packed representation.
///
/// `B` is the packed buffer type, which is `P::S1Packed` or `P::S2Packed` depending on which of
/// the two secret vectors is being unpacked.
pub(crate) fn s_unpack<P: MLDSAParams, B: ZeroizablePrimitive + AsRef<[u8]>>(
    s_packed: &Secret<B>,
    idx: usize,
) -> Polynomial {
    let mut s = Polynomial::new();
    let packed = (**s_packed).as_ref();
    let width = P::POLY_ETA_PACKED_LEN;
    bit_unpack_eta_out::<P>(&packed[idx * width..(idx + 1) * width], &mut s);
    s
}
