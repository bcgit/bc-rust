//! This is a set of helper function to support a low-memory implementation that "streams" the private key
//! and other intermediate values by never holding the whole thing in memory at once, but re-constructing
//! what it needs in pieces, which generally means handling the matrices and vectors row-wise or entry-wise.

use crate::aux_functions::{bit_unpack_eta_out, expand_mask_poly, rej_ntt_poly, unpack_z_row};
use crate::params::MLDSAParams;
use crate::polynomial::Polynomial;
use bouncycastle_core::errors::SignatureError;
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
    t1: &Polynomial,
    c: &Polynomial,
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

    let ct1 = compute_ct1(t1.clone(), c.clone());
    fn compute_ct1(mut t1_i: Polynomial, mut c: Polynomial) -> Polynomial {
        t1_i.shift_left_d();
        t1_i.ntt();
        c.ntt();
        t1_i.multiply_ntt(&c);

        t1_i
    }

    Az_acc.sub(&ct1);
    Az_acc.inv_ntt();
    Az_acc.conditional_add_q();

    Ok(Az_acc)
}

pub(crate) fn compute_z_component<P: MLDSAParams>(
    s1: &Polynomial,
    rho_p_p: &[u8; 64],
    c_hat: &Polynomial,
    kappa: u16,
    col: usize,
) -> Result<Option<Polynomial>, SignatureError> {
    let y = expand_mask_poly::<P>(rho_p_p, kappa + col as u16);
    let mut s1_hat = s1.clone();
    s1_hat.ntt();
    s1_hat.multiply_ntt(c_hat);
    let mut cs1 = s1_hat; // rename
    cs1.inv_ntt();
    let mut z = cs1;
    z.add_ntt(&y);

    if z.check_norm(P::gamma1_minus_beta) { Ok(None) } else { Ok(Some(z)) }
}

pub(crate) fn compute_w0cs2_component<P: MLDSAParams>(
    s2: &Polynomial,
    w: &Polynomial,
    c_hat: &Polynomial,
) -> Option<Polynomial> {
    let mut s2_hat = s2.clone();
    s2_hat.ntt();
    s2_hat.multiply_ntt(c_hat);
    let mut cs2 = s2_hat; // rename
    cs2.inv_ntt();

    //  Note: this could be further optimized by using the optimization described in
    //  https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf section 5.1:
    //    "instead of computing (r1, r0) = Decomposeq (w − cs2, α)
    //      and checking whether ‖r0‖∞ < γ2 − β and r1 = w1, it is equivalent to just check that
    //      ‖w0 − cs2‖∞ < γ2 − β, where w0 is the low part of w. If this check passes, w0 − cs2
    //      is the low part of w − cs2."
    let mut w0cs2 = w.clone();
    w0cs2.low_bits::<P>();
    w0cs2.sub(&cs2);
    if w0cs2.check_norm(P::gamma2_minus_beta) { None } else { Some(w0cs2) }
}

pub(crate) fn compute_ct0_component<P: MLDSAParams>(
    t0_row: &Polynomial,
    c_hat: &Polynomial,
) -> Option<Polynomial> {
    let mut t0_hat = t0_row.clone();
    t0_hat.ntt();
    t0_hat.multiply_ntt(c_hat);
    let mut ct0 = t0_hat; // rename
    ct0.inv_ntt();

    if ct0.check_norm(P::gamma2) { None } else { Some(ct0) }
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
