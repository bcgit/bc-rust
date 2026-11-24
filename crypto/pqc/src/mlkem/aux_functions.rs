//! The auxiliary functions of FIPS 203 over whole vectors and matrices: ExpandA (Algorithm 13
//! lines 3-7), the sampling of a vector of CBD polynomials, and the ciphertext packing of
//! K-PKE.Encrypt / K-PKE.Decrypt. The single-polynomial functions they are built from are in
//! `bouncycastle_pqc::mlkem_common::aux_functions`.

use crate::mlkem::matrix::{MatrixTrait, VectorTrait};
use crate::mlkem::mlkem::N;
use crate::mlkem::params::MLKEMParams;
use crate::mlkem_common::aux_functions::{sample_ntt, sample_poly_CBD_out};
use crate::mlkem_common::polynomial::Polynomial;

// Into `A_hat`, a matrix the caller holds: a matrix returned by value is built in this frame and
// copied to the caller's, and the stack carries both.
pub(in crate::mlkem) fn expandA<P: MLKEMParams>(rho: &[u8; 32], A_hat: &mut P::MatrixA) {
    for i in 0..P::k {
        // 5: for (𝑗 ← 0; 𝑗 < 𝑘; 𝑗++)
        for j in 0..P::k {
            // 6: 𝐀[𝑖, 𝑗] ← SampleNTT(𝜌‖𝑗‖𝑖)
            //  ▷ 𝑗 and 𝑖 are bytes 33 and 34 of the input
            A_hat.set_elem(i, j, sample_ntt(rho, &[j as u8, i as u8]));
        }
    }
}

/// The vector of `k` CBD polynomials SamplePolyCBD𝜂(PRF𝜂(𝑏, 𝑁)) for 𝑁 = `n`, `n` + 1, ...: 𝐬 and
/// 𝐞 of Algorithm 13, 𝐲 and 𝐞1 of Algorithm 14. Into `v`, which the caller holds: each is secret.
pub(in crate::mlkem) fn sample_vector_CBD_out<P: MLKEMParams>(
    b: &[u8; 32],
    mut n: u8,
    eta: i16,
    v: &mut P::VecK,
) {
    for i in 0..P::k {
        sample_poly_CBD_out(b, n, eta, &mut v[i]);

        // Alg 13: 10: 𝑁 ← 𝑁 + 1
        n += 1;
    }
}

/// Algorithm 14 lines 22-24, 𝑐1 ‖ 𝑐2, into `out`, which the caller holds. It is the ciphertext,
/// except in decapsulation, where it is the re-encryption 𝑐′ and secret until compared.
pub(in crate::mlkem) fn pack_ciphertext_out<P: MLKEMParams, const CT_LEN: usize>(
    u: &P::VecK,
    v: &Polynomial,
    out: &mut [u8; CT_LEN],
) {
    // each of the N i16's will take du bits, so a polynomial takes N * du bits, then we have k of them
    let lim: usize = P::k * (N * (P::du as usize) / 8);

    u.compress_pol_vec::<P>(&mut out[..lim]);
    v.compress_poly::<P>(&mut out[lim..]);
}

pub(in crate::mlkem) fn unpack_ciphertext_u<P: MLKEMParams, const CT_LEN: usize>(
    c: &[u8; CT_LEN],
) -> P::VecK {
    // each of the N i16's will take du bits, so a polynomial takes N * du bits, then we have k of them
    let lim: usize = P::k * (N * (P::du as usize) / 8);

    P::VecK::decompress_pol_vec::<P>(&c[..lim])
}

pub(in crate::mlkem) fn unpack_ciphertext_v<P: MLKEMParams, const CT_LEN: usize>(
    c: &[u8; CT_LEN],
) -> Polynomial {
    // each of the N i16's will take du bits, so a polynomial takes N * du bits, then we have k of them
    let lim: usize = P::k * (N * (P::du as usize) / 8);

    Polynomial::decompress_poly::<P>(&c[lim..])
}
