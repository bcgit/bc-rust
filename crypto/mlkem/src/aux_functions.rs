//! The auxiliary functions of FIPS 203 over whole vectors and matrices: ExpandA (Algorithm 13
//! lines 3-7), the sampling of a vector of CBD polynomials, and the ciphertext packing of
//! K-PKE.Encrypt / K-PKE.Decrypt. The single-polynomial functions they are built from are in
//! `bouncycastle_mlkem_common::aux_functions`.

use crate::matrix::{MatrixTrait, VectorTrait};
use crate::mlkem::N;
use crate::params::MLKEMParams;
use bouncycastle_mlkem_common::aux_functions::{sample_ntt, sample_poly_CBD};
use bouncycastle_mlkem_common::polynomial::Polynomial;

pub(crate) fn expandA<P: MLKEMParams>(rho: &[u8; 32]) -> P::MatrixA {
    let mut A_hat = P::MatrixA::new();
    for i in 0..P::k {
        // 5: for (𝑗 ← 0; 𝑗 < 𝑘; 𝑗++)
        for j in 0..P::k {
            // 6: 𝐀[𝑖, 𝑗] ← SampleNTT(𝜌‖𝑗‖𝑖)
            //  ▷ 𝑗 and 𝑖 are bytes 33 and 34 of the input
            A_hat.set_elem(i, j, sample_ntt(rho, &[j as u8, i as u8]));
        }
    }

    A_hat
}

/// Internal helper for keygen since both s_hat and e_hat have identical sampling code
pub(crate) fn sample_vector_CBD<P: MLKEMParams>(b: &[u8; 32], mut n: u8, eta: i16) -> P::VecK {
    let mut v = P::VecK::new();

    for i in 0..P::k {
        v[i] = sample_poly_CBD(b, n, eta);

        // Alg 13: 10: 𝑁 ← 𝑁 + 1
        n += 1;
    }

    v
}

pub(crate) fn pack_ciphertext<P: MLKEMParams, const CT_LEN: usize>(
    u: &P::VecK,
    v: &Polynomial,
) -> [u8; CT_LEN] {
    let mut out = [0u8; CT_LEN];

    // each of the N i16's will take du bits, so a polynomial takes N * du bits, then we have k of them
    let lim: usize = P::k * (N * (P::du as usize) / 8);

    u.compress_pol_vec::<P>(&mut out[..lim]);
    v.compress_poly::<P>(&mut out[lim..]);
    out
}

pub(crate) fn unpack_ciphertext_u<P: MLKEMParams, const CT_LEN: usize>(
    c: &[u8; CT_LEN],
) -> P::VecK {
    // each of the N i16's will take du bits, so a polynomial takes N * du bits, then we have k of them
    let lim: usize = P::k * (N * (P::du as usize) / 8);

    P::VecK::decompress_pol_vec::<P>(&c[..lim])
}

pub(crate) fn unpack_ciphertext_v<P: MLKEMParams, const CT_LEN: usize>(
    c: &[u8; CT_LEN],
) -> Polynomial {
    // each of the N i16's will take du bits, so a polynomial takes N * du bits, then we have k of them
    let lim: usize = P::k * (N * (P::du as usize) / 8);

    Polynomial::decompress_poly::<P>(&c[lim..])
}
