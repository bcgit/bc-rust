//! `rej_bounded_poly_out` against FIPS 204 Algorithm 31 written out literally, one squeezed byte per
//! iteration, with Algorithm 15 for the half bytes. The function buffers its squeeze 272 bytes
//! at a time and refills when a polynomial needs more, which for 𝜂 = 4 happens for a few seeds
//! in a million: too rare for the known-answer suites to reach, so a seed that does is pinned
//! here.

use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle_digest::sha3::SHAKE256;
use bouncycastle_pqc::mldsa_common::aux_functions::rej_bounded_poly_out;
use bouncycastle_pqc::mldsa_common::params::{
    MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParamsBase,
};
use bouncycastle_pqc::mldsa_common::polynomial::Polynomial;

/// The bytes the function squeezes at a time.
const BUFFER_LEN: usize = 272;

/// Algorithm 15, CoeffFromHalfByte(𝑏).
fn coeff_from_half_byte(eta: usize, b: u8) -> Option<i32> {
    // 1: if 𝜂 = 2 and 𝑏 < 15 then return 2 − (𝑏 mod 5)
    if eta == 2 && b < 15 {
        Some(2 - i32::from(b % 5))
    // 3: if 𝜂 = 4 and 𝑏 < 9 then return 4 − 𝑏
    } else if eta == 4 && b < 9 {
        Some(4 - i32::from(b))
    // 4: else return ⊥
    } else {
        None
    }
}

/// Algorithm 31, RejBoundedPoly(𝜌), with 𝜌 the 64 bytes and the two nonce bytes; returns the
/// polynomial and the number of bytes squeezed.
fn rej_bounded_poly_literal(eta: usize, rho: &[u8; 64], nonce: &[u8; 2]) -> ([i32; 256], usize) {
    let mut a = [0i32; 256];
    // 1: 𝑗 ← 0;  2: ctx ← H.Init();  3: ctx ← H.Absorb(ctx, 𝜌)
    let mut j = 0;
    let mut ctx = SHAKE256::new();
    ctx.do_update(rho);
    ctx.do_update(nonce);
    let mut ctx = ctx.into_squeezer();
    let mut squeezed = 0;
    // 4: while 𝑗 < 256 do
    while j < 256 {
        // 5: 𝑧 ← H.Squeeze(ctx, 1)
        let mut z = [0u8; 1];
        ctx.do_output_out(&mut z);
        squeezed += 1;
        // 6: 𝑧0 ← CoeffFromHalfByte(𝑧 mod 16);  7: 𝑧1 ← CoeffFromHalfByte(⌊𝑧/16⌋)
        let z0 = coeff_from_half_byte(eta, z[0] % 16);
        let z1 = coeff_from_half_byte(eta, z[0] / 16);
        // 8: if 𝑧0 ≠ ⊥ then 𝑎𝑗 ← 𝑧0; 𝑗 ← 𝑗 + 1
        if let Some(z0) = z0 {
            a[j] = z0;
            j += 1;
        }
        // 12: if 𝑧1 ≠ ⊥ and 𝑗 < 256 then 𝑎𝑗 ← 𝑧1; 𝑗 ← 𝑗 + 1
        if let Some(z1) = z1
            && j < 256
        {
            a[j] = z1;
            j += 1;
        }
    }
    // 17: return 𝑎
    (a, squeezed)
}

/// Checks one seed and returns the bytes the literal algorithm squeezed for it.
fn check<P: MLDSAParamsBase>(rho: &[u8; 64], nonce: &[u8; 2]) -> usize {
    let (expected, squeezed) = rej_bounded_poly_literal(P::eta, rho, nonce);
    // Filled first with a value no coefficient takes, so that one left unwritten shows.
    let mut got = Polynomial { coeffs: [i32::MAX; 256] };
    rej_bounded_poly_out::<P>(rho, nonce, &mut got);
    for k in 0..256 {
        assert_eq!(got[k], expected[k], "{}: coefficient {k}", P::ALG_NAME);
    }
    squeezed
}

/// A seed whose polynomial needs more than one buffer: the refill runs.
#[test]
fn a_seed_that_refills_the_buffer() {
    let mut rho = [0u8; 64];
    rho[..8].copy_from_slice(&27658u64.to_le_bytes());
    rho[63] = 4;
    let squeezed = check::<MLDSA65Params>(&rho, &[1, 1]);
    assert!(squeezed > BUFFER_LEN, "the seed must need a refill; it squeezed {squeezed} bytes");
}

/// A few hundred seeds per parameter set, none of which needs a refill for 𝜂 = 2.
#[test]
fn seeds_within_one_buffer() {
    let mut most = [0usize; 3];
    for i in 0..300u64 {
        let mut rho = [0u8; 64];
        rho[..8].copy_from_slice(&i.to_le_bytes());
        let nonce = [(i % 7) as u8, (i % 3) as u8];
        most[0] = most[0].max(check::<MLDSA44Params>(&rho, &nonce));
        most[1] = most[1].max(check::<MLDSA65Params>(&rho, &nonce));
        most[2] = most[2].max(check::<MLDSA87Params>(&rho, &nonce));
    }
    // 𝜂 = 2 accepts 15 half bytes in 16, so 256 coefficients need about 137 bytes.
    assert!(most[0] < BUFFER_LEN && most[2] < BUFFER_LEN, "{most:?}");
    // 𝜂 = 4 accepts 9 in 16, so it needs more.
    assert!(most[1] > most[0], "{most:?}");
}
