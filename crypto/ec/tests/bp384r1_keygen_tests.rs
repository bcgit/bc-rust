//! The brainpoolP384r1 key pair generator: the RNG strength gate, determinism given the RNG's output,
//! the scalar in range and the point `[d]G` checked through the variable-base multiplier.

use bouncycastle_core::errors::RNGError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::hazmat::bp384r1::Bp384r1FieldElement;
use bouncycastle_ec::hazmat::bp384r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::hazmat::bp384r1_keygen::{RNG_STRENGTH, keygen, public_point};
use bouncycastle_ec::hazmat::bp384r1_mul::multiply_point;
use bouncycastle_ec::hazmat::bp384r1_point::Bp384r1JacobianPoint;
use bouncycastle_ec::hazmat::bp384r1_scalar::N_LIMBS;
use bouncycastle_ec::hazmat::bp384r1_sec1::be_bytes_from_limbs;
use bouncycastle_rng::FixedSeedRNG;

/// `N + 64` bits, the key agreement crate's draw.
const DRBG_LEN: usize = 56;

fn counting_rng(strength: SecurityStrength) -> FixedSeedRNG<[u8; 256]> {
    let mut rng =
        FixedSeedRNG::new(core::array::from_fn::<u8, 256, _>(|i| (i as u8).wrapping_mul(7)));
    rng.set_security_strength(strength);
    rng
}

#[test]
fn refuses_an_rng_below_the_curves_strength_and_takes_one_at_it() {
    assert_eq!(RNG_STRENGTH, SecurityStrength::_192bit);
    let mut weak = counting_rng(SecurityStrength::_128bit);
    assert_eq!(
        keygen::<DRBG_LEN>(&mut weak).err(),
        Some(RNGError::SecurityStrengthInsufficientForAlgorithm)
    );
    let mut exact = counting_rng(RNG_STRENGTH);
    assert!(keygen::<DRBG_LEN>(&mut exact).is_ok());
}

#[test]
fn is_deterministic_given_the_rngs_output_and_a_longer_draw_gives_another_key() {
    let (d1, q1) = keygen::<DRBG_LEN>(&mut counting_rng(RNG_STRENGTH)).unwrap();
    let (d2, q2) = keygen::<DRBG_LEN>(&mut counting_rng(RNG_STRENGTH)).unwrap();
    assert!(d1 == d2);
    assert_eq!(q1, q2);
    let (d3, _) = keygen::<{ DRBG_LEN + 4 }>(&mut counting_rng(RNG_STRENGTH)).unwrap();
    assert!(d1 != d3);
}

#[test]
fn the_scalar_is_in_range_and_the_point_is_d_times_g() {
    let (d, (x, y)) = keygen::<DRBG_LEN>(&mut counting_rng(RNG_STRENGTH)).unwrap();
    let bytes = d.to_be_bytes();
    assert!(bytes.iter().any(|&b| b != 0), "d is never zero");
    assert!(bytes < be_bytes_from_limbs(&N_LIMBS), "d is below n");
    let g = Bp384r1JacobianPoint::from_affine(
        Bp384r1FieldElement::from_limbs(G_X_LIMBS),
        Bp384r1FieldElement::from_limbs(G_Y_LIMBS),
    );
    let q = multiply_point(&d, &g).to_affine().unwrap();
    assert_eq!(q, (x, y), "[d]G through the variable-base multiplier");
    assert_eq!(public_point(&d), (x, y));
}
