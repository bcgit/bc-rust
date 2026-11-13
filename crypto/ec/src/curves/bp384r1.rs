//! The [`Bp384r1`] marker and its [`Curve`] routing table into `hazmat::bp384r1*`.

use crate::curve::{Curve, GeneratedKeyPair, check_lengths, limbs_in_range};
use crate::hazmat::{
    bp384r1, bp384r1_comb, bp384r1_domain, bp384r1_extra_bits, bp384r1_keygen, bp384r1_mul,
    bp384r1_point, bp384r1_scalar, bp384r1_sec1, bp384r1_wnaf,
};
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::ct::Condition;

/// brainpoolP384r1, RFC 5639 Section 3.6.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bp384r1;

impl crate::curve::sealed::Sealed for Bp384r1 {}

impl Curve for Bp384r1 {
    const NAME: &'static str = "brainpoolP384r1";
    const STRENGTH: SecurityStrength = SecurityStrength::_192bit;
    const ORDER_BITS: usize = 384;
    const FE_LEN: usize = 48;
    const SCALAR_LEN: usize = 48;
    const PK_UNCOMPRESSED_LEN: usize = 97;
    const PK_COMPRESSED_LEN: usize = 49;
    const SIG_LEN: usize = 96;
    const EXTRA_BITS_DRAW_LEN: usize = 56;

    type Limbs = [u64; 6];
    type FeBytes = [u8; 48];
    type ScalarBytes = [u8; 48];
    type PkUncompressed = [u8; 97];
    type PkCompressed = [u8; 49];
    type Signature = [u8; 96];
    type ExtraBitsDraw = [u8; 56];

    type Fe = bp384r1::Bp384r1FieldElement;
    type Point = bp384r1_point::Bp384r1JacobianPoint;
    type Scalar = bp384r1_scalar::Bp384r1Scalar;
    type ScalarField = bp384r1_scalar::Bp384r1ScalarField;
    type PublicScalar = bp384r1_scalar::Bp384r1PublicScalar;

    const N: [u64; 6] = bp384r1_scalar::N_LIMBS;
    const RNG_STRENGTH: SecurityStrength = bp384r1_keygen::RNG_STRENGTH;
    const MAX_DRBG_OUTPUT_LEN: usize = bp384r1_keygen::MAX_DRBG_OUTPUT_LEN;

    fn base_point() -> Self::Point {
        Self::Point::from_affine(
            Self::Fe::from_limbs(bp384r1_domain::G_X_LIMBS),
            Self::Fe::from_limbs(bp384r1_domain::G_Y_LIMBS),
        )
    }

    fn multiply_base_point(k: &Self::Scalar) -> Self::Point {
        bp384r1_comb::comb_multiply_base_point(k)
    }

    fn multiply_point(k: &Self::Scalar, q: &Self::Point) -> Self::Point {
        bp384r1_mul::multiply_point(k, q)
    }

    fn shamir_multiply(
        u: &Self::PublicScalar,
        v: &Self::PublicScalar,
        q: &Self::Point,
    ) -> Self::Point {
        bp384r1_wnaf::shamir_multiply(u, v, q)
    }

    fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Self::Scalar {
        bp384r1_extra_bits::reduce_wide_bits_mod_n_minus_1(bytes)
    }

    fn keygen<const DRBG_LEN: usize>(
        rng: &mut dyn RNG,
    ) -> Result<GeneratedKeyPair<Self>, RNGError> {
        bp384r1_keygen::keygen::<DRBG_LEN>(rng)
    }

    fn keygen_extra_bits(rng: &mut dyn RNG) -> Result<GeneratedKeyPair<Self>, RNGError> {
        bp384r1_keygen::keygen::<{ Self::EXTRA_BITS_DRAW_LEN }>(rng)
    }

    fn public_point(d: &Self::Scalar) -> (Self::Fe, Self::Fe) {
        bp384r1_keygen::public_point(d)
    }

    fn encode_uncompressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkUncompressed {
        bp384r1_sec1::encode_uncompressed(x, y)
    }

    fn encode_compressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkCompressed {
        bp384r1_sec1::encode_compressed(x, y)
    }

    fn decode(bytes: &[u8]) -> Option<(Self::Fe, Self::Fe)> {
        bp384r1_sec1::decode(bytes)
    }

    fn limbs_from_be_bytes(bytes: &Self::ScalarBytes) -> Self::Limbs {
        bp384r1_sec1::limbs_from_be_bytes(bytes)
    }

    fn limbs_from_be_bytes_into(bytes: &Self::ScalarBytes, out: &mut Self::Limbs) {
        bp384r1_sec1::limbs_from_be_bytes_into(bytes, out)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::ScalarBytes {
        bp384r1_sec1::be_bytes_from_limbs(limbs)
    }

    fn be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::ScalarBytes) {
        bp384r1_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn fe_be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::FeBytes {
        bp384r1_sec1::be_bytes_from_limbs(limbs)
    }

    fn fe_be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::FeBytes) {
        bp384r1_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn scalar_in_range(limbs: &Self::Limbs) -> Condition<u64> {
        limbs_in_range(limbs, &Self::N)
    }
}

const _: () = check_lengths::<Bp384r1>();
