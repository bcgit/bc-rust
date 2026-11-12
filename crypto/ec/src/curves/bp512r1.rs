//! The [`Bp512r1`] marker and its [`Curve`] routing table into `hazmat::bp512r1*`.

use crate::curve::{Curve, GeneratedKeyPair, check_lengths, limbs_in_range};
use crate::hazmat::{
    bp512r1, bp512r1_comb, bp512r1_domain, bp512r1_extra_bits, bp512r1_keygen, bp512r1_mul,
    bp512r1_point, bp512r1_scalar, bp512r1_sec1, bp512r1_wnaf,
};
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::ct::Condition;

/// brainpoolP512r1, RFC 5639 Section 3.7.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bp512r1;

impl crate::curve::sealed::Sealed for Bp512r1 {}

impl Curve for Bp512r1 {
    const NAME: &'static str = "brainpoolP512r1";
    const STRENGTH: SecurityStrength = SecurityStrength::_256bit;
    const ORDER_BITS: usize = 512;
    const FE_LEN: usize = 64;
    const SCALAR_LEN: usize = 64;
    const PK_UNCOMPRESSED_LEN: usize = 129;
    const PK_COMPRESSED_LEN: usize = 65;
    const SIG_LEN: usize = 128;
    const EXTRA_BITS_DRAW_LEN: usize = 72;

    type Limbs = [u64; 8];
    type FeBytes = [u8; 64];
    type ScalarBytes = [u8; 64];
    type PkUncompressed = [u8; 129];
    type PkCompressed = [u8; 65];
    type Signature = [u8; 128];
    type ExtraBitsDraw = [u8; 72];

    type Fe = bp512r1::Bp512r1FieldElement;
    type Point = bp512r1_point::Bp512r1JacobianPoint;
    type Scalar = bp512r1_scalar::Bp512r1Scalar;
    type ScalarField = bp512r1_scalar::Bp512r1ScalarField;
    type PublicScalar = bp512r1_scalar::Bp512r1PublicScalar;

    const N: [u64; 8] = bp512r1_scalar::N_LIMBS;
    const RNG_STRENGTH: SecurityStrength = bp512r1_keygen::RNG_STRENGTH;
    const MAX_DRBG_OUTPUT_LEN: usize = bp512r1_keygen::MAX_DRBG_OUTPUT_LEN;

    fn base_point() -> Self::Point {
        Self::Point::from_affine(
            Self::Fe::from_limbs(bp512r1_domain::G_X_LIMBS),
            Self::Fe::from_limbs(bp512r1_domain::G_Y_LIMBS),
        )
    }

    fn multiply_base_point(k: &Self::Scalar) -> Self::Point {
        bp512r1_comb::comb_multiply_base_point(k)
    }

    fn multiply_point(k: &Self::Scalar, q: &Self::Point) -> Self::Point {
        bp512r1_mul::multiply_point(k, q)
    }

    fn shamir_multiply(
        u: &Self::PublicScalar,
        v: &Self::PublicScalar,
        q: &Self::Point,
    ) -> Self::Point {
        bp512r1_wnaf::shamir_multiply(u, v, q)
    }

    fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Self::Scalar {
        bp512r1_extra_bits::reduce_wide_bits_mod_n_minus_1(bytes)
    }

    fn keygen<const DRBG_LEN: usize>(
        rng: &mut dyn RNG,
    ) -> Result<GeneratedKeyPair<Self>, RNGError> {
        bp512r1_keygen::keygen::<DRBG_LEN>(rng)
    }

    fn keygen_extra_bits(rng: &mut dyn RNG) -> Result<GeneratedKeyPair<Self>, RNGError> {
        bp512r1_keygen::keygen::<{ Self::EXTRA_BITS_DRAW_LEN }>(rng)
    }

    fn public_point(d: &Self::Scalar) -> (Self::Fe, Self::Fe) {
        bp512r1_keygen::public_point(d)
    }

    fn encode_uncompressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkUncompressed {
        bp512r1_sec1::encode_uncompressed(x, y)
    }

    fn encode_compressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkCompressed {
        bp512r1_sec1::encode_compressed(x, y)
    }

    fn decode(bytes: &[u8]) -> Option<(Self::Fe, Self::Fe)> {
        bp512r1_sec1::decode(bytes)
    }

    fn limbs_from_be_bytes(bytes: &Self::ScalarBytes) -> Self::Limbs {
        bp512r1_sec1::limbs_from_be_bytes(bytes)
    }

    fn limbs_from_be_bytes_into(bytes: &Self::ScalarBytes, out: &mut Self::Limbs) {
        bp512r1_sec1::limbs_from_be_bytes_into(bytes, out)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::ScalarBytes {
        bp512r1_sec1::be_bytes_from_limbs(limbs)
    }

    fn be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::ScalarBytes) {
        bp512r1_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn fe_be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::FeBytes {
        bp512r1_sec1::be_bytes_from_limbs(limbs)
    }

    fn fe_be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::FeBytes) {
        bp512r1_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn scalar_in_range(limbs: &Self::Limbs) -> Condition<u64> {
        limbs_in_range(limbs, &Self::N)
    }
}

const _: () = check_lengths::<Bp512r1>();
