//! The [`P521`] marker and its [`Curve`] routing table into `hazmat::p521*`.

use crate::curve::{Curve, GeneratedKeyPair, check_lengths, limbs_in_range};
use crate::hazmat::{
    p521, p521_comb, p521_domain, p521_extra_bits, p521_keygen, p521_mul, p521_point, p521_scalar,
    p521_sec1, p521_wnaf,
};
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::ct::Condition;

/// NIST P-521 (secp521r1), SP 800-186 Section 3.2.1.5.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct P521;

impl crate::curve::sealed::Sealed for P521 {}

impl Curve for P521 {
    const NAME: &'static str = "P521";
    const STRENGTH: SecurityStrength = SecurityStrength::_256bit;
    const ORDER_BITS: usize = 521;
    const FE_LEN: usize = 66;
    const SCALAR_LEN: usize = 66;
    const PK_UNCOMPRESSED_LEN: usize = 133;
    const PK_COMPRESSED_LEN: usize = 67;
    const SIG_LEN: usize = 132;
    const EXTRA_BITS_DRAW_LEN: usize = 74;

    type Limbs = [u64; 9];
    type FeBytes = [u8; 66];
    type ScalarBytes = [u8; 66];
    type PkUncompressed = [u8; 133];
    type PkCompressed = [u8; 67];
    type Signature = [u8; 132];
    type ExtraBitsDraw = [u8; 74];

    type Fe = p521::P521FieldElement;
    type Point = p521_point::P521JacobianPoint;
    type Scalar = p521_scalar::P521Scalar;
    type ScalarField = p521_scalar::P521ScalarField;
    type PublicScalar = p521_scalar::P521PublicScalar;

    const N: [u64; 9] = p521_scalar::N_LIMBS;
    const RNG_STRENGTH: SecurityStrength = p521_keygen::RNG_STRENGTH;
    const MAX_DRBG_OUTPUT_LEN: usize = p521_keygen::MAX_DRBG_OUTPUT_LEN;

    fn base_point() -> Self::Point {
        Self::Point::from_affine(
            Self::Fe::from_limbs(p521_domain::G_X_LIMBS),
            Self::Fe::from_limbs(p521_domain::G_Y_LIMBS),
        )
    }

    fn multiply_base_point(k: &Self::Scalar) -> Self::Point {
        p521_comb::comb_multiply_base_point(k)
    }

    fn multiply_point(k: &Self::Scalar, q: &Self::Point) -> Self::Point {
        p521_mul::multiply_point(k, q)
    }

    fn shamir_multiply(
        u: &Self::PublicScalar,
        v: &Self::PublicScalar,
        q: &Self::Point,
    ) -> Self::Point {
        p521_wnaf::shamir_multiply(u, v, q)
    }

    fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Self::Scalar {
        p521_extra_bits::reduce_wide_bits_mod_n_minus_1(bytes)
    }

    fn keygen<const DRBG_LEN: usize>(
        rng: &mut dyn RNG,
    ) -> Result<GeneratedKeyPair<Self>, RNGError> {
        p521_keygen::keygen::<DRBG_LEN>(rng)
    }

    fn keygen_extra_bits(rng: &mut dyn RNG) -> Result<GeneratedKeyPair<Self>, RNGError> {
        p521_keygen::keygen::<{ Self::EXTRA_BITS_DRAW_LEN }>(rng)
    }

    fn public_point(d: &Self::Scalar) -> (Self::Fe, Self::Fe) {
        p521_keygen::public_point(d)
    }

    fn encode_uncompressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkUncompressed {
        p521_sec1::encode_uncompressed(x, y)
    }

    fn encode_compressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkCompressed {
        p521_sec1::encode_compressed(x, y)
    }

    fn decode(bytes: &[u8]) -> Option<(Self::Fe, Self::Fe)> {
        p521_sec1::decode(bytes)
    }

    fn limbs_from_be_bytes(bytes: &Self::ScalarBytes) -> Self::Limbs {
        p521_sec1::limbs_from_be_bytes(bytes)
    }

    fn limbs_from_be_bytes_into(bytes: &Self::ScalarBytes, out: &mut Self::Limbs) {
        p521_sec1::limbs_from_be_bytes_into(bytes, out)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::ScalarBytes {
        p521_sec1::be_bytes_from_limbs(limbs)
    }

    fn be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::ScalarBytes) {
        p521_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn fe_be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::FeBytes {
        p521_sec1::be_bytes_from_limbs(limbs)
    }

    fn fe_be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::FeBytes) {
        p521_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn scalar_in_range(limbs: &Self::Limbs) -> Condition<u64> {
        limbs_in_range(limbs, &Self::N)
    }
}

const _: () = check_lengths::<P521>();
