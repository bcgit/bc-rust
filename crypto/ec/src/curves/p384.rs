//! The [`P384`] marker and its [`Curve`] routing table into `hazmat::p384*`.

use crate::curve::{Curve, GeneratedKeyPair, check_lengths, limbs_in_range};
use crate::hazmat::{
    p384, p384_comb, p384_domain, p384_extra_bits, p384_keygen, p384_mul, p384_point, p384_scalar,
    p384_sec1, p384_wnaf,
};
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::ct::Condition;

/// NIST P-384 (secp384r1), SP 800-186 Section 3.2.1.4.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct P384;

impl crate::curve::sealed::Sealed for P384 {}

impl Curve for P384 {
    const NAME: &'static str = "P384";
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

    type Fe = p384::P384FieldElement;
    type Point = p384_point::P384JacobianPoint;
    type Scalar = p384_scalar::P384Scalar;
    type ScalarField = p384_scalar::P384ScalarField;
    type PublicScalar = p384_scalar::P384PublicScalar;

    const N: [u64; 6] = p384_scalar::N_LIMBS;
    const RNG_STRENGTH: SecurityStrength = p384_keygen::RNG_STRENGTH;
    const MAX_DRBG_OUTPUT_LEN: usize = p384_keygen::MAX_DRBG_OUTPUT_LEN;

    fn base_point() -> Self::Point {
        Self::Point::from_affine(
            Self::Fe::from_limbs(p384_domain::G_X_LIMBS),
            Self::Fe::from_limbs(p384_domain::G_Y_LIMBS),
        )
    }

    fn multiply_base_point(k: &Self::Scalar) -> Self::Point {
        p384_comb::comb_multiply_base_point(k)
    }

    fn multiply_point(k: &Self::Scalar, q: &Self::Point) -> Self::Point {
        p384_mul::multiply_point(k, q)
    }

    fn shamir_multiply(
        u: &Self::PublicScalar,
        v: &Self::PublicScalar,
        q: &Self::Point,
    ) -> Self::Point {
        p384_wnaf::shamir_multiply(u, v, q)
    }

    fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Self::Scalar {
        p384_extra_bits::reduce_wide_bits_mod_n_minus_1(bytes)
    }

    fn keygen<const DRBG_LEN: usize>(
        rng: &mut dyn RNG,
    ) -> Result<GeneratedKeyPair<Self>, RNGError> {
        p384_keygen::keygen::<DRBG_LEN>(rng)
    }

    fn keygen_extra_bits(rng: &mut dyn RNG) -> Result<GeneratedKeyPair<Self>, RNGError> {
        p384_keygen::keygen::<{ Self::EXTRA_BITS_DRAW_LEN }>(rng)
    }

    fn public_point(d: &Self::Scalar) -> (Self::Fe, Self::Fe) {
        p384_keygen::public_point(d)
    }

    fn encode_uncompressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkUncompressed {
        p384_sec1::encode_uncompressed(x, y)
    }

    fn encode_compressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkCompressed {
        p384_sec1::encode_compressed(x, y)
    }

    fn decode(bytes: &[u8]) -> Option<(Self::Fe, Self::Fe)> {
        p384_sec1::decode(bytes)
    }

    fn limbs_from_be_bytes(bytes: &Self::ScalarBytes) -> Self::Limbs {
        p384_sec1::limbs_from_be_bytes(bytes)
    }

    fn limbs_from_be_bytes_into(bytes: &Self::ScalarBytes, out: &mut Self::Limbs) {
        p384_sec1::limbs_from_be_bytes_into(bytes, out)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::ScalarBytes {
        p384_sec1::be_bytes_from_limbs(limbs)
    }

    fn be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::ScalarBytes) {
        p384_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn fe_be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::FeBytes {
        p384_sec1::be_bytes_from_limbs(limbs)
    }

    fn fe_be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::FeBytes) {
        p384_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn scalar_in_range(limbs: &Self::Limbs) -> Condition<u64> {
        limbs_in_range(limbs, &Self::N)
    }
}

const _: () = check_lengths::<P384>();
