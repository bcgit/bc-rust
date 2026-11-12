//! The [`Secp256K1`] marker and its [`Curve`] routing table into `hazmat::p256k1*`.

use crate::curve::{Curve, GeneratedKeyPair, check_lengths, limbs_in_range};
use crate::hazmat::{
    p256k1, p256k1_comb, p256k1_domain, p256k1_extra_bits, p256k1_keygen, p256k1_mul, p256k1_point,
    p256k1_scalar, p256k1_sec1, p256k1_wnaf,
};
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::ct::Condition;

/// secp256k1, SEC 2 Version 2.0 Section 2.4.1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Secp256K1;

impl crate::curve::sealed::Sealed for Secp256K1 {}

impl Curve for Secp256K1 {
    const NAME: &'static str = "secp256k1";
    const STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    const ORDER_BITS: usize = 256;
    const FE_LEN: usize = 32;
    const SCALAR_LEN: usize = 32;
    const PK_UNCOMPRESSED_LEN: usize = 65;
    const PK_COMPRESSED_LEN: usize = 33;
    const SIG_LEN: usize = 64;
    const EXTRA_BITS_DRAW_LEN: usize = 40;

    type Limbs = [u64; 4];
    type FeBytes = [u8; 32];
    type ScalarBytes = [u8; 32];
    type PkUncompressed = [u8; 65];
    type PkCompressed = [u8; 33];
    type Signature = [u8; 64];
    type ExtraBitsDraw = [u8; 40];

    type Fe = p256k1::P256K1FieldElement;
    type Point = p256k1_point::P256K1JacobianPoint;
    type Scalar = p256k1_scalar::P256K1Scalar;
    type ScalarField = p256k1_scalar::P256K1ScalarField;
    type PublicScalar = p256k1_scalar::P256K1PublicScalar;

    const N: [u64; 4] = p256k1_scalar::N_LIMBS;
    const RNG_STRENGTH: SecurityStrength = p256k1_keygen::RNG_STRENGTH;
    const MAX_DRBG_OUTPUT_LEN: usize = p256k1_keygen::MAX_DRBG_OUTPUT_LEN;

    fn base_point() -> Self::Point {
        Self::Point::from_affine(
            Self::Fe::from_limbs(p256k1_domain::G_X_LIMBS),
            Self::Fe::from_limbs(p256k1_domain::G_Y_LIMBS),
        )
    }

    fn multiply_base_point(k: &Self::Scalar) -> Self::Point {
        p256k1_comb::comb_multiply_base_point(k)
    }

    fn multiply_point(k: &Self::Scalar, q: &Self::Point) -> Self::Point {
        p256k1_mul::multiply_point(k, q)
    }

    fn shamir_multiply(
        u: &Self::PublicScalar,
        v: &Self::PublicScalar,
        q: &Self::Point,
    ) -> Self::Point {
        p256k1_wnaf::shamir_multiply(u, v, q)
    }

    fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Self::Scalar {
        p256k1_extra_bits::reduce_wide_bits_mod_n_minus_1(bytes)
    }

    fn keygen<const DRBG_LEN: usize>(
        rng: &mut dyn RNG,
    ) -> Result<GeneratedKeyPair<Self>, RNGError> {
        p256k1_keygen::keygen::<DRBG_LEN>(rng)
    }

    fn keygen_extra_bits(rng: &mut dyn RNG) -> Result<GeneratedKeyPair<Self>, RNGError> {
        p256k1_keygen::keygen::<{ Self::EXTRA_BITS_DRAW_LEN }>(rng)
    }

    fn public_point(d: &Self::Scalar) -> (Self::Fe, Self::Fe) {
        p256k1_keygen::public_point(d)
    }

    fn encode_uncompressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkUncompressed {
        p256k1_sec1::encode_uncompressed(x, y)
    }

    fn encode_compressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkCompressed {
        p256k1_sec1::encode_compressed(x, y)
    }

    fn decode(bytes: &[u8]) -> Option<(Self::Fe, Self::Fe)> {
        p256k1_sec1::decode(bytes)
    }

    fn limbs_from_be_bytes(bytes: &Self::ScalarBytes) -> Self::Limbs {
        p256k1_sec1::limbs_from_be_bytes(bytes)
    }

    fn limbs_from_be_bytes_into(bytes: &Self::ScalarBytes, out: &mut Self::Limbs) {
        p256k1_sec1::limbs_from_be_bytes_into(bytes, out)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::ScalarBytes {
        p256k1_sec1::be_bytes_from_limbs(limbs)
    }

    fn be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::ScalarBytes) {
        p256k1_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn fe_be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::FeBytes {
        p256k1_sec1::be_bytes_from_limbs(limbs)
    }

    fn fe_be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::FeBytes) {
        p256k1_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn scalar_in_range(limbs: &Self::Limbs) -> Condition<u64> {
        limbs_in_range(limbs, &Self::N)
    }
}

const _: () = check_lengths::<Secp256K1>();
