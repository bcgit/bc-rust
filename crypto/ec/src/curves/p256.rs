//! The [`P256`] marker and its [`Curve`] routing table into `hazmat::p256*`.

use crate::curve::{Curve, GeneratedKeyPair, check_lengths, limbs_in_range};
use crate::hazmat::{
    p256, p256_comb, p256_domain, p256_extra_bits, p256_keygen, p256_mul, p256_point, p256_scalar,
    p256_sec1, p256_wnaf,
};
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::ct::Condition;

/// NIST P-256 (secp256r1), SP 800-186 Section 3.2.1.3.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct P256;

impl crate::curve::sealed::Sealed for P256 {}

impl Curve for P256 {
    const NAME: &'static str = "P256";
    const STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    const ORDER_BITS: usize = 256;
    const FE_LEN: usize = 32;
    const SCALAR_LEN: usize = 32;
    const PK_UNCOMPRESSED_LEN: usize = 65;
    const PK_COMPRESSED_LEN: usize = 33;
    const SIG_LEN: usize = 64;
    /// FIPS 186-5 Table A.2: 352 bits recommended for p256 (288 required), above the N + 64
    /// the other curves draw.
    const EXTRA_BITS_DRAW_LEN: usize = 44;

    type Limbs = [u64; 4];
    type FeBytes = [u8; 32];
    type ScalarBytes = [u8; 32];
    type PkUncompressed = [u8; 65];
    type PkCompressed = [u8; 33];
    type Signature = [u8; 64];
    type ExtraBitsDraw = [u8; 44];

    type Fe = p256::P256FieldElement;
    type Point = p256_point::P256JacobianPoint;
    type Scalar = p256_scalar::P256Scalar;
    type ScalarField = p256_scalar::P256ScalarField;
    type PublicScalar = p256_scalar::P256PublicScalar;

    const N: [u64; 4] = p256_scalar::N_LIMBS;
    const RNG_STRENGTH: SecurityStrength = p256_keygen::RNG_STRENGTH;
    const MAX_DRBG_OUTPUT_LEN: usize = p256_keygen::MAX_DRBG_OUTPUT_LEN;

    fn base_point() -> Self::Point {
        Self::Point::from_affine(
            Self::Fe::from_limbs(p256_domain::G_X_LIMBS),
            Self::Fe::from_limbs(p256_domain::G_Y_LIMBS),
        )
    }

    fn multiply_base_point(k: &Self::Scalar) -> Self::Point {
        p256_comb::comb_multiply_base_point(k)
    }

    fn multiply_point(k: &Self::Scalar, q: &Self::Point) -> Self::Point {
        p256_mul::multiply_point(k, q)
    }

    fn shamir_multiply(
        u: &Self::PublicScalar,
        v: &Self::PublicScalar,
        q: &Self::Point,
    ) -> Self::Point {
        p256_wnaf::shamir_multiply(u, v, q)
    }

    fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Self::Scalar {
        p256_extra_bits::reduce_wide_bits_mod_n_minus_1(bytes)
    }

    fn keygen<const DRBG_LEN: usize>(
        rng: &mut dyn RNG,
    ) -> Result<GeneratedKeyPair<Self>, RNGError> {
        p256_keygen::keygen::<DRBG_LEN>(rng)
    }

    fn keygen_extra_bits(rng: &mut dyn RNG) -> Result<GeneratedKeyPair<Self>, RNGError> {
        p256_keygen::keygen::<{ Self::EXTRA_BITS_DRAW_LEN }>(rng)
    }

    fn public_point(d: &Self::Scalar) -> (Self::Fe, Self::Fe) {
        p256_keygen::public_point(d)
    }

    fn encode_uncompressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkUncompressed {
        p256_sec1::encode_uncompressed(x, y)
    }

    fn encode_compressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkCompressed {
        p256_sec1::encode_compressed(x, y)
    }

    fn decode(bytes: &[u8]) -> Option<(Self::Fe, Self::Fe)> {
        p256_sec1::decode(bytes)
    }

    fn limbs_from_be_bytes(bytes: &Self::ScalarBytes) -> Self::Limbs {
        p256_sec1::limbs_from_be_bytes(bytes)
    }

    fn limbs_from_be_bytes_into(bytes: &Self::ScalarBytes, out: &mut Self::Limbs) {
        p256_sec1::limbs_from_be_bytes_into(bytes, out)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::ScalarBytes {
        p256_sec1::be_bytes_from_limbs(limbs)
    }

    fn be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::ScalarBytes) {
        p256_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn fe_be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::FeBytes {
        p256_sec1::be_bytes_from_limbs(limbs)
    }

    fn fe_be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::FeBytes) {
        p256_sec1::be_bytes_from_limbs_into(limbs, out)
    }

    fn scalar_in_range(limbs: &Self::Limbs) -> Condition<u64> {
        limbs_in_range(limbs, &Self::N)
    }
}

const _: () = check_lengths::<P256>();
