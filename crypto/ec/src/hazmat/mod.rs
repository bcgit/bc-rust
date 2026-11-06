//! Raw primitives whose safe use is the caller's responsibility; see [`bouncycastle_core::hazmat`]
//! for what the path means and the supported uses.
//!
//! Everything curve-specific lives here, per curve: the base field, the scalar field, Jacobian
//! points with public coordinates, the comb, wNAF and constant-time variable-base multipliers, the
//! SEC 1 codec and the domain parameters. Each is correct on its own and composes nothing: a point
//! is checked against the curve equation only by its curve's `*_sec1::decode_point`, the
//! multipliers take any scalar and `*_mul::multiply_point` any point that passed that check, and
//! the wNAF multiplier and the `*PublicScalar` types are variable-time by design. The signature
//! crates are the intended callers, and the crate docs' Security Considerations apply to every
//! item here. The generic limb arithmetic ([`crate::nat`], [`crate::montgomery`],
//! [`crate::barrett`], [`crate::inverse_vartime`]) is not curve-specific and stays at the root.

pub mod bp256r1;
pub mod bp256r1_comb;
pub(crate) mod bp256r1_comb_table;
pub mod bp256r1_domain;
pub mod bp256r1_extra_bits;
pub mod bp256r1_mul;
pub mod bp256r1_point;
pub mod bp256r1_scalar;
pub mod bp256r1_sec1;
pub mod bp256r1_wnaf;
pub(crate) mod bp256r1_wnaf_table;
pub mod bp384r1;
pub mod bp384r1_comb;
pub(crate) mod bp384r1_comb_table;
pub mod bp384r1_domain;
pub mod bp384r1_extra_bits;
pub mod bp384r1_mul;
pub mod bp384r1_point;
pub mod bp384r1_scalar;
pub mod bp384r1_sec1;
pub mod bp384r1_wnaf;
pub(crate) mod bp384r1_wnaf_table;
pub mod bp512r1;
pub mod bp512r1_comb;
pub(crate) mod bp512r1_comb_table;
pub mod bp512r1_domain;
pub mod bp512r1_extra_bits;
pub mod bp512r1_mul;
pub mod bp512r1_point;
pub mod bp512r1_scalar;
pub mod bp512r1_sec1;
pub mod bp512r1_wnaf;
pub(crate) mod bp512r1_wnaf_table;
pub mod p256;
pub mod p256_comb;
pub(crate) mod p256_comb_table;
pub mod p256_domain;
pub mod p256_extra_bits;
pub mod p256_mul;
pub mod p256_point;
pub mod p256_scalar;
pub mod p256_sec1;
pub mod p256_wnaf;
pub(crate) mod p256_wnaf_table;
pub mod p256k1;
pub mod p256k1_comb;
pub(crate) mod p256k1_comb_table;
pub mod p256k1_domain;
pub mod p256k1_extra_bits;
pub mod p256k1_mul;
pub mod p256k1_point;
pub mod p256k1_scalar;
pub mod p256k1_sec1;
pub mod p256k1_wnaf;
pub(crate) mod p256k1_wnaf_table;
pub mod p384;
pub mod p384_comb;
pub(crate) mod p384_comb_table;
pub mod p384_domain;
pub mod p384_extra_bits;
pub mod p384_mul;
pub mod p384_point;
pub mod p384_scalar;
pub mod p384_sec1;
pub mod p384_wnaf;
pub(crate) mod p384_wnaf_table;
pub mod p521;
pub mod p521_comb;
pub(crate) mod p521_comb_table;
pub mod p521_domain;
pub mod p521_extra_bits;
pub mod p521_mul;
pub mod p521_point;
pub mod p521_scalar;
pub mod p521_sec1;
pub mod p521_wnaf;
pub(crate) mod p521_wnaf_table;
pub mod sm2;
pub mod sm2_comb;
pub(crate) mod sm2_comb_table;
pub mod sm2_domain;
pub mod sm2_point;
pub mod sm2_scalar;
pub mod sm2_sec1;
pub mod sm2_wnaf;
pub(crate) mod sm2_wnaf_table;
