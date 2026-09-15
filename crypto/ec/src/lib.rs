//! Constant-time elliptic-curve arithmetic over compile-time-selected Weierstrass curves.
//!
//! This crate is the "custom curve" math substrate: fixed-width limb arithmetic ([`nat`]) and,
//! per curve, a base-field implementation with a reduction tailored to that curve's prime. It
//! deliberately does not support a runtime-described generic curve (bc-java's `ECCurve.Fp`
//! equivalent): constant-time field arithmetic on secret values requires fixed-width limbs known
//! at compile time, not a `BigInteger`-shaped value whose own representation can vary with its
//! magnitude. See `local/ec_custom_curves_and_ecdsa_plan.md` §1 for the full argument.
//!
//! # Status
//!
//! P-256, P-384, P-521, and secp256k1 are all complete through domain parameters, branch-free
//! Jacobian point arithmetic, the scalar field, constant-time fixed-base scalar multiplication for
//! signing, variable-time Shamir's-trick multiplication for verification, and SEC 1 point
//! encoding/decoding with SP 800-186 (secp256k1: SEC 1 v2/SEC 2 v2) public-key validation. ECDSA
//! itself (key generation, sign, verify) is built on top of this in the separate
//! `bouncycastle-ecdsa` crate for P-256/P-384/P-521 so far; see
//! `local/ec_custom_curves_and_ecdsa_plan.md` §6 and §9 for the rest of the plan (secp256k1's own
//! ECDSA wiring, brainpool curves, SM2, CLI wiring, benches).
//!
//! # Security Considerations
//!
//! Every arithmetic primitive here is written to be branch-free and to avoid indexing by a
//! secret value, per this workspace's constant-time rules. See [`p256`]'s module docs for the
//! field's specific reduction algorithm and the reasoning behind it.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod bp256r1;
pub mod bp256r1_comb;
pub(crate) mod bp256r1_comb_table;
pub mod bp256r1_domain;
pub mod bp256r1_point;
pub mod bp256r1_scalar;
pub mod bp256r1_sec1;
pub mod bp256r1_wnaf;
pub mod montgomery;
pub mod nat;
pub mod p256;
pub mod p256_comb;
pub(crate) mod p256_comb_table;
pub mod p256_domain;
pub mod p256_point;
pub mod p256_scalar;
pub mod p256_sec1;
pub mod p256_wnaf;
pub mod p256k1;
pub mod p256k1_comb;
pub(crate) mod p256k1_comb_table;
pub mod p256k1_domain;
pub mod p256k1_point;
pub mod p256k1_scalar;
pub mod p256k1_sec1;
pub mod p256k1_wnaf;
pub mod p384;
pub mod p384_comb;
pub(crate) mod p384_comb_table;
pub mod p384_domain;
pub mod p384_point;
pub mod p384_scalar;
pub mod p384_sec1;
pub mod p384_wnaf;
pub mod p521;
pub mod p521_comb;
pub(crate) mod p521_comb_table;
pub mod p521_domain;
pub mod p521_point;
pub mod p521_scalar;
pub mod p521_sec1;
pub mod p521_wnaf;
