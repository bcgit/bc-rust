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
//! P-256 and P-384 are both complete through domain parameters, branch-free Jacobian point
//! arithmetic ([`p256_point`]/[`p384_point`]), the scalar field ([`p256_scalar`]/[`p384_scalar`]),
//! constant-time fixed-base scalar multiplication for signing ([`p256_comb`]/[`p384_comb`]),
//! variable-time Shamir's-trick multiplication for verification ([`p256_wnaf`]/[`p384_wnaf`]), and
//! SEC 1 point encoding/decoding with SP 800-186 public-key validation
//! ([`p256_sec1`]/[`p384_sec1`]). ECDSA itself (key generation, sign, verify) is built on top of
//! this in the separate `bouncycastle-ecdsa` crate, P-256 only so far; see
//! `local/ec_custom_curves_and_ecdsa_plan.md` §6 and §9 for the rest of the plan (P-384's own
//! ECDSA wiring, P-521, secp256k1, other curves, CLI wiring, benches).
//!
//! # Security Considerations
//!
//! Every arithmetic primitive here is written to be branch-free and to avoid indexing by a
//! secret value, per this workspace's constant-time rules. See [`p256`]'s module docs for the
//! field's specific reduction algorithm and the reasoning behind it.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod nat;
pub mod p256;
pub mod p256_comb;
pub(crate) mod p256_comb_table;
pub mod p256_domain;
pub mod p256_point;
pub mod p256_scalar;
pub mod p256_sec1;
pub mod p256_wnaf;
pub mod p384;
pub mod p384_comb;
pub(crate) mod p384_comb_table;
pub mod p384_domain;
pub mod p384_point;
pub mod p384_scalar;
pub mod p384_sec1;
pub mod p384_wnaf;
