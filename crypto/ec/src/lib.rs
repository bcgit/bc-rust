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
//! Only the P-256 base field ([`p256`]) exists so far -- limb arithmetic, field add/sub/negate,
//! multiply, and constant-time inversion. Point arithmetic, scalar multiplication, and SEC 1
//! encodings are not yet implemented.
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
pub mod p256_point;
pub mod p256_scalar;
pub mod p256_wnaf;
