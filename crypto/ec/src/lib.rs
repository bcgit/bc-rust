//! Constant-time elliptic-curve arithmetic over compile-time-selected Weierstrass curves.
//!
//! This crate is the "custom curve" math substrate: fixed-width limb arithmetic ([`nat`]) and,
//! per curve, a base-field implementation with a reduction tailored to that curve's prime.
//!
//! It deliberately does not support a runtime-described generic curve (bc-java's `ECCurve.Fp`
//! equivalent), and that is a constant-time decision rather than a scope one. Field arithmetic on
//! a secret value has to run in the same time whatever the value is, which needs limbs of a fixed
//! width known at compile time; a `BigInteger`-shaped value leaks the magnitude of a secret
//! through the length of its own internal representation, quite apart from its arithmetic being
//! variable-time. bc-java says as much about its own generic path, in `ECConstantTimeMultiplier`'s
//! class comment: the guarantee "stops at the field layer", because under a generic `ECCurve.Fp`
//! "the field operations under the point arithmetic are BigInteger-based and their timing can vary
//! with operand values". So the custom path is not an optimisation here -- it is the only path on
//! which constant-time signing is achievable at all. The cost, accepted deliberately, is that
//! curves are types chosen at compile time and the supported set is fixed by what is implemented.
//!
//! # Usage Examples
//!
//! Most callers want [`bouncycastle_ecdsa`](../bouncycastle_ecdsa/index.html) or
//! [`bouncycastle_sm2`](../bouncycastle_sm2/index.html) rather than this crate directly; what
//! follows is the layer underneath them.
//!
//! Field arithmetic, per curve:
//!
//! ```
//! use bouncycastle_ec::p256::P256FieldElement;
//!
//! let a = P256FieldElement::from_limbs([7, 0, 0, 0]);
//! let b = P256FieldElement::from_limbs([3, 0, 0, 0]);
//!
//! assert_eq!(a.add(&b), P256FieldElement::from_limbs([10, 0, 0, 0]));
//! assert_eq!(a.sub(&b), P256FieldElement::from_limbs([4, 0, 0, 0]));
//! assert_eq!(a.mul(&b), P256FieldElement::from_limbs([21, 0, 0, 0]));
//! assert_eq!(a.square(), a.mul(&a));
//! assert_eq!(a.mul(&a.invert()), P256FieldElement::ONE);
//! ```
//!
//! `[k]G` for a secret scalar, the operation signing is built on. The scalar type is
//! [`p256_scalar::P256Scalar`], which wraps its value in
//! [`bouncycastle_utils::secret::Secret`]; the multiplier is branch-free in `k`:
//!
//! ```
//! use bouncycastle_ec::p256_comb::comb_multiply_base_point;
//! use bouncycastle_ec::p256_scalar::P256Scalar;
//!
//! let k = P256Scalar::from_limbs([42, 0, 0, 0]);
//! let point = comb_multiply_base_point(&k);
//! let (x, _y) = point.to_affine().expect("[k]G is not the identity for k in [1, n-1]");
//! # let _ = x;
//! ```
//!
//! `[u]G + [v]Q` for *public* scalars, the operation verification is built on. A separate scalar
//! type ([`p256_scalar::P256PublicScalar`]) selects the variable-time multiplier, so a secret
//! scalar cannot reach it by accident -- the type system enforces the split rather than a
//! reviewer:
//!
//! ```
//! use bouncycastle_ec::p256::P256FieldElement;
//! use bouncycastle_ec::p256_domain::{G_X_LIMBS, G_Y_LIMBS};
//! use bouncycastle_ec::p256_point::P256JacobianPoint;
//! use bouncycastle_ec::p256_scalar::P256PublicScalar;
//! use bouncycastle_ec::p256_wnaf::shamir_multiply;
//!
//! let g = P256JacobianPoint::from_affine(
//!     P256FieldElement::from_limbs(G_X_LIMBS),
//!     P256FieldElement::from_limbs(G_Y_LIMBS),
//! );
//! let u = P256PublicScalar::from_limbs([3, 0, 0, 0]);
//! let v = P256PublicScalar::from_limbs([5, 0, 0, 0]);
//!
//! // [3]G + [5]([2]G) == [13]G
//! assert_eq!(
//!     shamir_multiply(&u, &v, &g.double()).to_affine(),
//!     comb_thirteen_g().to_affine(),
//! );
//! # fn comb_thirteen_g() -> P256JacobianPoint {
//! #     use bouncycastle_ec::p256_comb::comb_multiply_base_point;
//! #     use bouncycastle_ec::p256_scalar::P256Scalar;
//! #     comb_multiply_base_point(&P256Scalar::from_limbs([13, 0, 0, 0]))
//! # }
//! ```
//!
//! SEC 1 encoding and decoding, with the SP 800-186 Appendix D.1.1.1 validation that decoding a
//! public key requires:
//!
//! ```
//! use bouncycastle_ec::p256_sec1;
//!
//! let (x, y) = p256_sec1::decode(&hex_g()).expect("G is a valid uncompressed point");
//! assert_eq!(p256_sec1::encode_uncompressed(&x, &y), hex_g());
//! assert!(p256_sec1::decode(&[0x04; 65]).is_none(), "not on the curve");
//! # fn hex_g() -> [u8; 65] {
//! #     use bouncycastle_ec::p256::P256FieldElement;
//! #     use bouncycastle_ec::p256_domain::{G_X_LIMBS, G_Y_LIMBS};
//! #     bouncycastle_ec::p256_sec1::encode_uncompressed(
//! #         &P256FieldElement::from_limbs(G_X_LIMBS),
//! #         &P256FieldElement::from_limbs(G_Y_LIMBS),
//! #     )
//! # }
//! ```
//!
//! Every curve exposes the same shape, with its own module prefix: `p256`, `p384`, `p521`,
//! `p256k1`, `bp256r1`, `bp384r1`, `bp512r1`, `sm2`.
//!
//! # Status
//!
//! All eight curves -- P-256, P-384, P-521, secp256k1, brainpoolP256r1, brainpoolP384r1,
//! brainpoolP512r1 and SM2 -- are complete through domain parameters, branch-free Jacobian point
//! arithmetic, the scalar field, constant-time fixed-base scalar multiplication for signing,
//! variable-time Shamir's-trick multiplication for verification, and SEC 1 point
//! encoding/decoding with public-key validation (SP 800-186 Appendix D.1.1.1; SEC 1 v2/SEC 2 v2
//! for secp256k1; RFC 5639 for the brainpool curves). Signature schemes built on top live in
//! [`bouncycastle_ecdsa`](../bouncycastle_ecdsa/index.html) (the seven ECDSA curves) and
//! [`bouncycastle_sm2`](../bouncycastle_sm2/index.html).
//!
//! # Memory Usage
//!
//! Every type here is a fixed-size array of `u64` limbs with no indirection, so its in-memory size
//! is fully determined by the curve's width. There is no heap allocation anywhere in this crate.
//!
//! | Curve           | `FieldElement` | `JacobianPoint` | `Scalar` | `ScalarField` |
//! |-----------------|----------------|-----------------|----------|---------------|
//! | P-256           | 32             | 96              | 32       | 32            |
//! | P-384           | 48             | 144             | 48       | 48            |
//! | P-521           | 72             | 216             | 72       | 72            |
//! | secp256k1       | 32             | 96              | 32       | 32            |
//! | brainpoolP256r1 | 32             | 96              | 32       | 32            |
//! | brainpoolP384r1 | 48             | 144             | 48       | 48            |
//! | brainpoolP512r1 | 64             | 192             | 64       | 64            |
//! | SM2             | 32             | 96              | 32       | 32            |
//!
//! All values are bytes, from `core::mem::size_of`. A `JacobianPoint` is three field elements
//! (`X`, `Y`, `Z`). P-521's 72 bytes hold a 521-bit value across 9 limbs rather than a tighter
//! bit-packing, which is why it exceeds the 66 bytes its SEC 1 encoding needs.
//!
//! The dominant *stack* cost is not these types but the fixed-base comb tables, which are `const`
//! data rather than stack: 64 entries of two field elements per curve (4 KiB for a 256-bit curve,
//! 9 KiB for P-521). [`p256_comb::comb_multiply_base_point`] scans all 64 entries under a mask on
//! every round, so that table is read in full regardless of the scalar -- see its docs. The
//! variable-time multiplier keeps a second, smaller `const` table per curve: the 32 odd multiples
//! of `G` its width-7 window over `G` indexes (2 KiB for a 256-bit curve, 4.5 KiB for P-521),
//! read by public digit and so with no scan.
//!
//! # Security Considerations
//!
//! Every arithmetic primitive here is written to be branch-free and to avoid indexing by a
//! secret value, per this workspace's constant-time rules. See [`p256`]'s module docs for the
//! field's specific reduction algorithm and the reasoning behind it.
//!
//! Three deliberate exceptions, all marked in their own docs, all reachable only through a type
//! that says so: [`p256_wnaf::shamir_multiply`] and its siblings take
//! [`p256_scalar::P256PublicScalar`] and branch freely, because verification operates entirely on
//! public data; `P256PublicScalar::invert_vartime` and its siblings invert a public scalar
//! (verification's `s`) by the binary extended Euclidean algorithm in [`inverse_vartime`], for
//! the same reason; and `JacobianPoint::to_affine` branches on the point being the identity, so
//! it is for output boundaries on already-public points, not for secret intermediates.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod barrett;
pub mod bp256r1;
pub mod bp256r1_comb;
pub(crate) mod bp256r1_comb_table;
pub mod bp256r1_domain;
pub mod bp256r1_point;
pub mod bp256r1_scalar;
pub mod bp256r1_sec1;
pub mod bp256r1_wnaf;
pub(crate) mod bp256r1_wnaf_table;
pub mod bp384r1;
pub mod bp384r1_comb;
pub(crate) mod bp384r1_comb_table;
pub mod bp384r1_domain;
pub mod bp384r1_point;
pub mod bp384r1_scalar;
pub mod bp384r1_sec1;
pub mod bp384r1_wnaf;
pub(crate) mod bp384r1_wnaf_table;
pub mod bp512r1;
pub mod bp512r1_comb;
pub(crate) mod bp512r1_comb_table;
pub mod bp512r1_domain;
pub mod bp512r1_point;
pub mod bp512r1_scalar;
pub mod bp512r1_sec1;
pub mod bp512r1_wnaf;
pub(crate) mod bp512r1_wnaf_table;
pub mod inverse_vartime;
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
pub(crate) mod p256_wnaf_table;
pub mod p256k1;
pub mod p256k1_comb;
pub(crate) mod p256k1_comb_table;
pub mod p256k1_domain;
pub mod p256k1_point;
pub mod p256k1_scalar;
pub mod p256k1_sec1;
pub mod p256k1_wnaf;
pub(crate) mod p256k1_wnaf_table;
pub mod p384;
pub mod p384_comb;
pub(crate) mod p384_comb_table;
pub mod p384_domain;
pub mod p384_point;
pub mod p384_scalar;
pub mod p384_sec1;
pub mod p384_wnaf;
pub(crate) mod p384_wnaf_table;
pub mod p521;
pub mod p521_comb;
pub(crate) mod p521_comb_table;
pub mod p521_domain;
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
