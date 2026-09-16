//! SM2 domain parameters, `draft-shen-sm2-ecdsa-02` Appendix D. `p` and `a = -3` live in
//! [`crate::sm2`] (the `a = -3` shortcut is baked directly into
//! [`crate::sm2_point::Sm2JacobianPoint::double`]); `n` lives in [`crate::sm2_scalar`]. This
//! module holds the rest: the curve coefficient `b` and the base point `G`.
//!
//! Values extracted directly from a freshly downloaded copy of the draft (not retyped, not from
//! recall) and verified in Python: `G` is on the curve and `n·G` is the point at infinity, before
//! any of this was ported to Rust.

/// The curve coefficient `b` in `y^2 = x^3 - 3x + b`, little-endian `u64` limbs.
pub const B_LIMBS: [u64; 4] =
    [0xddbcbd414d940e93, 0xf39789f515ab8f92, 0x4d5a9e4bcf6509a7, 0x28e9fa9e9d9f5e34];

/// The base point `G`'s `x` coordinate, little-endian `u64` limbs.
pub const G_X_LIMBS: [u64; 4] =
    [0x715a4589334c74c7, 0x8fe30bbff2660be1, 0x5f9904466a39c994, 0x32c4ae2c1f198119];

/// The base point `G`'s `y` coordinate, little-endian `u64` limbs.
pub const G_Y_LIMBS: [u64; 4] =
    [0x02df32e52139f0a0, 0xd0a9877cc62a4740, 0x59bdcee36b692153, 0xbc3736a2f4f6779c];
