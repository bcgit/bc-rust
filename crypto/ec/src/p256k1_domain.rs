//! secp256k1 domain parameters, SEC 2 v2 (Certicom, Jan 2010) §2.4.1. `p` lives in
//! [`crate::p256k1`] (`a = 0`, unlike every NIST curve in this crate -- see
//! [`crate::p256k1_point`]); `n` lives in [`crate::p256k1_scalar`]. This module holds the rest: the
//! curve coefficient `b` and the base point `G`.

/// The curve coefficient `b` in `y^2 = x^3 + b` (`a = 0`), little-endian `u64` limbs.
pub const B_LIMBS: [u64; 4] = [0x0000000000000007, 0, 0, 0];

/// The base point `G`'s `x` coordinate, little-endian `u64` limbs.
pub const G_X_LIMBS: [u64; 4] =
    [0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac];

/// The base point `G`'s `y` coordinate, little-endian `u64` limbs.
pub const G_Y_LIMBS: [u64; 4] =
    [0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465];
