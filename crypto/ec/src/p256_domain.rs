//! P-256 domain parameters, NIST SP 800-186 (Feb 2023) §3.2.1.3, cross-checked byte-for-byte
//! against bc-java's `SecP256R1Curve`/`SecP256R1Point` constants. `p` and `a = -3` live in
//! [`crate::p256`] (the `a = -3` shortcut is baked directly into
//! [`crate::p256_point::P256JacobianPoint::double`]); `n` lives in [`crate::p256_scalar`]. This
//! module holds the rest: the curve coefficient `b` and the base point `G`.

/// The curve coefficient `b` in `y^2 = x^3 - 3x + b`, little-endian `u64` limbs.
pub const B_LIMBS: [u64; 4] =
    [0x3bce3c3e27d2604b, 0x651d06b0cc53b0f6, 0xb3ebbd55769886bc, 0x5ac635d8aa3a93e7];

/// The base point `G`'s `x` coordinate, little-endian `u64` limbs.
pub const G_X_LIMBS: [u64; 4] =
    [0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247];

/// The base point `G`'s `y` coordinate, little-endian `u64` limbs.
pub const G_Y_LIMBS: [u64; 4] =
    [0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b];
