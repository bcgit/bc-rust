//! ECDSA P-521 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1). Identical in
//! shape to [`crate::keys_p384`] -- see that module's docs for the general reasoning -- with
//! P-521's types and SEC 1 encoding widths substituted.
//!
//! # DRBG output length, and why the reduction is the wide form
//!
//! FIPS 186-5 Table A.2 gives `p521` a required and recommended DRBG output of 521 bits for key
//! generation: `n` is within `2^260` of `2^521`, so the reduction's bias is negligible with no
//! headroom. But Appendix A.3.1 -- the randomised per-message secret -- requires `N + t` bits with
//! `t >= 64` regardless, so both draws are `N + 71 = 592` bits (74 bytes, the byte-aligned width
//! at or above `585`; `EXTRA_BITS_DRBG_OUTPUT_LEN`). An earlier version drew the 66-byte
//! `SK_LEN` (528 bits, `t = 7`) for both, which met Table A.2 but not A.3.1.
//!
//! Even at 528 bits the reduction had to handle a value far wider than `n`: 66 bytes is 7 bits more
//! than `n`'s 521 (SEC 1 octets are byte-aligned and 521 is not a multiple of 8), so a raw draw
//! reinterpreted as a 9-limb integer can be as large as `2^528 - 1`, far past the `< 2(n-1)` a
//! single conditional subtraction of `n - 1` assumes, and one subtraction silently leaves most of
//! the value unreduced (a bug this module's own tests caught: `keygen`/`ECDSAP521::sign` produced
//! keys/signatures too broken to round-trip through sign+verify, despite every fixed-input KAT --
//! which never exercises a raw, unbounded DRBG value -- passing). The reduction is
//! [`bouncycastle_ec::hazmat::p521_extra_bits`]'s single fold at bit 521 -- see its docs for why
//! P-521 gets neither the other curves' Barrett reduction nor the field's Solinas fold.

use crate::keys_common::DerivePublicKey;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::hazmat::p521::P521FieldElement;
use bouncycastle_ec::hazmat::p521_keygen;
use bouncycastle_ec::hazmat::p521_scalar::{N_LIMBS, P521Scalar};
use bouncycastle_ec::hazmat::p521_sec1;
use bouncycastle_ec::nat;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a P-521 private key: SEC 1 §2.3.7 integer-to-octet-string of `d`, 66 bytes.
pub const SK_LEN: usize = 66;

/// Encoded length of a P-521 public key in the canonical uncompressed form (SEC 1 §2.3.3,
/// `04 || X || Y`); [`ECDSAP521PublicKey::from_bytes`] also accepts the 67-byte compressed form.
pub const PK_LEN: usize = 133;

/// Requested output length, in bytes, from the DRBG for FIPS 186-5 Appendix A.2.1 key generation
/// and Appendix A.3.1 randomised per-message secret generation: the smallest whole number of bytes
/// holding `N + t` bits with `N = 521` and `t = 64`, i.e. `ceil(585 / 8) = 74` bytes (`t = 71`).
/// See the module docs.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 74;

/// An ECDSA P-521 private key: FIPS 186-5 §6.2's `d`, `d` in `[1, n-1]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSAP521PrivateKey(P521Scalar);

impl ECDSAP521PrivateKey {
    /// The wrapped scalar, for this crate's own sign implementation to compute with.
    pub(crate) fn scalar(&self) -> &P521Scalar {
        &self.0
    }
}

impl DerivePublicKey<ECDSAP521PublicKey, PK_LEN> for ECDSAP521PrivateKey {
    fn derive_pk(&self) -> ECDSAP521PublicKey {
        let (x, y) = p521_keygen::public_point(&self.0);
        ECDSAP521PublicKey { x, y }
    }
}

impl SignaturePrivateKey<SK_LEN> for ECDSAP521PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.0.to_be_bytes()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);
        *out = self.0.to_be_bytes();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let array: [u8; SK_LEN] = bytes.try_into().map_err(|_| {
            SignatureError::DecodingError("ECDSA P-521 private key must be 66 bytes")
        })?;
        // FIPS 186-5 §6.2: d is in [1, n-1], checked on the raw big-endian value *before* any
        // reduction. `P521Scalar::from_be_bytes` reduces mod n, so checking afterwards would accept
        // an out-of-range encoding as a different, perfectly valid key: `d = n + 1` would load as
        // `d = 1`, giving one key two encodings and silently treating malformed input as well-
        // formed. Comparing against the fixed public values 0 and n is a one-time validation of
        // caller-supplied bytes at load time, not a computation performed repeatedly on a secret
        // intermediate value, so branching on it leaks nothing beyond what the caller already knows
        // from having supplied these exact bytes.
        let limbs = p521_sec1::limbs_from_be_bytes(&array);
        let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
        if limbs == [0; 9] || borrow != 1 {
            return Err(SignatureError::DecodingError(
                "ECDSA P-521 private key must be in [1, n-1]",
            ));
        }
        Ok(Self(P521Scalar::from_limbs(limbs)))
    }
}

/// An ECDSA P-521 public key: FIPS 186-5 §6.2's `Q = [d]G`, stored as affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECDSAP521PublicKey {
    pub(crate) x: P521FieldElement,
    pub(crate) y: P521FieldElement,
}

impl SignaturePublicKey<PK_LEN> for ECDSAP521PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        p521_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let (x, y) = p521_sec1::decode(bytes).ok_or(SignatureError::DecodingError(
            "invalid or out-of-range SEC 1 P-521 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for ECDSAP521PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECDSAP521PublicKey {{ {:x?} }}", self.encode())
    }
}

/// As [`keygen`], but sources the DRBG output from the caller-provided RNG, which must
/// offer a security strength of at least 256 bits: FIPS 186-5 Appendix A.2.1 step 3 requires
/// a DRBG whose security strength is "not less than" the one SP 800-57 Part 1 Rev. 5's
/// Table 2 associates with P-521's 521-bit order (`f = 512+` in that table's ECC column, giving
/// 256-bit security).
pub fn keygen(
    rng: &mut dyn RNG,
) -> Result<(ECDSAP521PublicKey, ECDSAP521PrivateKey), SignatureError> {
    // The pair comes from ec's generator, which checks the RNG's strength, draws
    // EXTRA_BITS_DRBG_OUTPUT_LEN bytes and reduces them; this crate names the key types.
    let (d, (x, y)) = p521_keygen::keygen::<EXTRA_BITS_DRBG_OUTPUT_LEN>(rng)?;
    Ok((ECDSAP521PublicKey { x, y }, ECDSAP521PrivateKey(d)))
}
