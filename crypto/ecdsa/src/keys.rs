//! ECDSA P-256 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1).

use crate::extra_bits::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::p256::P256FieldElement;
use bouncycastle_ec::p256_comb::comb_multiply_base_point;
use bouncycastle_ec::p256_scalar::P256Scalar;
use bouncycastle_ec::p256_sec1;
use bouncycastle_rng::DefaultRNG;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a P-256 private key: SEC 1 §2.3.7 integer-to-octet-string of `d`, `ceil(log2
/// n / 8)` = 32 bytes.
pub const SK_LEN: usize = 32;

/// Encoded length of a P-256 public key in the canonical form [`ECDSAP256PublicKey::encode`]
/// emits: SEC 1 §2.3.3's uncompressed `04 || X || Y`, 65 bytes.
/// [`ECDSAP256PublicKey::from_bytes`] also accepts the 33-byte compressed form.
pub const PK_LEN: usize = 65;

/// Requested output length, in bytes, from the DRBG for FIPS 186-5 Appendix A.2.1 key generation
/// and Appendix A.3.1 randomised per-message secret generation: SP 800-186's Table A.2
/// "Recommended" column for a P-256-sized prime is 352 bits, i.e. `N + t` with `N = 256` and `t =
/// 96 >= 64`.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 44;

/// An ECDSA P-256 private key: FIPS 186-5 §6.2's `d`, `d` in `[1, n-1]`, held in
/// [`bouncycastle_utils::secret::Secret`] via [`P256Scalar`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSAP256PrivateKey(P256Scalar);

impl ECDSAP256PrivateKey {
    /// The wrapped scalar, for this crate's own sign implementation to compute with.
    pub(crate) fn scalar(&self) -> &P256Scalar {
        &self.0
    }
}

impl SignaturePrivateKey<SK_LEN> for ECDSAP256PrivateKey {
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
            SignatureError::DecodingError("ECDSA P-256 private key must be 32 bytes")
        })?;
        let scalar = P256Scalar::from_be_bytes(&array);
        // FIPS 186-5 §6.2: d is in [1, n-1]. Checking equality with the fixed public value 0 is a
        // one-time validation of caller-supplied bytes at load time, not a computation performed
        // repeatedly on a secret intermediate value, so branching on it (via `!=`, itself backed by
        // P256Scalar's constant-time PartialEq) leaks nothing beyond what the caller already knows
        // from having supplied these exact bytes.
        if scalar == P256Scalar::from_limbs([0, 0, 0, 0]) {
            return Err(SignatureError::DecodingError(
                "ECDSA P-256 private key must be in [1, n-1], got 0",
            ));
        }
        Ok(Self(scalar))
    }
}

/// An ECDSA P-256 public key: FIPS 186-5 §6.2's `Q = [d]G`, stored as affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECDSAP256PublicKey {
    pub(crate) x: P256FieldElement,
    pub(crate) y: P256FieldElement,
}

impl SignaturePublicKey<PK_LEN> for ECDSAP256PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        p256_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    /// Accepts both SEC 1 §2.3.3 encodings (33-byte compressed, 65-byte uncompressed), fully
    /// validated per SP 800-186 Appendix D.1.1.1 (see [`p256_sec1::decode`]'s docs).
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let (x, y) = p256_sec1::decode(bytes).ok_or(SignatureError::DecodingError(
            "invalid or out-of-range SEC 1 P-256 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for ECDSAP256PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECDSAP256PublicKey {{ {:x?} }}", self.encode())
    }
}

/// FIPS 186-5 Appendix A.2.1: generates an ECDSA P-256 key pair, sourcing the DRBG output from the
/// library's default OS-backed RNG.
pub fn keygen() -> Result<(ECDSAP256PublicKey, ECDSAP256PrivateKey), SignatureError> {
    keygen_from_rng(&mut DefaultRNG::default())
}

/// As [`keygen`], but sources the DRBG output from the caller-provided RNG.
pub fn keygen_from_rng(
    rng: &mut dyn RNG,
) -> Result<(ECDSAP256PublicKey, ECDSAP256PrivateKey), SignatureError> {
    let mut extra_bits = [0u8; EXTRA_BITS_DRBG_OUTPUT_LEN];
    rng.next_bytes_out(&mut extra_bits).map_err(SignatureError::RNGError)?;
    let d = reduce_wide_bits_mod_n_minus_1(&extra_bits);

    let q = comb_multiply_base_point(&d);
    // d is in [1, n-1] by construction (see reduce_wide_bits_mod_n_minus_1) and G has prime order
    // n (SP 800-186 §3.2.1.3's cofactor h = 1), so [d]G is never the identity: this holds for every
    // valid d, so branching on it here leaks nothing about which d was drawn.
    let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");

    Ok((ECDSAP256PublicKey { x, y }, ECDSAP256PrivateKey(d)))
}
