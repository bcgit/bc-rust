//! SM2 key types (`draft-shen-sm2-ecdsa-02` §4, "Key Generation") and key-pair generation. Shaped
//! identically to `bouncycastle-ecdsa`'s per-curve `keys_*.rs` modules -- see that crate's
//! `keys_bp256r1` module's docs for the full reasoning -- with SM2's own field/scalar
//! types and the wide-DRBG-output reduction from [`crate::extra_bits`] substituted. The draft's §4
//! only says the private key `dA` is "a random number ... selected via a random number generator",
//! without specifying a DRBG-to-scalar conversion; this crate uses the same FIPS 186-5 Appendix
//! A.4.1 "extra random bits" method as every curve in `bouncycastle-ecdsa`, for the same reason (see
//! [`crate::extra_bits`]'s docs for the bias-bound derivation specific to SM2's `n`).

use crate::extra_bits::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::sm2::Sm2FieldElement;
use bouncycastle_ec::sm2_comb::comb_multiply_base_point;
use bouncycastle_ec::sm2_scalar::Sm2Scalar;
use bouncycastle_ec::sm2_sec1;
use bouncycastle_rng::DefaultRNG;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of an SM2 private key: SEC 1 §2.3.7 integer-to-octet-string of `dA`, 32 bytes.
pub const SK_LEN: usize = 32;

/// Encoded length of an SM2 public key in the canonical uncompressed form (SEC 1 §2.3.3, `04 || X
/// || Y`); [`SM2PublicKey::from_bytes`] also accepts the 33-byte compressed form.
pub const PK_LEN: usize = 65;

/// Requested output length, in bytes, from the DRBG for key generation and for the per-signature
/// secret `k` (`draft-shen-sm2-ecdsa-02` §5.1.3 step A3): `320` bits (40 bytes) -- derived directly
/// from FIPS 186-5 Appendix A.4.1's own bias-bound check for SM2's `n` (see [`crate::extra_bits`]'s
/// docs), not copied from any other curve's table entry.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 40;

/// An SM2 private key: `draft-shen-sm2-ecdsa-02` §4's `dA`, `dA` in `[1, n-1]`, held in
/// [`bouncycastle_utils::secret::Secret`] via [`Sm2Scalar`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SM2PrivateKey(Sm2Scalar);

impl SM2PrivateKey {
    /// The wrapped scalar, for this crate's own sign implementation to compute with.
    pub(crate) fn scalar(&self) -> &Sm2Scalar {
        &self.0
    }
}

impl SignaturePrivateKey<SK_LEN> for SM2PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.0.to_be_bytes()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);
        *out = self.0.to_be_bytes();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let array: [u8; SK_LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::DecodingError("SM2 private key must be 32 bytes"))?;
        let scalar = Sm2Scalar::from_be_bytes(&array);
        // draft-shen-sm2-ecdsa-02 S4: dA is in [1, n-1]. Checking equality with the fixed public
        // value 0 is a one-time validation of caller-supplied bytes at load time, not a computation
        // performed repeatedly on a secret intermediate value, so branching on it here leaks
        // nothing beyond what the caller already knows from having supplied these exact bytes.
        if scalar == Sm2Scalar::from_limbs([0, 0, 0, 0]) {
            return Err(SignatureError::DecodingError(
                "SM2 private key must be in [1, n-1], got 0",
            ));
        }
        Ok(Self(scalar))
    }
}

/// An SM2 public key: `draft-shen-sm2-ecdsa-02` §4's `PA = [dA]G`, stored as affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SM2PublicKey {
    pub(crate) x: Sm2FieldElement,
    pub(crate) y: Sm2FieldElement,
}

impl SignaturePublicKey<PK_LEN> for SM2PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        sm2_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    /// Accepts both SEC 1 §2.3.3 encodings (33-byte compressed, 65-byte uncompressed), fully
    /// validated per [`sm2_sec1::decode`]'s docs (partial validation is full validation here: SM2's
    /// cofactor is `h = 1`, per that module's docs).
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let (x, y) = sm2_sec1::decode(bytes).ok_or(SignatureError::DecodingError(
            "invalid or out-of-range SEC 1 SM2 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for SM2PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "SM2PublicKey {{ {:x?} }}", self.encode())
    }
}

impl SM2PublicKey {
    /// The public key's affine `x`, `y` coordinates -- for [`crate::za`]'s `ZA` computation, which
    /// needs them directly rather than through the SEC 1 encoding.
    pub(crate) fn affine(&self) -> (Sm2FieldElement, Sm2FieldElement) {
        (self.x, self.y)
    }
}

/// Generates an SM2 key pair, sourcing the DRBG output from the library's default OS-backed RNG.
pub fn keygen() -> Result<(SM2PublicKey, SM2PrivateKey), SignatureError> {
    keygen_from_rng(&mut DefaultRNG::default())
}

/// As [`keygen`], but sources the DRBG output from the caller-provided RNG.
pub fn keygen_from_rng(rng: &mut dyn RNG) -> Result<(SM2PublicKey, SM2PrivateKey), SignatureError> {
    let mut extra_bits = [0u8; EXTRA_BITS_DRBG_OUTPUT_LEN];
    rng.next_bytes_out(&mut extra_bits).map_err(SignatureError::RNGError)?;
    let d = reduce_wide_bits_mod_n_minus_1(&extra_bits);

    let q = comb_multiply_base_point(&d);
    // d is in [1, n-1] by construction (see reduce_wide_bits_mod_n_minus_1) and G has prime order n
    // (SM2's cofactor h = 1, per bouncycastle_ec::sm2_sec1's docs), so [d]G is never the identity:
    // this holds for every valid d, so branching on it here leaks nothing about which d was drawn.
    let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");

    Ok((SM2PublicKey { x, y }, SM2PrivateKey(d)))
}
