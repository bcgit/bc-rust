//! ECDSA key types over any [`Curve`] and hash, and key-pair generation (FIPS 186-5 Section 6.2
//! and Appendix A.2.1). A key names the pairing it signs or verifies under,
//! [`ECDSA<C, H>`](crate::ecdsa::ECDSA), so that `sk.sign(..)` and `pk.verify(..)` resolve
//! without naming the algorithm at the call: `ECDSAPrivateKey<P256, SHA256>` is the
//! ECDSA-P256-SHA256 key, spelled in full since the customary pairing is a convention that
//! moves, and [`ECDSAPrivateKey::with_hash`] re-pairs the same key bytes with another hash.

use crate::ecdsa::EcdsaHash;
use crate::keys_common::{DerivePublicKey, SignatureKeyPair};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::curve::{Curve, SecretScalar, private_scalar_from_be_bytes};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::marker::PhantomData;

/// An ECDSA private key for `ECDSA<C, H>`: FIPS 186-5 Section 6.2's `d`, in `[1, n-1]`, held
/// in [`bouncycastle_utils::secret::Secret`] via the curve's scalar type. Encoded as SEC 1
/// Section 2.3.7's integer-to-octet-string of `d`, `C::SCALAR_LEN` bytes, the same under every
/// hash.
pub struct ECDSAPrivateKey<C: Curve, H: EcdsaHash> {
    d: C::Scalar,
    _hash: PhantomData<H>,
}

impl<C: Curve, H: EcdsaHash> ECDSAPrivateKey<C, H> {
    /// The wrapped scalar, for this crate's own signers to compute with.
    pub(crate) fn scalar(&self) -> &C::Scalar {
        &self.d
    }

    /// The same key under another hash: ECDSA-P256-SHA384 from an ECDSA-P256-SHA256 key, say.
    pub fn with_hash<H2: EcdsaHash>(self) -> ECDSAPrivateKey<C, H2> {
        ECDSAPrivateKey { d: self.d, _hash: PhantomData }
    }
}

impl<C, H: EcdsaHash, const PK_LEN: usize> DerivePublicKey<ECDSAPublicKey<C, H>, PK_LEN>
    for ECDSAPrivateKey<C, H>
where
    C: Curve<PkUncompressed = [u8; PK_LEN]>,
{
    fn derive_pk(&self) -> ECDSAPublicKey<C, H> {
        let (x, y) = C::public_point(&self.d);
        ECDSAPublicKey { x, y, _hash: PhantomData }
    }
}

impl<C, H: EcdsaHash, const SK_LEN: usize> SignaturePrivateKey<SK_LEN> for ECDSAPrivateKey<C, H>
where
    C: Curve<ScalarBytes = [u8; SK_LEN]>,
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.d.to_be_bytes()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);
        *out = self.d.to_be_bytes();
        SK_LEN
    }

    /// FIPS 186-5 Section 6.2: `d` is in `[1, n-1]`, checked on the raw big-endian value before
    /// any reduction, so that `d = n + 1` is refused rather than loaded as `d = 1` (one key would
    /// otherwise have unboundedly many encodings); the check and the load are
    /// [`private_scalar_from_be_bytes`], which stages the candidate in a `Secret` and reveals only
    /// whether the key loaded.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; SK_LEN] = bytes.try_into().map_err(|_| {
            SignatureError::DecodingError("an ECDSA private key is the curve's scalar length")
        })?;
        private_scalar_from_be_bytes::<C>(bytes)
            .map(|d| Self { d, _hash: PhantomData })
            .ok_or(SignatureError::DecodingError("ECDSA private key must be in [1, n-1]"))
    }
}

/// An ECDSA public key for `ECDSA<C, H>`: FIPS 186-5 Section 6.2's `Q = [d]G`, stored as
/// affine coordinates. Encoded as SEC 1 Section 2.3.3's uncompressed `04 || X || Y`,
/// `C::PK_UNCOMPRESSED_LEN` bytes, the same under every hash; the compressed form is also
/// accepted on decode.
pub struct ECDSAPublicKey<C: Curve, H: EcdsaHash> {
    pub(crate) x: C::Fe,
    pub(crate) y: C::Fe,
    _hash: PhantomData<H>,
}

impl<C: Curve, H: EcdsaHash> ECDSAPublicKey<C, H> {
    /// The same key under another hash, for verifying what was signed with it.
    pub fn with_hash<H2: EcdsaHash>(self) -> ECDSAPublicKey<C, H2> {
        ECDSAPublicKey { x: self.x, y: self.y, _hash: PhantomData }
    }
}

impl<C, H: EcdsaHash, const PK_LEN: usize> SignaturePublicKey<PK_LEN> for ECDSAPublicKey<C, H>
where
    C: Curve<PkUncompressed = [u8; PK_LEN]>,
{
    fn encode(&self) -> [u8; PK_LEN] {
        C::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    /// Accepts both SEC 1 Section 2.3.3 encodings (compressed and uncompressed), validated by the
    /// curve's decoder as SP 800-186 Appendix D.1.1.1 asks: coordinates in `[0, p-1]` and on the
    /// curve. A point off the curve is refused here, so it never reaches a verification.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let (x, y) = C::decode(bytes).ok_or(SignatureError::DecodingError(
            "invalid or out-of-range SEC 1 point encoding for the curve",
        ))?;
        Ok(Self { x, y, _hash: PhantomData })
    }
}

impl<C: Curve, H: EcdsaHash> Display for ECDSAPublicKey<C, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ECDSAPublicKey<{}, {}> {{ {:x?} }}",
            C::NAME,
            H::ALG_NAME,
            C::encode_uncompressed(&self.x, &self.y).as_ref()
        )
    }
}

/// FIPS 186-5 Appendix A.2.1, key-pair generation using extra random bits, from the caller's
/// RNG, which must offer the curve's strength (step 3: "a security strength of
/// requested_security_strength ... or more", the one SP 800-57 Part 1 Rev. 5 Table 2 associates
/// with the order's length): the draw is the curve's
/// [`keygen_extra_bits`](Curve::keygen_extra_bits), Table A.2's recommended length.
///
/// # Errors
/// [`SignatureError::RNGError`] if the RNG is weaker than the curve or fails to deliver.
pub fn keygen<C: Curve, H: EcdsaHash>(
    rng: &mut dyn RNG,
) -> Result<(ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>), SignatureError> {
    let (d, (x, y)) = C::keygen_extra_bits(rng)?;
    Ok((ECDSAPublicKey { x, y, _hash: PhantomData }, ECDSAPrivateKey { d, _hash: PhantomData }))
}

/// Every curve's [`generate_signature_key_pair`](SignatureKeyPair::generate_signature_key_pair)
/// is [`keygen`].
impl<C: Curve> SignatureKeyPair for C {
    fn generate_signature_key_pair<H: EcdsaHash>(
        rng: &mut dyn RNG,
    ) -> Result<(ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>), SignatureError> {
        keygen::<C, H>(rng)
    }
}

// The derives would bound `H` as well as the fields, so these are written out: the hash is a
// marker and takes no part in cloning, comparing or printing a key.

impl<C: Curve, H: EcdsaHash> Clone for ECDSAPrivateKey<C, H> {
    fn clone(&self) -> Self {
        Self { d: self.d.clone(), _hash: PhantomData }
    }
}

impl<C: Curve, H: EcdsaHash> Debug for ECDSAPrivateKey<C, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ECDSAPrivateKey").field("d", &self.d).finish()
    }
}

impl<C: Curve, H: EcdsaHash> PartialEq for ECDSAPrivateKey<C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.d == other.d
    }
}

impl<C: Curve, H: EcdsaHash> Eq for ECDSAPrivateKey<C, H> {}

impl<C: Curve, H: EcdsaHash> Clone for ECDSAPublicKey<C, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: Curve, H: EcdsaHash> Copy for ECDSAPublicKey<C, H> {}

impl<C: Curve, H: EcdsaHash> Debug for ECDSAPublicKey<C, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ECDSAPublicKey").field("x", &self.x).field("y", &self.y).finish()
    }
}

impl<C: Curve, H: EcdsaHash> PartialEq for ECDSAPublicKey<C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.x == other.x && self.y == other.y
    }
}

impl<C: Curve, H: EcdsaHash> Eq for ECDSAPublicKey<C, H> {}
