//! ECDSA key types over any [`Curve`] and hash, and key-pair generation (FIPS 186-5 Section 6.2
//! and Appendix A.2.1). A key names the pairing it signs or verifies under,
//! [`ECDSA<C, H>`](crate::ecdsa::ecdsa::ECDSA), so that `sk.sign(..)` and `pk.verify(..)` resolve
//! without naming the algorithm at the call: `ECDSAPrivateKey<P256, SHA256>` is the
//! ECDSA-P256-SHA256 key, spelled in full since the customary pairing is a convention that
//! moves, and [`ECDSAPrivateKey::with_hash`] re-pairs the same key bytes with another hash.

use crate::curve::{
    Curve, DECODE_STACK_FIXED, DECODE_STACK_PER_LIMB, ENCODE_STACK_FIXED, ENCODE_STACK_PER_LIMB,
    KEYGEN_STACK_FIXED, KEYGEN_STACK_PER_LIMB, SecretScalar, keygen_scalar_into,
    private_key_from_be_bytes, public_point_wiped, scalar_is_filled, zero_scalar,
};
use crate::ecdsa::ecdsa::EcdsaHash;
use crate::ecdsa::keys_common::SignatureKeyPair;
use bouncycastle_core::errors::{KeyDecodingError, KeyMaterialError, SignatureError};
use bouncycastle_core::traits::{
    CollisionResistantHash, KeyPairGenerator, PrivateKey, PublicKey, RNG,
};
use bouncycastle_utils::stack_wipe::in_wiped_frame_scaled;
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
    /// The key [`keygen_out`] writes into, so that `d` is reduced where it will live and never
    /// moved: `d = 0`, which is not a key. Until `keygen_out` fills it, it has no public key and
    /// signs nothing ([`KeyMaterialError::ActingOnZeroizedKey`]), and it is equal to no key that
    /// was generated or decoded.
    ///
    /// # 🚨 Security Considerations 🚨
    ///
    /// The encoding of this key is not refused, the encoding methods having no error to give: it
    /// is all zero, which decodes as no key. Do not store or send the encoding of a key whose
    /// generation failed.
    pub fn zeroized() -> Self {
        Self { d: zero_scalar::<C>(), _hash: PhantomData }
    }

    /// Whether the key has been generated or decoded, which `d != 0` says.
    pub(in crate::ecdsa) fn check_filled(&self) -> Result<(), SignatureError> {
        if scalar_is_filled::<C>(&self.d) {
            Ok(())
        } else {
            Err(KeyMaterialError::ActingOnZeroizedKey.into())
        }
    }

    /// Recomputes the public key `Q = [d]G` from `d`, with the fixed-base multiplier
    /// [`keygen`] uses.
    ///
    /// # Errors
    /// [`KeyMaterialError::ActingOnZeroizedKey`] for a key that was never filled.
    pub fn pub_key(&self) -> Result<ECDSAPublicKey<C, H>, SignatureError> {
        self.check_filled()?;
        let (x, y) = public_point_wiped::<C>(&self.d);
        Ok(ECDSAPublicKey { x, y, _hash: PhantomData })
    }

    /// The wrapped scalar, for this module's own signers to compute with.
    pub(in crate::ecdsa) fn scalar(&self) -> &C::Scalar {
        &self.d
    }

    /// A copy of this key under another hash: ECDSA-P256-SHA384 from an ECDSA-P256-SHA256 key,
    /// say. Both keys hold `d` and wipe it when dropped.
    // By reference: taking `self` by value would move `d` out of the caller's slot, which
    // nothing wipes.
    pub fn with_hash<H2: EcdsaHash>(&self) -> ECDSAPrivateKey<C, H2> {
        ECDSAPrivateKey { d: self.d.clone(), _hash: PhantomData }
    }
}

impl<C: Curve, H: EcdsaHash + CollisionResistantHash> KeyPairGenerator for ECDSAPrivateKey<C, H> {
    type PublicKey = ECDSAPublicKey<C, H>;
    type Error = SignatureError;

    fn zeroized() -> Self {
        Self::zeroized()
    }

    fn generate_out(rng: &mut dyn RNG, sk: &mut Self) -> Result<(), SignatureError> {
        keygen_out(rng, sk)
    }

    fn pub_key(&self) -> Result<ECDSAPublicKey<C, H>, SignatureError> {
        self.pub_key()
    }
}

impl<C, H: EcdsaHash, const SK_LEN: usize> PrivateKey<SK_LEN> for ECDSAPrivateKey<C, H>
where
    C: Curve<ScalarBytes = [u8; SK_LEN]>,
{
    // `encode` converts in a wiped frame, whose conversion stages the bytes of `d`, and the array
    // it returns is written to the caller's slot, not staged above that frame. `encode_out`
    // writes the bytes straight into `out`, staging none.
    fn encode(&self) -> [u8; SK_LEN] {
        in_wiped_frame_scaled::<C::Limbs, ENCODE_STACK_PER_LIMB, ENCODE_STACK_FIXED, _>(|| {
            self.d.to_be_bytes()
        })
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        in_wiped_frame_scaled::<C::Limbs, ENCODE_STACK_PER_LIMB, ENCODE_STACK_FIXED, _>(|| {
            self.d.to_be_bytes_into(out)
        });
        SK_LEN
    }

    /// FIPS 186-5 Section 6.2: `d` is in `[1, n-1]`, checked on the raw big-endian value before
    /// any reduction, so that `d = n + 1` is refused rather than loaded as `d = 1` (one key would
    /// otherwise have unboundedly many encodings). The check and the load stage the candidate in
    /// a `Secret`, wipe the scalar it is reduced into, and reveal only whether the key loaded.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let bytes: &[u8; SK_LEN] = bytes
            .try_into()
            .map_err(|_| KeyDecodingError("an ECDSA private key is the curve's scalar length"))?;
        // The key is built in the wiped frame, `Result` and all: the temporaries of the
        // conversion would otherwise hold a copy of `d` in this frame.
        in_wiped_frame_scaled::<C::Limbs, DECODE_STACK_PER_LIMB, DECODE_STACK_FIXED, _>(|| {
            private_key_from_be_bytes::<C, _>(
                bytes,
                |d| Ok(Self { d: d.clone(), _hash: PhantomData }),
                || Err(KeyDecodingError("ECDSA private key must be in [1, n-1]")),
            )
        })
    }
}

/// An ECDSA public key for `ECDSA<C, H>`: FIPS 186-5 Section 6.2's `Q = [d]G`, stored as
/// affine coordinates. Encoded as SEC 1 Section 2.3.3's uncompressed `04 || X || Y`,
/// `C::PK_UNCOMPRESSED_LEN` bytes, the same under every hash; the compressed form is also
/// accepted on decode.
pub struct ECDSAPublicKey<C: Curve, H: EcdsaHash> {
    pub(in crate::ecdsa) x: C::Fe,
    pub(in crate::ecdsa) y: C::Fe,
    _hash: PhantomData<H>,
}

impl<C: Curve, H: EcdsaHash> ECDSAPublicKey<C, H> {
    /// The same key under another hash, for verifying what was signed with it.
    pub fn with_hash<H2: EcdsaHash>(self) -> ECDSAPublicKey<C, H2> {
        ECDSAPublicKey { x: self.x, y: self.y, _hash: PhantomData }
    }
}

impl<C, H: EcdsaHash, const PK_LEN: usize> PublicKey<PK_LEN> for ECDSAPublicKey<C, H>
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
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let (x, y) = C::decode(bytes).ok_or(KeyDecodingError(
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
/// A pair is generated to sign with, so `H` is a [`CollisionResistantHash`]; a key over another
/// hash is decoded, or re-paired with [`with_hash`](ECDSAPublicKey::with_hash):
///
/// ```compile_fail,E0277
/// use bouncycastle_ec::P256;
/// use bouncycastle_ec::ecdsa::keys::keygen;
/// use bouncycastle_digest::ripemd::RIPEMD160;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let _ = keygen::<P256, RIPEMD160>(&mut HashDRBG_SHA512::new_from_os());
/// ```
///
/// [`keygen_out`] into a key you hold, moved out of this frame; a move wipes nothing.
///
/// # Errors
/// [`SignatureError::RNGError`] if the RNG is weaker than the curve or fails to deliver.
pub fn keygen<C: Curve, H: EcdsaHash + CollisionResistantHash>(
    rng: &mut dyn RNG,
) -> Result<(ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>), SignatureError> {
    in_wiped_frame_scaled::<C::Limbs, KEYGEN_STACK_PER_LIMB, KEYGEN_STACK_FIXED, _>(|| {
        let mut sk = ECDSAPrivateKey::zeroized();
        keygen_out(rng, &mut sk)?;
        let pk = sk.pub_key()?;
        Ok((pk, sk))
    })
}

/// As [`keygen`], into `sk`, a key you hold (made with
/// [`zeroized`](ECDSAPrivateKey::zeroized)): `d` is reduced from the RNG's output straight into
/// the key, in a frame whose stack is overwritten afterwards, so no copy of it is left on the
/// way. The same RNG output gives the same key as [`keygen`]. The public key is computed from the
/// key afterwards with [`pub_key`](ECDSAPrivateKey::pub_key), which cannot fail once this has
/// returned `Ok`. `sk` is zeroized first and left so on every error.
///
/// # Errors
/// As [`keygen`].
pub fn keygen_out<C: Curve, H: EcdsaHash + CollisionResistantHash>(
    rng: &mut dyn RNG,
    sk: &mut ECDSAPrivateKey<C, H>,
) -> Result<(), SignatureError> {
    sk.d = zero_scalar::<C>();
    let result =
        in_wiped_frame_scaled::<C::Limbs, KEYGEN_STACK_PER_LIMB, KEYGEN_STACK_FIXED, _>(|| {
            keygen_scalar_into::<C>(rng, &mut sk.d)
        });
    if let Err(e) = result {
        sk.d = zero_scalar::<C>();
        return Err(e.into());
    }
    Ok(())
}

/// Every curve's [`generate_signature_key_pair`](SignatureKeyPair::generate_signature_key_pair)
/// is [`keygen`], and its
/// [`generate_signature_key_out`](SignatureKeyPair::generate_signature_key_out) is
/// [`keygen_out`].
impl<C: Curve> SignatureKeyPair for C {
    fn generate_signature_key_pair<H: EcdsaHash + CollisionResistantHash>(
        rng: &mut dyn RNG,
    ) -> Result<(ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>), SignatureError> {
        keygen::<C, H>(rng)
    }

    fn generate_signature_key_out<H: EcdsaHash + CollisionResistantHash>(
        rng: &mut dyn RNG,
        sk: &mut ECDSAPrivateKey<C, H>,
    ) -> Result<(), SignatureError> {
        keygen_out::<C, H>(rng, sk)
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
