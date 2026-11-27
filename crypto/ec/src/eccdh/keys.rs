//! ECC CDH key types over any [`Curve`], and key-pair generation (SP 800-56A Rev. 3 Sections
//! 5.6.1.2.1, 5.6.2.1.2 and 5.6.2.3.3).

use crate::curve::{
    Curve, DECODE_STACK_FIXED, DECODE_STACK_PER_LIMB, ENCODE_STACK_FIXED, ENCODE_STACK_PER_LIMB,
    KEYGEN_STACK_FIXED, KEYGEN_STACK_PER_LIMB, SecretScalar, private_key_from_be_bytes,
    public_point_wiped,
};
use crate::eccdh::keys_common::{AgreementKeyPair, DerivePublicKey};
use bouncycastle_core::errors::{KeyAgreementError, KeyDecodingError};
use bouncycastle_core::traits::{PrivateKey, PublicKey, RNG};
use bouncycastle_utils::stack_wipe::in_wiped_frame_scaled;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// An ECC CDH private key: `d` in `[1, n-1]` (SP 800-56A Rev. 3 Section 5.6.2.1.2), held in
/// [`bouncycastle_utils::secret::Secret`] via the curve's scalar type. A key-establishment key:
/// never also a signing key (Section 5.6.3.2 item 5), which is why this is not the ECDSA type.
/// Encoded as SEC 1 Section 2.3.7's integer-to-octet-string of `d`, `C::SCALAR_LEN` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECCDHPrivateKey<C: Curve>(C::Scalar);

impl<C: Curve> ECCDHPrivateKey<C> {
    /// The wrapped scalar, for this module's own agreement to compute with.
    pub(in crate::eccdh) fn scalar(&self) -> &C::Scalar {
        &self.0
    }

    /// The key over a scalar already known to be in `[1, n-1]`.
    pub(in crate::eccdh) fn from_scalar(d: C::Scalar) -> Self {
        Self(d)
    }
}

impl<C, const PK_LEN: usize> DerivePublicKey<ECCDHPublicKey<C>, PK_LEN> for ECCDHPrivateKey<C>
where
    C: Curve<PkUncompressed = [u8; PK_LEN]>,
{
    fn derive_pk(&self) -> ECCDHPublicKey<C> {
        let (x, y) = public_point_wiped::<C>(&self.0);
        ECCDHPublicKey { x, y }
    }
}

impl<C, const SK_LEN: usize> PrivateKey<SK_LEN> for ECCDHPrivateKey<C>
where
    C: Curve<ScalarBytes = [u8; SK_LEN]>,
{
    // As the ECDSA key's: `encode` converts in a wiped frame and its array is written to the
    // caller's slot; `encode_out` writes straight into `out`.
    fn encode(&self) -> [u8; SK_LEN] {
        in_wiped_frame_scaled::<C::Limbs, ENCODE_STACK_PER_LIMB, ENCODE_STACK_FIXED, _>(|| {
            self.0.to_be_bytes()
        })
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        in_wiped_frame_scaled::<C::Limbs, ENCODE_STACK_PER_LIMB, ENCODE_STACK_FIXED, _>(|| {
            self.0.to_be_bytes_into(out)
        });
        SK_LEN
    }

    /// `d` must be in `[1, n-1]` (SP 800-56A Rev. 3 Section 5.6.2.1.2), checked on the raw
    /// big-endian value before any reduction, so that `d = n + 1` is refused rather than loaded
    /// as `d = 1`. The check and the load stage the candidate in a `Secret`, wipe the scalar it
    /// is reduced into, and reveal only whether the key loaded.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let bytes: &[u8; SK_LEN] = bytes
            .try_into()
            .map_err(|_| KeyDecodingError("an ECC CDH private key is the curve's scalar length"))?;
        // The key is built in the wiped frame, `Result` and all: the temporaries of the
        // conversion would otherwise hold a copy of `d` in this frame.
        in_wiped_frame_scaled::<C::Limbs, DECODE_STACK_PER_LIMB, DECODE_STACK_FIXED, _>(|| {
            private_key_from_be_bytes::<C, _>(
                bytes,
                |d| Ok(Self(d.clone())),
                || Err(KeyDecodingError("ECC CDH private key must be in [1, n-1]")),
            )
        })
    }
}

/// An ECC CDH public key: `Q = [d]G`, stored as affine coordinates. A key that exists has
/// passed full public-key validation (see [`PublicKey::from_bytes`]). Encoded as
/// SEC 1 Section 2.3.3's uncompressed `04 || X || Y`, `C::PK_UNCOMPRESSED_LEN` bytes; the
/// compressed form is also accepted on decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECCDHPublicKey<C: Curve> {
    pub(in crate::eccdh) x: C::Fe,
    pub(in crate::eccdh) y: C::Fe,
}

impl<C, const PK_LEN: usize> PublicKey<PK_LEN> for ECCDHPublicKey<C>
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

    /// Accepts both SEC 1 Section 2.3.3 encodings (compressed and uncompressed) and runs SP
    /// 800-56A Rev. 3 Section 5.6.2.3.3's full public-key validation, as the static keys of
    /// Section 5.6.2.2.1 require: steps 1 to 3 (not the identity, which no encoding expresses;
    /// coordinates in `[0, p-1]`; on the curve) are the curve's decoder's checks (SP 800-186
    /// Appendix D.1.1.1). Step 4, `nQ = O`, is not computed: every curve here has cofactor 1,
    /// so the curve group has prime order n and every point other than O has order n.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let (x, y) = C::decode(bytes).ok_or(KeyDecodingError(
            "invalid or out-of-range SEC 1 point encoding for the curve",
        ))?;
        Ok(Self { x, y })
    }
}

impl<C: Curve> Display for ECCDHPublicKey<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ECCDHPublicKey<{}> {{ {:x?} }}",
            C::NAME,
            C::encode_uncompressed(&self.x, &self.y).as_ref()
        )
    }
}

/// SP 800-56A Rev. 3 Section 5.6.1.2.1, key-pair generation using extra random bits, from the
/// caller's RNG, which must offer the curve's strength (step 4: "an RBG with a security
/// strength of s bits or more"; `s` from SP 800-57 Part 1 Rev. 5 Table 2): step 3's draw of at
/// least `N + 64` bits is the curve's [`keygen_extra_bits`](Curve::keygen_extra_bits).
///
/// # Errors
/// [`KeyAgreementError::RNGError`] if the RNG is weaker than the curve or fails to deliver.
pub fn keygen<C: Curve>(
    rng: &mut dyn RNG,
) -> Result<(ECCDHPublicKey<C>, ECCDHPrivateKey<C>), KeyAgreementError> {
    in_wiped_frame_scaled::<C::Limbs, KEYGEN_STACK_PER_LIMB, KEYGEN_STACK_FIXED, _>(|| {
        let (d, (x, y)) = C::keygen_extra_bits(rng)?;
        Ok((ECCDHPublicKey { x, y }, ECCDHPrivateKey(d)))
    })
}

/// Every curve's [`generate_agreement_key_pair`](AgreementKeyPair::generate_agreement_key_pair)
/// is [`keygen`].
impl<C: Curve> AgreementKeyPair for C {
    type PublicKey = ECCDHPublicKey<C>;
    type PrivateKey = ECCDHPrivateKey<C>;

    fn generate_agreement_key_pair(
        rng: &mut dyn RNG,
    ) -> Result<(ECCDHPublicKey<C>, ECCDHPrivateKey<C>), KeyAgreementError> {
        keygen::<C>(rng)
    }
}
