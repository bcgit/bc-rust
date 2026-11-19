//! ECC CDH key types over any [`Curve`], and key-pair generation (SP 800-56A Rev. 3 Sections
//! 5.6.1.2.1, 5.6.2.1.2 and 5.6.2.3.3).

use crate::keys_common::{AgreementKeyPair, DerivePublicKey};
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey, RNG};
use bouncycastle_ec::curve::{Curve, SecretScalar, private_scalar_from_be_bytes};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// An ECC CDH private key: `d` in `[1, n-1]` (SP 800-56A Rev. 3 Section 5.6.2.1.2), held in
/// [`bouncycastle_utils::secret::Secret`] via the curve's scalar type. A key-establishment key:
/// never also a signing key (Section 5.6.3.2 item 5), which is why this is not the ECDSA type.
/// Encoded as SEC 1 Section 2.3.7's integer-to-octet-string of `d`, `C::SCALAR_LEN` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECCDHPrivateKey<C: Curve>(C::Scalar);

impl<C: Curve> ECCDHPrivateKey<C> {
    /// The wrapped scalar, for this crate's own agreement to compute with.
    pub(crate) fn scalar(&self) -> &C::Scalar {
        &self.0
    }
}

impl<C, const PK_LEN: usize> DerivePublicKey<ECCDHPublicKey<C>, PK_LEN> for ECCDHPrivateKey<C>
where
    C: Curve<PkUncompressed = [u8; PK_LEN]>,
{
    fn derive_pk(&self) -> ECCDHPublicKey<C> {
        let (x, y) = C::public_point(&self.0);
        ECCDHPublicKey { x, y }
    }
}

impl<C, const SK_LEN: usize> KeyAgreementPrivateKey<SK_LEN> for ECCDHPrivateKey<C>
where
    C: Curve<ScalarBytes = [u8; SK_LEN]>,
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.0.to_be_bytes()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);
        *out = self.0.to_be_bytes();
        SK_LEN
    }

    /// `d` must be in `[1, n-1]` (SP 800-56A Rev. 3 Section 5.6.2.1.2), checked on the raw
    /// big-endian value before any reduction, so that `d = n + 1` is refused rather than loaded
    /// as `d = 1`; the check and the load are
    /// [`private_scalar_from_be_bytes`],
    /// which stages the candidate in a `Secret` and reveals only whether the key loaded.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let bytes: &[u8; SK_LEN] = bytes.try_into().map_err(|_| {
            KeyAgreementError::DecodingError("an ECC CDH private key is the curve's scalar length")
        })?;
        private_scalar_from_be_bytes::<C>(bytes)
            .map(Self)
            .ok_or(KeyAgreementError::DecodingError("ECC CDH private key must be in [1, n-1]"))
    }
}

/// An ECC CDH public key: `Q = [d]G`, stored as affine coordinates. A key that exists has
/// passed full public-key validation (see [`KeyAgreementPublicKey::from_bytes`]). Encoded as
/// SEC 1 Section 2.3.3's uncompressed `04 || X || Y`, `C::PK_UNCOMPRESSED_LEN` bytes; the
/// compressed form is also accepted on decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECCDHPublicKey<C: Curve> {
    pub(crate) x: C::Fe,
    pub(crate) y: C::Fe,
}

impl<C, const PK_LEN: usize> KeyAgreementPublicKey<PK_LEN> for ECCDHPublicKey<C>
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
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let (x, y) = C::decode(bytes).ok_or(KeyAgreementError::DecodingError(
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
    let (d, (x, y)) = C::keygen_extra_bits(rng)?;
    Ok((ECCDHPublicKey { x, y }, ECCDHPrivateKey(d)))
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
