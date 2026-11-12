//! ECC CDH brainpoolP512r1 key types and key-pair generation (SP 800-56A Rev. 3 Sections 5.6.1.2.1,
//! 5.6.2.1.2 and 5.6.2.3.3).

use crate::keys_common::{AgreementKeyPair, DerivePublicKey};
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey, RNG};
use bouncycastle_ec::Bp512r1;
use bouncycastle_ec::hazmat::bp512r1::Bp512r1FieldElement;
use bouncycastle_ec::hazmat::bp512r1_keygen;
use bouncycastle_ec::hazmat::bp512r1_scalar::{Bp512r1Scalar, N_LIMBS};
use bouncycastle_ec::hazmat::bp512r1_sec1;
use bouncycastle_ec::nat;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a brainpoolP512r1 private key: SEC 1 Section 2.3.7 integer-to-octet-string of `d`,
/// `ceil(log2 n / 8)` = 64 bytes.
pub const SK_LEN: usize = 64;

/// Encoded length of a brainpoolP512r1 public key in the canonical form [`ECCDHBp512r1PublicKey::encode`]
/// emits: SEC 1 Section 2.3.3's uncompressed `04 || X || Y`, 129 bytes.
/// [`ECCDHBp512r1PublicKey::from_bytes`] also accepts the 65-byte compressed form.
pub const PK_LEN: usize = 129;

/// The DRBG output [`keygen`] draws: SP 800-56A Rev. 3 Section 5.6.1.2.1 step 3, `L = len(n) + 64`
/// = 576 bits, rounded up to 72 bytes.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 72;

/// An ECC CDH brainpoolP512r1 private key: `d` in `[1, n-1]` (SP 800-56A Rev. 3 Section 5.6.2.1.2), held
/// in [`bouncycastle_utils::secret::Secret`] via [`Bp512r1Scalar`]. A key-establishment key: never
/// also a signing key (Section 5.6.3.2 item 5), which is why this is not the ECDSA type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECCDHBp512r1PrivateKey(Bp512r1Scalar);

impl ECCDHBp512r1PrivateKey {
    /// The wrapped scalar, for this crate's own agreement to compute with.
    pub(crate) fn scalar(&self) -> &Bp512r1Scalar {
        &self.0
    }
}

impl DerivePublicKey<ECCDHBp512r1PublicKey, PK_LEN> for ECCDHBp512r1PrivateKey {
    fn derive_pk(&self) -> ECCDHBp512r1PublicKey {
        let (x, y) = bp512r1_keygen::public_point(&self.0);
        ECCDHBp512r1PublicKey { x, y }
    }
}

impl KeyAgreementPrivateKey<SK_LEN> for ECCDHBp512r1PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.0.to_be_bytes()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);
        *out = self.0.to_be_bytes();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let bytes: &[u8; SK_LEN] = bytes.try_into().map_err(|_| {
            KeyAgreementError::DecodingError("ECC CDH brainpoolP512r1 private key must be 64 bytes")
        })?;
        // SP 800-56A Rev. 3 Section 5.6.2.1.2: "the private keys are in the interval [1, n - 1]",
        // checked on the raw big-endian value *before* any reduction. `Bp512r1Scalar::from_be_bytes`
        // reduces mod n, so checking afterwards would accept an out-of-range encoding as a
        // different, perfectly valid key: `d = n + 1` would load as `d = 1`. The candidate is a
        // secret from the moment it arrives (a service loading a stored key for a request does so
        // in front of observers who are not the caller), so the limbs and the difference live in
        // `Secret`s, scrubbed on both exits, and the two bounds are tested without a comparison
        // or branch on their value: `nat::sub_assign`'s borrow for `d < n` and the OR of the limbs for
        // `d != 0`, combined under masks into one decision, which reveals only whether the key
        // loaded, as the return value does.
        let mut limbs = Secret::<[u64; 8]>::new();
        bp512r1_sec1::limbs_from_be_bytes_into(bytes, &mut limbs);
        let mut diff = Secret::<[u64; 8]>::new();
        diff.copy_from_slice(&*limbs);
        let borrow = nat::sub_assign(&mut diff, &N_LIMBS);
        let in_range = !nat::is_zero(&limbs) & Condition::<u64>::is_equal(borrow, 1);
        if !in_range.to_bool() {
            return Err(KeyAgreementError::DecodingError(
                "ECC CDH brainpoolP512r1 private key must be in [1, n-1]",
            ));
        }
        // The scalar is reduced from the borrowed `Secret` limbs straight into its own `Secret`,
        // so no plain copy of d is staged in this frame; the returned key is moved out, and a
        // move does not wipe where it was built.
        Ok(Self(Bp512r1Scalar::from_borrowed_limbs(&limbs)))
    }
}

/// An ECC CDH brainpoolP512r1 public key: `Q = [d]G`, stored as affine coordinates. A key that exists has
/// passed full public-key validation (see [`KeyAgreementPublicKey::from_bytes`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECCDHBp512r1PublicKey {
    pub(crate) x: Bp512r1FieldElement,
    pub(crate) y: Bp512r1FieldElement,
}

impl KeyAgreementPublicKey<PK_LEN> for ECCDHBp512r1PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        bp512r1_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    /// Accepts both SEC 1 Section 2.3.3 encodings (65-byte compressed, 129-byte uncompressed)
    /// and runs SP 800-56A Rev. 3 Section 5.6.2.3.3's full public-key validation, as the static
    /// keys of Section 5.6.2.2.1 require: steps 1 to 3 (not the identity, which no encoding
    /// expresses; coordinates in `[0, p-1]`; on the curve) are [`bp512r1_sec1::decode`]'s checks
    /// (SP 800-186 Appendix D.1.1.1). Step 4, `nQ = O`, is not computed: the cofactor is 1 (RFC 5639 Section 3.7 (h = 1)), so the curve group
    /// has prime order n and every point on the curve other than O has order n.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let (x, y) = bp512r1_sec1::decode(bytes).ok_or(KeyAgreementError::DecodingError(
            "invalid or out-of-range SEC 1 brainpoolP512r1 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for ECCDHBp512r1PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECCDHBp512r1PublicKey {{ {:x?} }}", self.encode())
    }
}

/// SP 800-56A Rev. 3 Section 5.6.1.2.1, key-pair generation using extra random bits, from the
/// caller's RNG, which must offer the curve's strength of 256 bits (step 4: "an RBG with a
/// security strength of s bits or more"; `s` from SP 800-57 Part 1 Rev. 5 Table 2).
///
/// # Errors
/// [`KeyAgreementError::RNGError`] if the RNG is weaker than the curve or fails to deliver.
pub fn keygen(
    rng: &mut dyn RNG,
) -> Result<(ECCDHBp512r1PublicKey, ECCDHBp512r1PrivateKey), KeyAgreementError> {
    // The pair comes from ec's generator, which checks the RNG's strength, draws
    // EXTRA_BITS_DRBG_OUTPUT_LEN bytes and reduces them; this crate names the key types.
    let (d, (x, y)) = bp512r1_keygen::keygen::<EXTRA_BITS_DRBG_OUTPUT_LEN>(rng)?;
    Ok((ECCDHBp512r1PublicKey { x, y }, ECCDHBp512r1PrivateKey(d)))
}

/// [`Bp512r1::generate_agreement_key_pair`](AgreementKeyPair::generate_agreement_key_pair) is [`keygen`].
impl AgreementKeyPair for Bp512r1 {
    type PublicKey = ECCDHBp512r1PublicKey;
    type PrivateKey = ECCDHBp512r1PrivateKey;

    fn generate_agreement_key_pair(
        rng: &mut dyn RNG,
    ) -> Result<(ECCDHBp512r1PublicKey, ECCDHBp512r1PrivateKey), KeyAgreementError> {
        keygen(rng)
    }
}
