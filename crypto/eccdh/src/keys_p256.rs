//! ECC CDH P-256 key types and key-pair generation (SP 800-56A Rev. 3 Sections 5.6.1.2.1,
//! 5.6.2.1.2 and 5.6.2.3.3).

use crate::keys_common::DerivePublicKey;
use bouncycastle_core::errors::{KeyAgreementError, RNGError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey, RNG};
use bouncycastle_ec::hazmat::p256::P256FieldElement;
use bouncycastle_ec::hazmat::p256_comb::comb_multiply_base_point;
use bouncycastle_ec::hazmat::p256_extra_bits::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_ec::hazmat::p256_scalar::{N_LIMBS, P256Scalar};
use bouncycastle_ec::hazmat::p256_sec1;
use bouncycastle_ec::nat;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a P-256 private key: SEC 1 Section 2.3.7 integer-to-octet-string of `d`,
/// `ceil(log2 n / 8)` = 32 bytes.
pub const SK_LEN: usize = 32;

/// Encoded length of a P-256 public key in the canonical form [`ECCDHP256PublicKey::encode`]
/// emits: SEC 1 Section 2.3.3's uncompressed `04 || X || Y`, 65 bytes.
/// [`ECCDHP256PublicKey::from_bytes`] also accepts the 33-byte compressed form.
pub const PK_LEN: usize = 65;

/// The DRBG output [`keygen`] draws: SP 800-56A Rev. 3 Section 5.6.1.2.1 step 3, `L = len(n) + 64`
/// = 320 bits, rounded up to 40 bytes.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 40;

/// An ECC CDH P-256 private key: `d` in `[1, n-1]` (SP 800-56A Rev. 3 Section 5.6.2.1.2), held
/// in [`bouncycastle_utils::secret::Secret`] via [`P256Scalar`]. A key-establishment key: never
/// also a signing key (Section 5.6.3.2 item 5), which is why this is not the ECDSA type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECCDHP256PrivateKey(P256Scalar);

impl ECCDHP256PrivateKey {
    /// The wrapped scalar, for this crate's own agreement to compute with.
    pub(crate) fn scalar(&self) -> &P256Scalar {
        &self.0
    }
}

impl DerivePublicKey<ECCDHP256PublicKey, PK_LEN> for ECCDHP256PrivateKey {
    fn derive_pk(&self) -> ECCDHP256PublicKey {
        let mut q = comb_multiply_base_point(&self.0);
        // d is in [1, n-1] by construction (every ECCDHP256PrivateKey is built that way; see
        // from_bytes and keygen) and G has prime order n, so [d]G is never the identity.
        let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");
        // Only the affine pair is public; the projective coordinates are a function of `d`'s bits.
        q.zeroize();
        ECCDHP256PublicKey { x, y }
    }
}

impl KeyAgreementPrivateKey<SK_LEN> for ECCDHP256PrivateKey {
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
            KeyAgreementError::DecodingError("ECC CDH P-256 private key must be 32 bytes")
        })?;
        // SP 800-56A Rev. 3 Section 5.6.2.1.2: "the private keys are in the interval [1, n - 1]",
        // checked on the raw big-endian value *before* any reduction. `P256Scalar::from_be_bytes`
        // reduces mod n, so checking afterwards would accept an out-of-range encoding as a
        // different, perfectly valid key: `d = n + 1` would load as `d = 1`. The candidate is a
        // secret from the moment it arrives (a service loading a stored key for a request does so
        // in front of observers who are not the caller), so the limbs and the difference live in
        // `Secret`s, scrubbed on both exits, and the two bounds are tested without a comparison
        // or branch on their value: `nat::sub`'s borrow for `d < n` and the OR of the limbs for
        // `d != 0`, combined under masks into one decision, which reveals only whether the key
        // loaded, as the return value does.
        let mut limbs = Secret::<[u64; 4]>::new();
        *limbs = p256_sec1::limbs_from_be_bytes(bytes);
        let mut diff = Secret::<[u64; 4]>::new();
        diff.copy_from_slice(&*limbs);
        let borrow = nat::sub_assign(&mut diff, &N_LIMBS);
        let in_range = !nat::is_zero(&limbs) & Condition::<u64>::is_equal(borrow, 1);
        if !in_range.to_bool() {
            return Err(KeyAgreementError::DecodingError(
                "ECC CDH P-256 private key must be in [1, n-1]",
            ));
        }
        // The scalar is reduced from the borrowed `Secret` limbs straight into its own `Secret`,
        // so no plain copy of d is staged in this frame; the returned key is moved out, and a
        // move does not wipe where it was built.
        Ok(Self(P256Scalar::from_borrowed_limbs(&limbs)))
    }
}

/// An ECC CDH P-256 public key: `Q = [d]G`, stored as affine coordinates. A key that exists has
/// passed full public-key validation (see [`KeyAgreementPublicKey::from_bytes`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECCDHP256PublicKey {
    pub(crate) x: P256FieldElement,
    pub(crate) y: P256FieldElement,
}

impl KeyAgreementPublicKey<PK_LEN> for ECCDHP256PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        p256_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    /// Accepts both SEC 1 Section 2.3.3 encodings (33-byte compressed, 65-byte uncompressed)
    /// and runs SP 800-56A Rev. 3 Section 5.6.2.3.3's full public-key validation, as the static
    /// keys of Section 5.6.2.2.1 require: steps 1 to 3 (not the identity, which no encoding
    /// expresses; coordinates in `[0, p-1]`; on the curve) are [`p256_sec1::decode`]'s checks
    /// (SP 800-186 Appendix D.1.1.1). Step 4, `nQ = O`, is not computed: the cofactor is 1 (SP 800-186 Section 3.2.1.3 (P-256; Section 3.2.1: "For pseudorandom curves, the cofactor h = 1")), so the curve group
    /// has prime order n and every point on the curve other than O has order n.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let (x, y) = p256_sec1::decode(bytes).ok_or(KeyAgreementError::DecodingError(
            "invalid or out-of-range SEC 1 P-256 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for ECCDHP256PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECCDHP256PublicKey {{ {:x?} }}", self.encode())
    }
}

/// SP 800-56A Rev. 3 Section 5.6.1.2.1, key-pair generation using extra random bits, from the
/// caller's RNG, which must offer the curve's strength of 128 bits (step 4: "an RBG with a
/// security strength of s bits or more"; `s` from SP 800-57 Part 1 Rev. 5 Table 2).
///
/// # Errors
/// [`KeyAgreementError::RNGError`] if the RNG is weaker than the curve or fails to deliver.
pub fn keygen(
    rng: &mut dyn RNG,
) -> Result<(ECCDHP256PublicKey, ECCDHP256PrivateKey), KeyAgreementError> {
    // Step 4's RBG strength: SP 800-57 Part 1 Rev. 5 Table 2 gives 128 bits for this order.
    if rng.security_strength() < SecurityStrength::_128bit {
        return Err(KeyAgreementError::RNGError(
            RNGError::SecurityStrengthInsufficientForAlgorithm,
        ));
    }

    // Steps 3 and 4: L = len(n) + 64 bits of DRBG output, held in `Secret` so it is scrubbed when
    // this function returns rather than left on the stack.
    let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits).map_err(KeyAgreementError::RNGError)?;
    // Steps 5 and 6: c from the bits (Appendix C.4), d = (c mod (n - 1)) + 1, in constant time.
    let d = reduce_wide_bits_mod_n_minus_1(&*extra_bits);

    // Step 7: Q = dG.
    let mut q = comb_multiply_base_point(&d);
    // d is in [1, n-1] by construction (see reduce_wide_bits_mod_n_minus_1) and G has prime order
    // n (the cofactor is 1: SP 800-186 Section 3.2.1.3 (P-256; Section 3.2.1: "For pseudorandom curves, the cofactor h = 1")), so [d]G is never the identity: this holds for every valid d,
    // so branching on it here leaks nothing about which d was drawn.
    let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");
    // Only the affine pair is public; the projective coordinates are a function of `d`'s bits.
    q.zeroize();

    Ok((ECCDHP256PublicKey { x, y }, ECCDHP256PrivateKey(d)))
}
