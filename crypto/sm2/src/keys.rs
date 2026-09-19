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
use bouncycastle_ec::nat;
use bouncycastle_ec::sm2::Sm2FieldElement;
use bouncycastle_ec::sm2_comb::comb_multiply_base_point;
use bouncycastle_ec::sm2_scalar::{N_LIMBS, Sm2Scalar, Sm2ScalarField};
use bouncycastle_ec::sm2_sec1;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_utils::secret::Secret;
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
///
/// # Why the public key is carried alongside `dA`
///
/// Unlike ECDSA, *every* SM2 signing operation needs the signer's own public key: §5.1.2's `ZA =
/// SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)` mixes `PA`'s affine coordinates into the
/// message hash, so `sign` cannot proceed without them. Deriving `PA` on each call means a second
/// fixed-base scalar multiplication per signature -- as expensive as the `[k]G` the signature
/// actually needs, i.e. double the cost of signing, and measurably so: signing used to cost about
/// twice what key generation did, and slightly more than *verification*, which is backwards for
/// any signature scheme.
///
/// So `PA` is computed once, when the key is created ([`keygen_from_rng`], which has it for free)
/// or loaded ([`SignaturePrivateKey::from_bytes`], which pays one multiplication once instead of
/// one per signature), and kept here. The cost is [`core::mem::size_of`] for this struct rising
/// from 32 bytes to 96 -- `PA` is two field elements -- which the crate docs' Memory Footprint
/// table records. `PA` is public data and is deliberately *not* wrapped in
/// [`bouncycastle_utils::secret::Secret`]; only `dA` is.
///
/// # Why `(1 + dA)^-1` is carried too
///
/// `draft-shen-sm2-ecdsa-02` §5.1.3 step A6 divides by `1 + dA`, and that inverse depends on the
/// key alone, not on the message or `k`. Recomputing it per signature was a constant-time
/// Fermat inversion each time -- roughly the same cost as `to_affine`'s field inversion, about a
/// tenth of a signature on P-256-class hardware -- for a value that never changes. It is computed
/// once, in [`SM2PrivateKey::from_validated_scalar`], and held in [`Sm2Scalar`], the same
/// [`bouncycastle_utils::secret::Secret`] wrapper as `dA`: anyone holding `(1 + dA)^-1` recovers
/// `dA` by inverting and subtracting one, so it is exactly as sensitive. That is 32 more bytes in
/// memory (128 in all, per the crate docs' Memory Footprint table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SM2PrivateKey {
    d: Sm2Scalar,
    /// `PA = [dA]G`, cached at construction; see the type's docs.
    pk: SM2PublicKey,
    /// `(1 + dA)^-1 mod n`, cached at construction; see the type's docs.
    one_plus_d_inv: Sm2Scalar,
}

impl SM2PrivateKey {
    /// Builds the key pair from an already-validated `dA` in `[1, n-1]`, computing `PA = [dA]G`.
    /// The single place `SM2PrivateKey`'s invariant (`pk` really is `[d]G`) is established.
    fn from_validated_scalar(d: Sm2Scalar) -> Self {
        let q = comb_multiply_base_point(&d);
        // dA is in [1, n-1] by construction (every caller validates first) and G has prime order n
        // (h = 1), so [dA]G is never the identity.
        let (x, y) = q.to_affine().expect("[dA]G is never infinity for dA in [1, n-1]");

        // (1 + dA)^-1, once per key rather than once per signature (see the type's docs). The
        // three scalar-field intermediates reveal dA and are scrubbed, the same way sign_with_k
        // scrubs its own; the cached value itself goes into a Secret. (For dA = n - 1 the inverse
        // is of 0 and comes out 0, which makes every signature's s = 0 and fail step A6 exactly as
        // it did when the inverse was computed per signature.)
        let mut d_field = Sm2ScalarField::from_secret(&d);
        let mut one_plus_d = Sm2ScalarField::ONE.add(&d_field);
        let mut inverse = one_plus_d.invert();
        let one_plus_d_inv = Sm2Scalar::from_limbs(inverse.to_limbs());
        d_field.zeroize();
        one_plus_d.zeroize();
        inverse.zeroize();

        Self { d, pk: SM2PublicKey { x, y }, one_plus_d_inv }
    }

    /// The wrapped scalar, for this crate's own sign implementation to compute with.
    pub(crate) fn scalar(&self) -> &Sm2Scalar {
        &self.d
    }

    /// The cached `(1 + dA)^-1 mod n` (see the type's docs), for step A6 of signing.
    pub(crate) fn one_plus_d_inv(&self) -> &Sm2Scalar {
        &self.one_plus_d_inv
    }

    /// The matching public key `PA = [dA]G`. Free: it was computed when this key was created or
    /// loaded (see the type's docs), not recomputed here.
    ///
    /// For the CLI's `PkFromSk`/`CheckConsistency` actions, which need it without having generated
    /// the pair together -- see `bouncycastle_ecdsa::keys_common::DerivePublicKey`'s docs for the
    /// shape this mirrors (kept as a plain inherent method here rather than a shared trait, since
    /// SM2's own CLI command needs the extra `IDA` argument every other curve's doesn't, so it was
    /// never going to share a single generic command function with them anyway).
    pub fn derive_pk(&self) -> SM2PublicKey {
        self.pk
    }
}

impl SignaturePrivateKey<SK_LEN> for SM2PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.d.to_be_bytes()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);
        *out = self.d.to_be_bytes();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let array: [u8; SK_LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::DecodingError("SM2 private key must be 32 bytes"))?;
        // draft-shen-sm2-ecdsa-02 S4: dA is in [1, n-1], checked on the raw big-endian value
        // *before* any reduction. `Sm2Scalar::from_be_bytes` reduces mod n, so checking afterwards
        // would accept an out-of-range encoding as a different, perfectly valid key: `dA = n + 1`
        // would load as `dA = 1`, giving one key two encodings and silently treating malformed
        // input as well-formed. Comparing against the fixed public values 0 and n is a one-time
        // validation of caller-supplied bytes at load time, not a computation performed repeatedly
        // on a secret intermediate value, so branching on it leaks nothing beyond what the caller
        // already knows from having supplied these exact bytes.
        let limbs = sm2_sec1::limbs_from_be_bytes(&array);
        let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
        if limbs == [0; 4] || borrow != 1 {
            return Err(SignatureError::DecodingError("SM2 private key must be in [1, n-1]"));
        }
        Ok(Self::from_validated_scalar(Sm2Scalar::from_limbs(limbs)))
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
    // Raw DRBG output, reduced below into the private key / per-message secret: held in
    // `Secret` so it is scrubbed when this function returns rather than left on the stack.
    let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
    let d = reduce_wide_bits_mod_n_minus_1(&*extra_bits);

    // d is in [1, n-1] by construction (see reduce_wide_bits_mod_n_minus_1), which is what
    // `from_validated_scalar` assumes; it computes PA = [d]G once, and the pair shares that value.
    let sk = SM2PrivateKey::from_validated_scalar(d);

    Ok((sk.derive_pk(), sk))
}
