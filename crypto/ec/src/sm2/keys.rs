//! SM2 key types and key-pair generation (GB/T 32918.1-2016 §6.1, which GB/T 32918.2-2016 §5.3
//! defers to for the signer's key pair). Shaped like [`crate::ecdsa::keys`],
//! with SM2's own field/scalar types and the wide-DRBG-output reduction from
//! [`crate::sm2::extra_bits`] substituted. §6.1 a) says only that `dA` is an integer in `[1, n-2]`
//! produced "with a random number generator" (`draft-shen-sm2-ecdsa-02` says the same without a
//! range), without specifying a DRBG-to-scalar conversion; this module uses the same FIPS 186-5
//! Appendix A.4.1 "extra random bits" method as every curve in `crate::ecdsa`, for the same
//! reason (see [`crate::sm2::extra_bits`]'s docs for the bias-bound derivation specific to SM2's `n`).

use crate::hazmat::sm2::Sm2FieldElement;
use crate::hazmat::sm2_comb::comb_multiply_base_point;
use crate::hazmat::sm2_scalar::{Sm2Scalar, Sm2ScalarField};
use crate::hazmat::sm2_sec1;
use crate::rng_draw::fill_bytes;
use crate::sm2::extra_bits::{N_MINUS_1_LIMBS, reduce_wide_bits_mod_n_minus_2};
use bouncycastle_core::errors::{KeyDecodingError, RNGError, SignatureError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{PrivateKey, PublicKey, RNG};
use bouncycastle_utils::nat;
use bouncycastle_utils::secret::{Secret, zeroize_in_place};
use bouncycastle_utils::stack_wipe::WipeStackBelowOnDrop;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of an SM2 private key: SEC 1 §2.3.7 integer-to-octet-string of `dA`, 32 bytes.
pub const SK_LEN: usize = 32;

/// Encoded length of an SM2 public key in the canonical uncompressed form (SEC 1 §2.3.3, `04 || X
/// || Y`); [`SM2PublicKey::from_bytes`] also accepts the 33-byte compressed form.
pub const PK_LEN: usize = 65;

/// Requested output length, in bytes, from the DRBG for key generation and for the per-signature
/// secret `k` (GB/T 32918.2-2016 §6.1 step A3): `320` bits (40 bytes) -- derived directly
/// from FIPS 186-5 Appendix A.4.1's own bias-bound check for SM2's `n` (see [`crate::sm2::extra_bits`]'s
/// docs), not copied from any other curve's table entry.
pub(in crate::sm2) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 40;

/// What the stack wipe overwrites after a signing key is loaded or generated, in 64-bit words:
/// 5120 bytes. In x86-64 builds under the workspace's release profile with the body of the wipe
/// taken out, `dev_scripts/sm2_stack_harness` reports the stack written to 2664 bytes below a
/// call of `from_bytes` and 2968 below one of [`keygen`] with rustc 1.97 (nightly), and 2384 and
/// 2688 with rustc 1.88; with 2816 bytes wiped `dev_scripts/check_sm2_stack.sh` fails with rustc
/// 1.88, and with 2560 with either. On arm64 Linux with rustc 1.100 the harness reports 2760 and
/// 3064 bytes. The rest is room for a compiler that lays the frames out less tightly.
const WIPED_STACK_WORDS: usize = 640;

/// An SM2 private key: `dA` in `[1, n-2]` (GB/T 32918.1-2016 §6.1 a); the draft states no range),
/// held in [`bouncycastle_utils::secret::Secret`] via [`Sm2Scalar`].
///
/// # Why the public key is carried alongside `dA`
///
/// Unlike ECDSA, *every* SM2 signing operation needs the signer's own public key: GB/T
/// 32918.2-2016 §5.5's `ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)` mixes `PA`'s
/// affine coordinates into the
/// message hash, so `sign` cannot proceed without them. Deriving `PA` on each call means a second
/// fixed-base scalar multiplication per signature -- as expensive as the `[k]G` the signature
/// actually needs, i.e. double the cost of signing, and measurably so: signing used to cost about
/// twice what key generation did, and slightly more than *verification*, which is backwards for
/// any signature scheme.
///
/// So `PA` is computed once, when the key is created ([`keygen`], which has it for free)
/// or loaded ([`PrivateKey::from_bytes`], which pays one multiplication once instead of
/// one per signature), and kept here. The cost is [`core::mem::size_of`] for this struct rising
/// from 32 bytes to 96 -- `PA` is two field elements -- which [`crate::sm2`]'s Memory Usage
/// table records. `PA` is public data and is deliberately *not* wrapped in
/// [`bouncycastle_utils::secret::Secret`]; only `dA` is.
///
/// # Why `(1 + dA)^-1` is carried too
///
/// GB/T 32918.2-2016 §6.1 step A6 divides by `1 + dA`, and that inverse depends on the
/// key alone, not on the message or `k`. Recomputing it per signature was a constant-time
/// Fermat inversion each time -- roughly the same cost as `to_affine`'s field inversion, about a
/// tenth of a signature on P-256-class hardware -- for a value that never changes. It is computed
/// once, in `SM2PrivateKey::from_validated_scalar`, and held in [`Sm2Scalar`], the same
/// [`bouncycastle_utils::secret::Secret`] wrapper as `dA`: anyone holding `(1 + dA)^-1` recovers
/// `dA` by inverting and subtracting one, so it is exactly as sensitive. That is 32 more bytes in
/// memory (128 in all, per [`crate::sm2`]'s Memory Usage table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SM2PrivateKey {
    d: Sm2Scalar,
    /// `PA = [dA]G`, cached at construction; see the type's docs.
    pk: SM2PublicKey,
    /// `(1 + dA)^-1 mod n`, cached at construction; see the type's docs.
    one_plus_d_inv: Sm2Scalar,
}

impl SM2PrivateKey {
    /// Builds the key pair from an already-validated `dA` in `[1, n-2]`, computing `PA = [dA]G`.
    /// The single place `SM2PrivateKey`'s invariant (`pk` really is `[d]G`) is established.
    fn from_validated_scalar(d: Sm2Scalar) -> Self {
        let q = comb_multiply_base_point(&d);
        // dA is in [1, n-2] by construction (every caller validates first) and G has prime order n
        // (h = 1), so [dA]G is never the identity.
        let (x, y) = q.to_affine().expect("[dA]G is never infinity for dA in [1, n-2]");

        // (1 + dA)^-1, once per key rather than once per signature (see the type's docs). The
        // three scalar-field intermediates reveal dA and are scrubbed, the same way sign_with_k
        // scrubs its own; the cached value itself goes into a Secret. 1 + dA is at most n - 1,
        // since dA <= n - 2, so the inverse is never of 0.
        let mut d_field = Sm2ScalarField::from_secret(&d);
        let mut one_plus_d = Sm2ScalarField::ONE.add(&d_field);
        let mut inverse = one_plus_d.invert();
        let one_plus_d_inv = Sm2Scalar::from_limbs(inverse.to_limbs());
        d_field.zeroize();
        one_plus_d.zeroize();
        inverse.zeroize();

        Self { d, pk: SM2PublicKey { x, y }, one_plus_d_inv }
    }

    /// [`Self::from_validated_scalar`] over `dA`'s limbs, never inlined, so that what it and its
    /// callees leave lies below its caller's frame, where the stack wipe reaches it. It returns
    /// what `from_bytes` does, for `from_bytes` to end in the call: the key is then written to
    /// where `from_bytes`'s caller wants it, and to no frame above the wiped ones.
    #[inline(never)]
    fn from_validated_limbs_in_own_frame(limbs: &[u64; 4]) -> Result<Self, KeyDecodingError> {
        Ok(Self::from_validated_scalar(Sm2Scalar::from_limbs(*limbs)))
    }

    /// The wrapped scalar, for this module's own sign implementation to compute with.
    pub(in crate::sm2) fn scalar(&self) -> &Sm2Scalar {
        &self.d
    }

    /// The cached `(1 + dA)^-1 mod n` (see the type's docs), for step A6 of signing.
    pub(in crate::sm2) fn one_plus_d_inv(&self) -> &Sm2Scalar {
        &self.one_plus_d_inv
    }

    /// The matching public key `PA = [dA]G`. Free: it was computed when this key was created or
    /// loaded (see the type's docs), not recomputed here.
    ///
    /// For the CLI's `PkFromSk`/`CheckConsistency` actions, which need it without having generated
    /// the pair together -- see `crate::ecdsa::keys_common::DerivePublicKey`'s docs for the
    /// shape this mirrors (kept as a plain inherent method here rather than a shared trait, since
    /// SM2's own CLI command needs the extra `IDA` argument every other curve's doesn't, so it was
    /// never going to share a single generic command function with them anyway).
    pub fn derive_pk(&self) -> SM2PublicKey {
        self.pk
    }
}

impl PrivateKey<SK_LEN> for SM2PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.d.to_be_bytes()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);
        *out = self.d.to_be_bytes();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let array: &[u8; SK_LEN] =
            bytes.try_into().map_err(|_| KeyDecodingError("SM2 private key must be 32 bytes"))?;
        // Dropped last, after the key is where the caller wants it.
        let _wipe = WipeStackBelowOnDrop::<WIPED_STACK_WORDS>;
        // GB/T 32918.1-2016 S6.1 a): dA is in [1, n-2], checked on the value as encoded and not
        // after a reduction, so that a key has one encoding: `Sm2Scalar::from_be_bytes` reduces
        // mod n, and would load `dA = n + 1` as `dA = 1`. Whether it is in range is all that the
        // branch below shows of it.
        let mut limbs = Secret::<[u64; 4]>::new();
        *limbs = sm2_sec1::limbs_from_be_bytes(array);
        // borrow == 1 iff limbs < n - 1, i.e. limbs <= n - 2.
        let (mut difference, borrow) = nat::sub(&limbs, &N_MINUS_1_LIMBS);
        zeroize_in_place(&mut difference);
        let any_bit = limbs.iter().fold(0, |bits, limb| bits | limb);
        if any_bit == 0 || borrow != 1 {
            return Err(KeyDecodingError("SM2 private key must be in [1, n-2]"));
        }
        Self::from_validated_limbs_in_own_frame(&limbs)
    }
}

/// An SM2 public key: `PA = [dA]G` (GB/T 32918.1-2016 §6.1 b)), stored as affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SM2PublicKey {
    pub(in crate::sm2) x: Sm2FieldElement,
    pub(in crate::sm2) y: Sm2FieldElement,
}

impl PublicKey<PK_LEN> for SM2PublicKey {
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
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let (x, y) = sm2_sec1::decode(bytes)
            .ok_or(KeyDecodingError("invalid or out-of-range SEC 1 SM2 point encoding"))?;
        Ok(Self { x, y })
    }
}

impl Display for SM2PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "SM2PublicKey {{ {:x?} }}", self.encode())
    }
}

impl SM2PublicKey {
    /// The public key's affine `x`, `y` coordinates -- for `za`'s `ZA` computation, which
    /// needs them directly rather than through the SEC 1 encoding.
    pub(in crate::sm2) fn affine(&self) -> (Sm2FieldElement, Sm2FieldElement) {
        (self.x, self.y)
    }
}

/// As [`keygen`], but sources the DRBG output from the caller-provided RNG, which must offer
/// a security strength of at least 128 bits: GB/T 32918.2-2016 §5.4.3 asks only for an approved
/// random number generator and the draft says no more (see the module docs on why key generation
/// borrows FIPS 186-5's method wholesale), so this follows that
/// method's own Appendix A.2.1 step 3, requiring a DRBG strength "not less than" the one SP
/// 800-57 Part 1 Rev. 5's Table 2 associates with SM2's 256-bit curve order (`f = 256-383` in
/// that table's ECC column, giving 128-bit security).
///
/// # Errors
/// [`SignatureError::RNGError`] if `rng` offers less than 128 bits of security strength, fails,
/// or writes fewer bytes than it was asked for.
pub fn keygen(rng: &mut dyn RNG) -> Result<(SM2PublicKey, SM2PrivateKey), SignatureError> {
    // FIPS 186-5 Appendix A.2.1 step 3: the DRBG must offer at least the security strength
    // SM2's 256-bit curve order calls for (SP 800-57 Part 1 Rev. 5, Table 2: 128 bits).
    if rng.security_strength() < SecurityStrength::_128bit {
        return Err(SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm));
    }

    // Dropped last, after the result is where the caller wants it.
    let _wipe = WipeStackBelowOnDrop::<WIPED_STACK_WORDS>;
    // Raw DRBG output, reduced into the private key: held in `Secret` so it is scrubbed when
    // this function returns rather than left on the stack.
    let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    fill_bytes(rng, &mut *extra_bits).map_err(SignatureError::RNGError)?;
    key_pair_in_own_frame(&extra_bits)
}

/// The key pair that 320 bits of an RNG's output give, never inlined, so that what it and its
/// callees leave lies below [`keygen`]'s frame, where the stack wipe reaches it. It returns what
/// `keygen` does, for `keygen` to end in the call: the private key is then written to where
/// `keygen`'s caller wants it, and to no frame above the wiped ones.
#[inline(never)]
fn key_pair_in_own_frame(
    extra_bits: &[u8; EXTRA_BITS_DRBG_OUTPUT_LEN],
) -> Result<(SM2PublicKey, SM2PrivateKey), SignatureError> {
    // d is in [1, n-2] by construction (see reduce_wide_bits_mod_n_minus_2), which is what
    // `from_validated_scalar` assumes; it computes PA = [d]G once, and the pair shares that value.
    let sk = SM2PrivateKey::from_validated_scalar(reduce_wide_bits_mod_n_minus_2(extra_bits));
    Ok((sk.derive_pk(), sk))
}
