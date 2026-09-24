//! RSASVE, RSA Secret-Value Encapsulation (NIST SP 800-56B Rev. 2 §7.2.1), as a
//! [`bouncycastle_core`] KEM: [`RSASVE`] implements
//! [`KEMEncapsulator`]/[`KEMDecapsulator`], with RSASVE.GENERATE (§7.2.1.2) as `encaps` and
//! RSASVE.RECOVER (§7.2.1.3) as `decaps`, over the KEM-only key types [`RsaKEMPublicKey`] and
//! [`RsaKEMPrivateKey`].
//!
//! This is the scheme BC FIPS Java 2.0 exposes as `FipsRSA.KTS_SVE` (JCA name `RSA-KAS-KEM`): the
//! encapsulating party draws a random `z` with `1 < z < n - 1` and sends `C = z^e mod n`, and both
//! parties end up holding `Z = I2BS(z, nLen)`. The shared secret *is* `Z`, the raw secret value, at
//! the modulus's full byte length. It is not a derived key. SP 800-56B Rev. 2 uses RSASVE only
//! inside its KAS1/KAS2 key-agreement schemes (§8.2, §8.3), which always pass `Z` through a key-
//! derivation method (§5.5, i.e. SP 800-56C) before use. Doing that is the caller's job here,
//! as with every other KEM in this workspace. See the crate docs' `# Security Considerations`.
//!
//! # Key separation
//!
//! The key types here wrap the signature schemes' [`RsaPublicKey`]/[`RsaPrivateKey`] rather than
//! reusing them, so the type system keeps key-establishment and signing keys apart. There is no
//! `Signer` impl for an [`RsaKEMPrivateKey`] and no `KEMDecapsulator` impl for an
//! [`RsaPrivateKey`]. SP 800-56B Rev. 2 §6.1 item 5 is the requirement: "One key pair shall not
//! be used for different cryptographic purposes (for example, a digital-signature key pair shall
//! not be used for key establishment or vice versa)". BC FIPS Java checks the same thing at runtime with
//! `canBeUsed(ENCRYPT_OR_DECRYPT)`. Nothing stops a caller from building both kinds of key from
//! the same CRT components, and nothing can.
//!
//! # Key validation
//!
//! On top of what [`RsaPublicKey::new`]/[`RsaPrivateKey::from_crt_components`] already check,
//! the KEM key types enforce two things:
//!
//! * `65,537 <= e` (§6.2.1 item 2, "65,537 ≤ e < 2^256"; the upper bound holds by construction,
//!   because `e` is a `u32`). This applies to the public key only: the CRT private key does not
//!   carry `e`.
//! * `n` is exactly `64 * L` bits long, i.e. its top bit is set. §6.2.1 item 1 gives the key an
//!   `nBits`, and §6.4.2.2's partial public-key validation requires "that the bit length of the
//!   modulus shall be a length that is approved in this Recommendation". A 2048-bit key type holding
//!   a shorter modulus would also break RSASVE.GENERATE's `nLen`, which is fixed at `8 * L` bytes
//!   here. And with the top bit set, each draw of step 2's rejection loop succeeds with probability
//!   above one half.
//!
//! The rest of SP 800-89 §5.3.3's plausibility tests, which §6.4.2.2 also requires, are not
//! performed (beyond `n` odd and `e` odd, which [`RsaPublicKey::new`] checks). Nothing here
//! amounts to full public-key validation, which §6.4.2.2 notes "is not specified in this
//! Recommendation".

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsa_core::{crt_exp, public_exp};
use bouncycastle_core::errors::{KEMError, RNGError, SignatureError};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey, RNG,
};
use bouncycastle_ec::nat;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_utils::secret::Secret;
use core::fmt;
use core::fmt::{Display, Formatter};
use core::marker::PhantomData;

/// The smallest public exponent SP 800-56B Rev. 2 §6.2.1 item 2 allows: "65,537 ≤ e < 2^256".
pub const MIN_PUBLIC_EXPONENT: u32 = 65537;

/// How many `nLen`-byte draws RSASVE.GENERATE's step 2 makes before it gives up with
/// `GenericError`. §7.2.1.2 step 2.c just says "go to step 2a", with no limit. The limit exists so
/// that a broken RNG, e.g. one stuck on all-`0xFF` output, produces an error rather than a hang, the
/// same reason `crate::keygen` caps its candidate loops. `n`'s top bit is set (see the module docs'
/// `# Key validation`), so a working RNG's draw falls outside `(1, n - 1)` with probability below
/// one half, and 128 draws all fail with probability below `2^-128`.
pub const MAX_GENERATE_ATTEMPTS: usize = 128;

/// Maps an error from the signature-typed key constructors and key generation this module wraps
/// into its [`KEMError`] equivalent. Every variant those can actually produce keeps its meaning.
fn kem_error(e: SignatureError) -> KEMError {
    match e {
        SignatureError::DecodingError(s) => KEMError::DecodingError(s),
        SignatureError::RNGError(e) => KEMError::RNGError(e),
        SignatureError::GenericError(s) => KEMError::GenericError(s),
        _ => KEMError::GenericError("unexpected error from the RSA key layer"),
    }
}

/// Whether `n` is exactly `64 * L` bits: see the module docs' `# Key validation`.
fn has_full_bit_length<const L: usize>(n: &[u64; L]) -> bool {
    n[L - 1] >> 63 == 1
}

/// `1 < x < n - 1`, the range SP 800-56B Rev. 2 requires of RSAEP's plaintext (§7.1.1 input 2),
/// RSADP's ciphertext (§7.1.2.3 step 1), and RSASVE.GENERATE's `z` (§7.2.1.2 step 2.c).
///
/// Written as two borrow-outs combined with `&` rather than as a short-circuiting comparison. In
/// RSASVE.GENERATE `x` is the secret `z`, and it should not matter to the timing which half of the
/// test a rejected candidate failed.
fn in_open_range<const L: usize>(x: &[u64; L], n: &[u64; L]) -> bool {
    // `n` is odd (every key type here checks it), so `n - 1` is `n` with its low bit cleared and
    // needs no borrow propagation.
    let mut n_minus_1 = *n;
    n_minus_1[0] &= !1;
    let mut one = [0u64; L];
    one[0] = 1;
    // `x - (n - 1)` borrows exactly when `x < n - 1`; `1 - x` borrows exactly when `1 < x`.
    let below_n_minus_1 = nat::sub(x, &n_minus_1).1;
    let above_1 = nat::sub(&one, x).1;
    (below_n_minus_1 & above_1) == 1
}

/// An RSA public key-establishment key: an [`RsaPublicKey`] with the extra checks listed in the
/// module docs' `# Key validation`, and a distinct type so that it cannot verify signatures (see
/// `# Key separation`).
///
/// # Encoding
///
/// `KEMPublicKey::encode`/`from_bytes` (implemented per size, e.g. for
/// `crate::rsa_2048::RSA2048KEMPublicKey`) use [`RsaPublicKey`]'s layout, `n || e`, unchanged.
/// Decoding applies this type's checks as well as [`RsaPublicKey`]'s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaKEMPublicKey<const L: usize>(pub(crate) RsaPublicKey<L>);

impl<const L: usize> RsaKEMPublicKey<L> {
    /// Builds a public key from its modulus and exponent. Returns
    /// `Err(`[`KEMError::DecodingError`]`)` in the cases [`RsaPublicKey::new`] rejects, and also
    /// if `e < 65,537` or `n`'s top bit is clear (see the module docs' `# Key validation`).
    pub fn new(n: &[u64; L], e: u32) -> Result<Self, KEMError> {
        Self::from_rsa_key(RsaPublicKey::new(n, e).map_err(kem_error)?)
    }

    /// Applies this type's own checks to an already-built [`RsaPublicKey`]. Crate-private, so there
    /// is no direct signature-key-to-KEM-key conversion in the public API. Key material still gets
    /// in through its raw components or encoding, which the two kinds of key share.
    pub(crate) fn from_rsa_key(pk: RsaPublicKey<L>) -> Result<Self, KEMError> {
        if pk.e() < MIN_PUBLIC_EXPONENT {
            return Err(KEMError::DecodingError(
                "RSA key-establishment public exponent must be at least 65537",
            ));
        }
        if !has_full_bit_length(pk.n()) {
            return Err(KEMError::DecodingError("RSA modulus must have its top bit set"));
        }
        Ok(Self(pk))
    }

    /// The modulus `n`.
    pub fn n(&self) -> &[u64; L] {
        self.0.n()
    }

    /// The public exponent `e`.
    pub fn e(&self) -> u32 {
        self.0.e()
    }
}

/// Defers to [`RsaPublicKey`]'s `Display`. Required by `KEMPublicKey`'s `Display` supertrait.
impl<const L: usize> Display for RsaKEMPublicKey<L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// An RSA private key-establishment key: an [`RsaPrivateKey`] (CRT form) with the modulus
/// bit-length check listed in the module docs' `# Key validation`, and a distinct type so that it
/// cannot sign (see `# Key separation`).
///
/// # Encoding
///
/// `KEMPrivateKey::encode`/`from_bytes` (implemented per size, e.g. for
/// `crate::rsa_2048::RSA2048KEMPrivateKey`) use [`RsaPrivateKey`]'s layout,
/// `p || q || dP || dQ || qInv`, unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaKEMPrivateKey<const L: usize, const HALF: usize>(pub(crate) RsaPrivateKey<L, HALF>);

impl<const L: usize, const HALF: usize> RsaKEMPrivateKey<L, HALF> {
    /// Builds a private key from its CRT components. Returns
    /// `Err(`[`KEMError::DecodingError`]`)` in the cases [`RsaPrivateKey::from_crt_components`]
    /// rejects, and also if `n = p * q`'s top bit is clear (see the module docs'
    /// `# Key validation`).
    pub fn from_crt_components(
        p: &[u64; HALF],
        q: &[u64; HALF],
        d_p: &[u64; HALF],
        d_q: &[u64; HALF],
        q_inv: &[u64; HALF],
    ) -> Result<Self, KEMError> {
        Self::from_rsa_key(
            RsaPrivateKey::from_crt_components(p, q, d_p, d_q, q_inv).map_err(kem_error)?,
        )
    }

    /// As [`RsaKEMPublicKey::from_rsa_key`], for the private half.
    pub(crate) fn from_rsa_key(sk: RsaPrivateKey<L, HALF>) -> Result<Self, KEMError> {
        if !has_full_bit_length(sk.n()) {
            return Err(KEMError::DecodingError("RSA modulus must have its top bit set"));
        }
        Ok(Self(sk))
    }

    /// The modulus `n = p * q`.
    pub fn n(&self) -> &[u64; L] {
        self.0.n()
    }
}

/// RSASVE (SP 800-56B Rev. 2 §7.2.1) at one modulus size, as a
/// [`KEMEncapsulator`]/[`KEMDecapsulator`]. Each size module names its own instantiation (e.g.
/// `crate::rsa_2048::RSASVE`), along with that size's `keygen`/`keygen_from_rng` as inherent
/// associated functions, which is where the KEM traits' docs put key generation.
///
/// `L`/`L2`/`L21`/`HALF`/`HALF2`/`HALF21` are the widths the rest of this crate threads through
/// `rsa_core` (see [`crate::modexp`]). `N_BYTES = 8 * L` is `nLen`, which is both the ciphertext
/// length and the shared-secret length. `SECURITY_BITS` is the modulus's SP 800-57 Part 1
/// security strength, the same value that size's `keygen_from_rng` demands of its RNG. `encaps_rng`
/// demands it too, and the shared secret is labelled with it.
///
/// Uninhabited: every operation is an associated function, as with the other KEMs in this
/// workspace.
#[allow(non_camel_case_types)]
pub struct RSASVE<
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
    const N_BYTES: usize,
    const SECURITY_BITS: usize,
> {
    _widths: PhantomData<[u64; L]>,
}

impl<
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
    const N_BYTES: usize,
    const SECURITY_BITS: usize,
    const PK_LEN: usize,
> KEMEncapsulator<RsaKEMPublicKey<L>, PK_LEN, N_BYTES, N_BYTES>
    for RSASVE<L, L2, L21, HALF, HALF2, HALF21, N_BYTES, SECURITY_BITS>
where
    RsaKEMPublicKey<L>: KEMPublicKey<PK_LEN>,
{
    /// RSASVE.GENERATE, drawing `Z` from the library's default OS-backed RNG. See
    /// [`Self::encaps_rng`].
    fn encaps(pk: &RsaKEMPublicKey<L>) -> Result<(KeyMaterial<N_BYTES>, [u8; N_BYTES]), KEMError> {
        Self::encaps_rng(pk, &mut DefaultRNG::default())
    }

    /// RSASVE.GENERATE((n, e)) (SP 800-56B Rev. 2 §7.2.1.2), drawing `Z` from `rng`. Returns
    /// `(Z, C)`: the secret value as a [`KeyMaterial`] of type
    /// [`KeyType::CryptographicRandom`] at the modulus's security strength, and the ciphertext.
    ///
    /// Errors: `RNGError(SecurityStrengthInsufficientForAlgorithm)` if `rng` is weaker than the
    /// modulus (§5.3: an RBG generating `Z` "shall be instantiated to support a security strength
    /// that is equal to or greater than the security strength associated with the RSA modulus
    /// length"),
    /// `RNGError` if `rng` fails, and `GenericError` if [`MAX_GENERATE_ATTEMPTS`] draws all fall
    /// outside `(1, n - 1)`, which a working RNG does not do (see that constant).
    // `Z`, `C`: SP 800-56B's own names (see QUALITY_AND_STYLE.md's naming exception).
    #[allow(non_snake_case)]
    fn encaps_rng(
        pk: &RsaKEMPublicKey<L>,
        rng: &mut dyn RNG,
    ) -> Result<(KeyMaterial<N_BYTES>, [u8; N_BYTES]), KEMError> {
        debug_assert_eq!(N_BYTES, 8 * L, "RSASVE needs N_BYTES == 8 * L");
        if rng.security_strength() < SecurityStrength::from_bits(SECURITY_BITS) {
            return Err(KEMError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm));
        }

        // Step 1: "nLen = len(n)/8, the byte length of the modulus n" -- N_BYTES, since
        // `RsaKEMPublicKey` guarantees `n` is exactly `8 * N_BYTES` bits.

        // `Z` and `z` are held in `Secret` so that they are scrubbed on every exit, including
        // the error ones: §7.2.1.2's closing paragraph requires this routine to "destroy any
        // locally stored portions of Z and z".
        let mut Z = Secret::<[u8; N_BYTES]>::new();
        let mut z = Secret::<[u64; L]>::new();
        let mut attempts = 0;
        loop {
            if attempts == MAX_GENERATE_ATTEMPTS {
                return Err(KEMError::GenericError(
                    "RSASVE.GENERATE: RNG output never fell within (1, n - 1)",
                ));
            }
            attempts += 1;
            // Step 2.a: "Using the RBG ..., generate Z, a byte string of nLen bytes."
            rng.next_bytes_out(&mut *Z)?;
            // Step 2.b: "z = BS2I(Z, nLen)."
            *z = limbs_from_be_bytes::<L, N_BYTES>(&Z);
            // Step 2.c: "If z does not satisfy 1 < z < (n – 1), then go to step 2a."
            if in_open_range(&z, pk.n()) {
                break;
            }
        }

        // Step 3.a: "c = RSAEP((n, e), z)". RSAEP's own step 1 range check (§7.1.1, "1 < m <
        // (n – 1)") is the one step 2.c has just ensured, so it is not repeated: `public_exp` is
        // RSAEP's step 2, `c = z^e mod n`.
        let c = public_exp::<L, L2, L21>(&pk.0, &z);
        // Step 3.b: "C = I2BS(c, nLen)."
        let C = be_bytes_from_limbs::<L, N_BYTES>(&c);

        // Step 4: "Output the string Z as the secret value, and the ciphertext C."
        let mut ss = KeyMaterial::<N_BYTES>::from_bytes_as_type(&*Z, KeyType::CryptographicRandom)?;
        do_hazardous_operations(&mut ss, |ss| {
            ss.set_security_strength(SecurityStrength::from_bits(SECURITY_BITS))
        })?;
        Ok((ss, C))
    }
}

impl<
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
    const N_BYTES: usize,
    const SECURITY_BITS: usize,
    const SK_LEN: usize,
> KEMDecapsulator<RsaKEMPrivateKey<L, HALF>, SK_LEN, N_BYTES, N_BYTES>
    for RSASVE<L, L2, L21, HALF, HALF2, HALF21, N_BYTES, SECURITY_BITS>
where
    RsaKEMPrivateKey<L, HALF>: KEMPrivateKey<SK_LEN>,
{
    /// RSASVE.RECOVER((n, d), C) (SP 800-56B Rev. 2 §7.2.1.3), with the private key in CRT form
    /// (§7.1.2.3's RSADP). Returns `Z` as a [`KeyMaterial`] of type
    /// [`KeyType::CryptographicRandom`] at the modulus's security strength, matching what
    /// [`KEMEncapsulator::encaps_rng`] returned to the other party.
    ///
    /// Errors: `LengthError` if `ct` is not `nLen` bytes long (step 2), and `DecapsulationFailed`
    /// if RSADP finds the ciphertext out of range (step 3.c). §7.2.1.3 calls both "an indication
    /// of a decryption error". They are kept as separate variants because every KEM in this workspace reports a
    /// wrong-length ciphertext as `LengthError`, which `bouncycastle_core_test_framework`'s KEM
    /// suite checks. A ciphertext that is in range but was never produced by `encaps` is *not*
    /// detected. RSASVE has no redundancy to check, so such a ciphertext just recovers a different
    /// `Z` (see the crate docs' `# Security Considerations`).
    #[allow(non_snake_case)]
    fn decaps(sk: &RsaKEMPrivateKey<L, HALF>, ct: &[u8]) -> Result<KeyMaterial<N_BYTES>, KEMError> {
        debug_assert_eq!(N_BYTES, 8 * L, "RSASVE needs N_BYTES == 8 * L");
        // Step 1: "nLen = len(n)/8" -- N_BYTES, as in `encaps_rng`.

        // Step 2: "If the length of the ciphertext C is not nLen bytes in length, output an
        // indication of a decryption error".
        let C: &[u8; N_BYTES] = ct
            .try_into()
            .map_err(|_| KEMError::LengthError("RSASVE ciphertext must be exactly nLen bytes"))?;

        // Step 3.a: "c = BS2I(C)."
        let c = limbs_from_be_bytes::<L, N_BYTES>(C);

        // Step 3.b/3.c: "z = RSADP((n, d), c)", and "If RSADP indicates that the ciphertext is
        // out of range, output an indication of a decryption error". This is RSADP's step 1
        // (§7.1.2.3, "If the ciphertext c does not satisfy 1 < c < (n – 1) ..."), checked here
        // rather than inside a separate RSADP function, and `crt_exp` is its steps 2-5 (`mp =
        // c^dP mod p`, `mq = c^dQ mod q`, `h = ((mp − mq) × qInv) mod p`, `m = mq + q × h`).
        // `c` is the public ciphertext, so the range check need not be constant-time, although
        // it is.
        if !in_open_range(&c, sk.n()) {
            return Err(KEMError::DecapsulationFailed);
        }
        let mut z = Secret::<[u64; L]>::new();
        *z = crt_exp::<L, L2, L21, HALF, HALF2, HALF21>(&sk.0, &c);

        // Step 3.d: "Z = I2BS(z, nLen)."
        let mut Z = Secret::<[u8; N_BYTES]>::new();
        *Z = be_bytes_from_limbs::<L, N_BYTES>(&z);

        // Step 4: "Output the string Z as the secret value (i.e., the shared secret)".
        let mut ss = KeyMaterial::<N_BYTES>::from_bytes_as_type(&*Z, KeyType::CryptographicRandom)?;
        do_hazardous_operations(&mut ss, |ss| {
            ss.set_security_strength(SecurityStrength::from_bits(SECURITY_BITS))
        })?;
        Ok(ss)
    }
}

/// Wraps a size module's signature-typed `keygen_from_rng` result as a KEM key pair, applying
/// the KEM key types' checks. These always pass for this crate's own keys, which have `e = 65537`
/// and an `n` of exactly `nlen` bits by construction (see [`crate::keygen`]).
pub(crate) fn keygen_from<const L: usize, const HALF: usize>(
    pair: Result<(RsaPublicKey<L>, RsaPrivateKey<L, HALF>), SignatureError>,
) -> Result<(RsaKEMPublicKey<L>, RsaKEMPrivateKey<L, HALF>), KEMError> {
    let (pk, sk) = pair.map_err(kem_error)?;
    Ok((RsaKEMPublicKey::from_rsa_key(pk)?, RsaKEMPrivateKey::from_rsa_key(sk)?))
}

/// Decodes [`RsaPrivateKey`]'s raw layout into an [`RsaKEMPrivateKey`], for the per-size
/// `KEMPrivateKey::from_bytes` impls, which reject a wrong-length slice before calling this.
pub(crate) fn private_key_from_bytes<
    const L: usize,
    const HALF: usize,
    const HALF_BYTES: usize,
    const SK_LEN: usize,
>(
    bytes: &[u8; SK_LEN],
) -> Result<RsaKEMPrivateKey<L, HALF>, KEMError> {
    RsaKEMPrivateKey::from_rsa_key(
        RsaPrivateKey::from_bytes_raw::<HALF_BYTES, SK_LEN>(bytes).map_err(kem_error)?,
    )
}

/// Decodes [`RsaPublicKey`]'s raw layout into an [`RsaKEMPublicKey`], for the per-size
/// `KEMPublicKey::from_bytes` impls, which reject a wrong-length slice before calling this.
pub(crate) fn public_key_from_bytes<const L: usize, const N_BYTES: usize, const PK_LEN: usize>(
    bytes: &[u8; PK_LEN],
) -> Result<RsaKEMPublicKey<L>, KEMError> {
    RsaKEMPublicKey::from_rsa_key(
        RsaPublicKey::from_bytes_raw::<N_BYTES, PK_LEN>(bytes).map_err(kem_error)?,
    )
}
