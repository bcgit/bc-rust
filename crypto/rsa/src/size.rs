//! The modulus size as a type: [`RsaSize`], implemented by the markers [`RSA1024`] to
//! [`RSA8192`], names a size's limb and byte widths and routes to the width-fixed engine
//! ([`crate::modexp`], `rsa_core`, [`crate::keygen`], the codec), so that the scheme types and
//! the keys are written once over `K: RsaSize`. [`RsaSigningSize`] marks the sizes that sign
//! and generate keys, RSA-2048 and up; RSA-1024 and RSA-1536 implement only [`RsaSize`], which
//! is what keeps them verify-only (the crate's `# Scope`). Widths reach generic code as array
//! types: `K::Modulus` is the `[u8; N]` a signature or ciphertext is, and where a `core` trait
//! needs `N` itself an impl is bound `K: RsaSize<Modulus = [u8; N]>`, which the solver resolves
//! from `K`.

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use crate::keygen::{keygen_as, keygen_from_rng, validate_key_pair};
use crate::keys::{
    RsaPrivateComponents, RsaPrivateKey, RsaPublicComponents, RsaPublicKey, modulus_strength,
};
use crate::rsa_core;
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use crate::rsassa_pss::{PssHash, PssParams, RSASSA_PSS};
use crate::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey};
use bouncycastle_core::errors::{KEMError, SignatureError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{AlgorithmOID, HashAlgParams, HashOneShot, RNG};
use bouncycastle_ec::montgomery;
use bouncycastle_ec::nat;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::{NoPadding, ZeroizablePrimitive};
use core::fmt::Debug;
use core::num::NonZeroUsize;

/// A fixed-size array a size's values are held or encoded in: `[u64; L]` limbs or `[u8; N]`
/// bytes. `ZEROED` (from [`ZeroizablePrimitive`]) stands in for `Default`, which arrays over
/// 32 elements lack.
pub trait Array<T: Copy>:
    ZeroizablePrimitive + NoPadding + AsRef<[T]> + AsMut<[T]> + PartialEq + Eq + Debug + 'static
{
    /// The number of elements.
    const LEN: usize;
}

impl<T: ZeroizablePrimitive + NoPadding + PartialEq + Eq + Debug + 'static, const N: usize> Array<T>
    for [T; N]
{
    const LEN: usize = N;
}

/// A modulus size: the marker's view of the engine at one width. Sealed, since an impl is a
/// routing table into this crate's arithmetic and every length below must agree with it
/// ([`check_lengths`]).
///
/// The public-key exponentiation is not a method code outside the crate can call: a public
/// key is used through a scheme, by the roles its key types implement.
///
/// ```compile_fail,E0599
/// use bouncycastle_rsa::RSA2048;
/// use bouncycastle_rsa::size::RsaSize;
/// let _ = RSA2048::public_exp(&[3u64; 32], 65537, &[1u64; 32]);
/// ```
///
/// Nor through a bound, which reaches the method but cannot supply its last argument:
///
/// ```compile_fail,E0277
/// use bouncycastle_rsa::size::RsaSize;
/// fn raw<K: RsaSize>(n: &K::Limbs, x: &K::Limbs) -> K::Limbs {
///     K::public_exp(n, 65537, x, Default::default())
/// }
/// ```
///
/// ```
/// use bouncycastle_rsa::RSA2048;
/// use bouncycastle_rsa::size::RsaSize;
/// fn less<K: RsaSize>(x: &K::Limbs, y: &K::Limbs) -> bool {
///     K::is_less(x, y)
/// }
/// assert!(less::<RSA2048>(&[1u64; 32], &[3u64; 32]));
/// ```
pub trait RsaSize:
    sealed::Sealed
    + sealed::PublicKeyEngine<<Self as RsaSize>::Limbs>
    + Copy
    + Clone
    + Debug
    + Default
    + PartialEq
    + Eq
    + 'static
{
    /// The size's name, `RSA-2048`.
    const NAME: &'static str;
    /// The modulus length in bits as text, for algorithm names: `2048`.
    const BITS_NAME: &'static str;
    /// `nLen`, the modulus length in bits.
    const BITS: usize;
    /// `nLen / 8`: the byte length of the modulus, of a signature, of an RSASVE ciphertext and
    /// of its shared secret.
    const K_LEN: usize;
    /// `K_LEN + 8`: the public key's encoding, `n || e`.
    const PK_LEN: usize;
    /// `5 * K_LEN / 2 + 8`: the private key's encoding, `p || q || dP || dQ || qInv || e`.
    const SK_LEN: usize;
    /// The strength SP 800-57 Part 1 Rev. 5 Table 2 gives the modulus length; `None` below
    /// 2048 bits.
    const STRENGTH: SecurityStrength;

    /// `[u64; K_LEN / 8]`, a modulus-width integer.
    type Limbs: Array<u64>;
    /// `[u64; K_LEN / 16]`, a prime-width integer.
    type HalfLimbs: Array<u64>;
    /// `[u8; K_LEN]`.
    type Modulus: Array<u8>;
    /// `[u8; K_LEN / 2]`, one CRT component's encoding.
    type HalfBytes: Array<u8>;
    /// `[u8; PK_LEN]`.
    type PublicKeyEncoded: Array<u8>;
    /// `[u8; SK_LEN]`.
    type PrivateKeyEncoded: Array<u8>;

    /// Big-endian bytes to limbs.
    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs;
    /// Limbs to big-endian bytes.
    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus;
    /// Whether `x < y`.
    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool;
}

/// A size this crate signs, generates keys and establishes keys at: RSA-2048 and up (SP
/// 800-131A's 112-bit floor).
///
/// The private-key exponentiation is not a method code outside the crate can call, by name or
/// through a bound: a private key is used through a scheme, by the roles its key types
/// implement.
///
/// ```compile_fail,E0599
/// use bouncycastle_rsa::RSA2048;
/// use bouncycastle_rsa::keys::RsaPrivateComponents;
/// use bouncycastle_rsa::size::{RsaSigningSize, RsaSize};
/// fn raw(sk: &RsaPrivateComponents<RSA2048>, m: &[u64; 32], out: &mut [u64; 32]) {
///     let _ = RSA2048::crt_exp(sk, m, out);
/// }
/// ```
///
/// ```
/// use bouncycastle_rsa::RSA2048;
/// use bouncycastle_rsa::keys::RsaPrivateComponents;
/// use bouncycastle_rsa::size::{RsaSigningSize, RsaSize};
/// fn modulus(sk: &RsaPrivateComponents<RSA2048>) -> [u8; 256] {
///     RSA2048::be_bytes_from_limbs(sk.n())
/// }
/// ```
///
/// ```compile_fail,E0277
/// use bouncycastle_rsa::keys::RsaPrivateComponents;
/// use bouncycastle_rsa::size::{RsaSigningSize, RsaSize};
/// fn raw<K: RsaSigningSize>(sk: &RsaPrivateComponents<K>, m: &K::Limbs, out: &mut K::Limbs) {
///     let _ = K::crt_exp(sk, m, out, Default::default());
/// }
/// ```
///
/// ```
/// use bouncycastle_rsa::keys::RsaPrivateComponents;
/// use bouncycastle_rsa::size::{RsaSigningSize, RsaSize};
/// fn modulus<K: RsaSigningSize>(sk: &RsaPrivateComponents<K>) -> K::Modulus {
///     K::be_bytes_from_limbs(sk.n())
/// }
/// ```
pub trait RsaSigningSize: RsaSize + sealed::PrivateKeyEngine {
    /// The Miller-Rabin rounds run on a prime of this size: 25 at every size, the count the FIPS
    /// 140-3 Implementation Guidance (IG C.F, option 2) strongly recommends in place of FIPS 186-5
    /// Table B.1's minimum, which is 5 for a 1024-bit prime and 4 for larger ones.
    const MR_ROUNDS: NonZeroUsize;
    /// The Miller-Rabin rounds [`RsaPrivateComponents::validate`] runs on each prime of a key
    /// from elsewhere: half of `ES(nBits)`, the strength SP 800-56B Rev. 2 Appendix D Table 4
    /// estimates for the modulus length (112, 128, 152 and 200 bits at 2048, 3072, 4096 and
    /// 8192), so that a composite passes with probability at most `2^-ES(nBits)` (§6.4.1.2.1
    /// step 5).
    const VALIDATION_MR_ROUNDS: NonZeroUsize;
    /// FIPS 186-5 Appendix A.1.3 key generation from `rng`, which must offer the size's
    /// [`STRENGTH`](RsaSize::STRENGTH).
    ///
    /// # Errors
    /// [`SignatureError::RNGError`] if the RNG is weaker than the size or fails to deliver;
    /// [`SignatureError::GenericError`] if no prime was found within the candidate budget, or
    /// no usable Miller-Rabin base in 128 draws.
    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicComponents<Self>, RsaPrivateComponents<Self>), SignatureError>;

    // The private key's arithmetic: only a signing size has a private key, so only a signing
    // size routes it.
    /// Big-endian bytes to prime-width limbs.
    fn half_limbs_from_be_bytes(bytes: &Self::HalfBytes) -> Self::HalfLimbs;
    /// Prime-width limbs to big-endian bytes.
    fn half_be_bytes_from_limbs(limbs: &Self::HalfLimbs) -> Self::HalfBytes;
    /// `p * q`, exact: the modulus from its primes.
    fn modulus_from_primes(p: &Self::HalfLimbs, q: &Self::HalfLimbs) -> Self::Limbs;
    /// Whether `x < y`, at prime width.
    fn half_is_less(x: &Self::HalfLimbs, y: &Self::HalfLimbs) -> bool;
}

/// Implemented on a signing size marker: a signature key pair for one scheme and hash, so a
/// caller starts from the size and spells the algorithm,
/// `RSA2048::generate_pss_signature_key_pair::<SHA256>(&mut rng)`, and the pair is a key for
/// that algorithm and no other (SP 800-57 Part 1 Rev. 5's one scheme per key pair). The hash
/// is spelled, never defaulted, as on the ECDSA markers: the customary pairing is a convention
/// that moves. All of them run [`RsaSigningSize::keygen`], FIPS 186-5 Appendix A.1.3; the RNG is
/// an argument, not a default. The KEM pair is [`KemKeyPair`], a different type, as
/// [`rsasve`](crate::rsasve)'s `# Key separation` asks.
pub trait SignatureKeyPair: RsaSigningSize {
    /// A key pair for RSASSA-PKCS1-v1_5 with `H`.
    ///
    /// # Errors
    /// As [`RsaSigningSize::keygen`].
    #[allow(clippy::type_complexity)]
    fn generate_pkcs1_v1_5_signature_key_pair<H: HashOneShot + HashAlgParams + AlgorithmOID>(
        rng: &mut dyn RNG,
    ) -> Result<
        (RsaPublicKey<RSASSA_PKCS1_v1_5<Self, H>>, RsaPrivateKey<RSASSA_PKCS1_v1_5<Self, H>>),
        SignatureError,
    >;

    /// A key pair for RSASSA-PSS with `H` under its conventional parameters
    /// ([`PssHash`]: MGF1 over `H` for SHA-2 and SHA-3, the XOF
    /// itself for SHAKE).
    ///
    /// # Errors
    /// As [`RsaSigningSize::keygen`].
    #[allow(clippy::type_complexity)]
    fn generate_pss_signature_key_pair<H: PssHash>(
        rng: &mut dyn RNG,
    ) -> Result<
        (RsaPublicKey<RSASSA_PSS<Self, H>>, RsaPrivateKey<RSASSA_PSS<Self, H>>),
        SignatureError,
    >;

    /// A key pair for RSASSA-PSS with `H` under the spelled parameters `P`: another MGF1 hash
    /// or salt length ([`Mgf1`](crate::rsassa_pss::Mgf1)) or no salt
    /// ([`NoSalt`](crate::rsassa_pss::NoSalt)).
    ///
    /// # Errors
    /// As [`RsaSigningSize::keygen`].
    #[allow(clippy::type_complexity)]
    fn generate_pss_signature_key_pair_with<H: HashOneShot + HashAlgParams, P: PssParams<H>>(
        rng: &mut dyn RNG,
    ) -> Result<
        (RsaPublicKey<RSASSA_PSS<Self, H, P>>, RsaPrivateKey<RSASSA_PSS<Self, H, P>>),
        SignatureError,
    >;
}

impl<K: RsaSigningSize> SignatureKeyPair for K {
    fn generate_pkcs1_v1_5_signature_key_pair<H: HashOneShot + HashAlgParams + AlgorithmOID>(
        rng: &mut dyn RNG,
    ) -> Result<
        (RsaPublicKey<RSASSA_PKCS1_v1_5<K, H>>, RsaPrivateKey<RSASSA_PKCS1_v1_5<K, H>>),
        SignatureError,
    > {
        keygen_as::<K, _, _>(rng, |pair| {
            let (pk, sk) = pair?;
            Ok((RsaPublicKey::from_components(pk), RsaPrivateKey::from_components(sk)))
        })
    }

    fn generate_pss_signature_key_pair<H: PssHash>(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicKey<RSASSA_PSS<K, H>>, RsaPrivateKey<RSASSA_PSS<K, H>>), SignatureError>
    {
        keygen_as::<K, _, _>(rng, |pair| {
            let (pk, sk) = pair?;
            Ok((RsaPublicKey::from_components(pk), RsaPrivateKey::from_components(sk)))
        })
    }

    fn generate_pss_signature_key_pair_with<H: HashOneShot + HashAlgParams, P: PssParams<H>>(
        rng: &mut dyn RNG,
    ) -> Result<
        (RsaPublicKey<RSASSA_PSS<K, H, P>>, RsaPrivateKey<RSASSA_PSS<K, H, P>>),
        SignatureError,
    > {
        keygen_as::<K, _, _>(rng, |pair| {
            let (pk, sk) = pair?;
            Ok((RsaPublicKey::from_components(pk), RsaPrivateKey::from_components(sk)))
        })
    }
}

/// Implemented on a signing size marker: the RSASVE key-establishment pair
/// (`RSA2048::generate_kem_key_pair(&mut rng)`), the same generator as the signature pair's,
/// in the KEM key types.
pub trait KemKeyPair {
    /// The size's KEM public key.
    type PublicKey;
    /// The size's KEM private key.
    type PrivateKey;

    /// Key pair generation from `rng`.
    ///
    /// # Errors
    /// As [`RsaSigningSize::keygen`], as a [`KEMError`].
    fn generate_kem_key_pair(
        rng: &mut dyn RNG,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), KEMError>;
}

impl<K: RsaSigningSize> KemKeyPair for K {
    type PublicKey = RsaKEMPublicKey<K>;
    type PrivateKey = RsaKEMPrivateKey<K>;

    fn generate_kem_key_pair(
        rng: &mut dyn RNG,
    ) -> Result<(RsaKEMPublicKey<K>, RsaKEMPrivateKey<K>), KEMError> {
        keygen_as::<K, _, _>(rng, crate::rsasve::keygen_from::<K>)
    }
}

/// The lesser of two strengths: a scheme's strength is its modulus's or its hash's, whichever
/// is lower.
pub const fn min_strength(a: SecurityStrength, b: SecurityStrength) -> SecurityStrength {
    if (a as u8) <= (b as u8) { a } else { b }
}

/// The lengths an [`RsaSize`] impl states, checked against the array types it names and each
/// other; evaluated as a `const` beside every impl.
pub const fn check_lengths<K: RsaSize>() {
    assert!(K::BITS % 64 == 0, "the modulus is whole limbs");
    assert!(K::K_LEN == K::BITS / 8, "K_LEN is the modulus's byte length");
    assert!(<K::Limbs as Array<u64>>::LEN * 8 == K::K_LEN, "Limbs spans the modulus");
    assert!(
        <K::HalfLimbs as Array<u64>>::LEN * 2 == <K::Limbs as Array<u64>>::LEN,
        "HalfLimbs is half"
    );
    assert!(<K::Modulus as Array<u8>>::LEN == K::K_LEN, "Modulus is K_LEN bytes");
    assert!(<K::HalfBytes as Array<u8>>::LEN * 2 == K::K_LEN, "HalfBytes is K_LEN / 2 bytes");
    assert!(K::PK_LEN == K::K_LEN + 8, "PK_LEN is n || e");
    assert!(
        <K::PublicKeyEncoded as Array<u8>>::LEN == K::PK_LEN,
        "PublicKeyEncoded is PK_LEN bytes"
    );
    assert!(K::SK_LEN == 5 * K::K_LEN / 2 + 8, "SK_LEN is the five CRT components and e");
    assert!(
        <K::PrivateKeyEncoded as Array<u8>>::LEN == K::SK_LEN,
        "PrivateKeyEncoded is SK_LEN bytes"
    );
}

/// RSA-1024 (verification only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RSA1024;

impl sealed::Sealed for RSA1024 {}

impl RsaSize for RSA1024 {
    const NAME: &'static str = "RSA-1024";
    const BITS_NAME: &'static str = "1024";
    const BITS: usize = 1024;
    const K_LEN: usize = 128;
    const PK_LEN: usize = 136;
    const SK_LEN: usize = 328;
    const STRENGTH: SecurityStrength = modulus_strength(16);

    type Limbs = [u64; 16];
    type HalfLimbs = [u64; 8];
    type Modulus = [u8; 128];
    type HalfBytes = [u8; 64];
    type PublicKeyEncoded = [u8; 136];
    type PrivateKeyEncoded = [u8; 328];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<16, 128>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<16, 128>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }
}

impl sealed::PublicKeyEngine<[u64; 16]> for RSA1024 {
    fn public_exp(n: &[u64; 16], e: u64, x: &[u64; 16], _: sealed::EngineToken) -> [u64; 16] {
        rsa_core::public_exp::<16, 32, 33>(n, e, x)
    }
}

const _: () = check_lengths::<RSA1024>();

/// RSA-1536 (verification only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RSA1536;

impl sealed::Sealed for RSA1536 {}

impl RsaSize for RSA1536 {
    const NAME: &'static str = "RSA-1536";
    const BITS_NAME: &'static str = "1536";
    const BITS: usize = 1536;
    const K_LEN: usize = 192;
    const PK_LEN: usize = 200;
    const SK_LEN: usize = 488;
    const STRENGTH: SecurityStrength = modulus_strength(24);

    type Limbs = [u64; 24];
    type HalfLimbs = [u64; 12];
    type Modulus = [u8; 192];
    type HalfBytes = [u8; 96];
    type PublicKeyEncoded = [u8; 200];
    type PrivateKeyEncoded = [u8; 488];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<24, 192>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<24, 192>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }
}

impl sealed::PublicKeyEngine<[u64; 24]> for RSA1536 {
    fn public_exp(n: &[u64; 24], e: u64, x: &[u64; 24], _: sealed::EngineToken) -> [u64; 24] {
        rsa_core::public_exp::<24, 48, 49>(n, e, x)
    }
}

const _: () = check_lengths::<RSA1536>();

/// RSA-2048.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RSA2048;

impl sealed::Sealed for RSA2048 {}

impl RsaSize for RSA2048 {
    const NAME: &'static str = "RSA-2048";
    const BITS_NAME: &'static str = "2048";
    const BITS: usize = 2048;
    const K_LEN: usize = 256;
    const PK_LEN: usize = 264;
    const SK_LEN: usize = 648;
    const STRENGTH: SecurityStrength = modulus_strength(32);

    type Limbs = [u64; 32];
    type HalfLimbs = [u64; 16];
    type Modulus = [u8; 256];
    type HalfBytes = [u8; 128];
    type PublicKeyEncoded = [u8; 264];
    type PrivateKeyEncoded = [u8; 648];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<32, 256>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<32, 256>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }
}

impl sealed::PublicKeyEngine<[u64; 32]> for RSA2048 {
    fn public_exp(n: &[u64; 32], e: u64, x: &[u64; 32], _: sealed::EngineToken) -> [u64; 32] {
        rsa_core::public_exp::<32, 64, 65>(n, e, x)
    }
}

const _: () = check_lengths::<RSA2048>();

impl RsaSigningSize for RSA2048 {
    const MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(25).unwrap();
    const VALIDATION_MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(56).unwrap();

    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicComponents<Self>, RsaPrivateComponents<Self>), SignatureError> {
        keygen_from_rng::<Self, 16, 32, 33>(rng, Self::MR_ROUNDS, Self::STRENGTH)
    }

    fn half_limbs_from_be_bytes(bytes: &Self::HalfBytes) -> Self::HalfLimbs {
        limbs_from_be_bytes::<16, 128>(bytes)
    }

    fn half_be_bytes_from_limbs(limbs: &Self::HalfLimbs) -> Self::HalfBytes {
        be_bytes_from_limbs::<16, 128>(limbs)
    }

    fn modulus_from_primes(p: &Self::HalfLimbs, q: &Self::HalfLimbs) -> Self::Limbs {
        montgomery::widening_mul::<16, 32>(p, q)
    }

    fn half_is_less(x: &Self::HalfLimbs, y: &Self::HalfLimbs) -> bool {
        nat::sub(x, y).1 == 1
    }
}

impl sealed::PrivateKeyEngine for RSA2048 {
    fn crt_congruences(
        p: &Self::HalfLimbs,
        q: &Self::HalfLimbs,
        d_p: &Self::HalfLimbs,
        d_q: &Self::HalfLimbs,
        q_inv: &Self::HalfLimbs,
        e: u64,
        _: sealed::EngineToken,
    ) -> [Condition<u64>; 3] {
        rsa_core::crt_congruences::<16, 32>(p, q, d_p, d_q, q_inv, e)
    }

    fn validate_key_pair(
        sk: &RsaPrivateComponents<Self>,
        rng: &mut dyn RNG,
        _: sealed::EngineToken,
    ) -> Result<(), SignatureError> {
        validate_key_pair::<Self, 16, 32, 33>(sk, rng)
    }

    fn crt_exp(
        sk: &RsaPrivateComponents<Self>,
        m: &Self::Limbs,
        out: &mut Self::Limbs,
        _: sealed::EngineToken,
    ) -> Condition<u64> {
        rsa_core::crt_exp_checked::<32, 64, 65, 16, 32, 33>(
            sk.p(),
            sk.q(),
            sk.d_p(),
            sk.d_q(),
            sk.q_inv(),
            sk.n(),
            sk.e(),
            m,
            out,
        )
    }
}

/// RSA-3072.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RSA3072;

impl sealed::Sealed for RSA3072 {}

impl RsaSize for RSA3072 {
    const NAME: &'static str = "RSA-3072";
    const BITS_NAME: &'static str = "3072";
    const BITS: usize = 3072;
    const K_LEN: usize = 384;
    const PK_LEN: usize = 392;
    const SK_LEN: usize = 968;
    const STRENGTH: SecurityStrength = modulus_strength(48);

    type Limbs = [u64; 48];
    type HalfLimbs = [u64; 24];
    type Modulus = [u8; 384];
    type HalfBytes = [u8; 192];
    type PublicKeyEncoded = [u8; 392];
    type PrivateKeyEncoded = [u8; 968];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<48, 384>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<48, 384>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }
}

impl sealed::PublicKeyEngine<[u64; 48]> for RSA3072 {
    fn public_exp(n: &[u64; 48], e: u64, x: &[u64; 48], _: sealed::EngineToken) -> [u64; 48] {
        rsa_core::public_exp::<48, 96, 97>(n, e, x)
    }
}

const _: () = check_lengths::<RSA3072>();

impl RsaSigningSize for RSA3072 {
    const MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(25).unwrap();
    const VALIDATION_MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(64).unwrap();

    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicComponents<Self>, RsaPrivateComponents<Self>), SignatureError> {
        keygen_from_rng::<Self, 24, 48, 49>(rng, Self::MR_ROUNDS, Self::STRENGTH)
    }

    fn half_limbs_from_be_bytes(bytes: &Self::HalfBytes) -> Self::HalfLimbs {
        limbs_from_be_bytes::<24, 192>(bytes)
    }

    fn half_be_bytes_from_limbs(limbs: &Self::HalfLimbs) -> Self::HalfBytes {
        be_bytes_from_limbs::<24, 192>(limbs)
    }

    fn modulus_from_primes(p: &Self::HalfLimbs, q: &Self::HalfLimbs) -> Self::Limbs {
        montgomery::widening_mul::<24, 48>(p, q)
    }

    fn half_is_less(x: &Self::HalfLimbs, y: &Self::HalfLimbs) -> bool {
        nat::sub(x, y).1 == 1
    }
}

impl sealed::PrivateKeyEngine for RSA3072 {
    fn crt_congruences(
        p: &Self::HalfLimbs,
        q: &Self::HalfLimbs,
        d_p: &Self::HalfLimbs,
        d_q: &Self::HalfLimbs,
        q_inv: &Self::HalfLimbs,
        e: u64,
        _: sealed::EngineToken,
    ) -> [Condition<u64>; 3] {
        rsa_core::crt_congruences::<24, 48>(p, q, d_p, d_q, q_inv, e)
    }

    fn validate_key_pair(
        sk: &RsaPrivateComponents<Self>,
        rng: &mut dyn RNG,
        _: sealed::EngineToken,
    ) -> Result<(), SignatureError> {
        validate_key_pair::<Self, 24, 48, 49>(sk, rng)
    }

    fn crt_exp(
        sk: &RsaPrivateComponents<Self>,
        m: &Self::Limbs,
        out: &mut Self::Limbs,
        _: sealed::EngineToken,
    ) -> Condition<u64> {
        rsa_core::crt_exp_checked::<48, 96, 97, 24, 48, 49>(
            sk.p(),
            sk.q(),
            sk.d_p(),
            sk.d_q(),
            sk.q_inv(),
            sk.n(),
            sk.e(),
            m,
            out,
        )
    }
}

/// RSA-4096.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RSA4096;

impl sealed::Sealed for RSA4096 {}

impl RsaSize for RSA4096 {
    const NAME: &'static str = "RSA-4096";
    const BITS_NAME: &'static str = "4096";
    const BITS: usize = 4096;
    const K_LEN: usize = 512;
    const PK_LEN: usize = 520;
    const SK_LEN: usize = 1288;
    const STRENGTH: SecurityStrength = modulus_strength(64);

    type Limbs = [u64; 64];
    type HalfLimbs = [u64; 32];
    type Modulus = [u8; 512];
    type HalfBytes = [u8; 256];
    type PublicKeyEncoded = [u8; 520];
    type PrivateKeyEncoded = [u8; 1288];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<64, 512>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<64, 512>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }
}

impl sealed::PublicKeyEngine<[u64; 64]> for RSA4096 {
    fn public_exp(n: &[u64; 64], e: u64, x: &[u64; 64], _: sealed::EngineToken) -> [u64; 64] {
        rsa_core::public_exp::<64, 128, 129>(n, e, x)
    }
}

const _: () = check_lengths::<RSA4096>();

impl RsaSigningSize for RSA4096 {
    const MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(25).unwrap();
    const VALIDATION_MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(76).unwrap();

    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicComponents<Self>, RsaPrivateComponents<Self>), SignatureError> {
        keygen_from_rng::<Self, 32, 64, 65>(rng, Self::MR_ROUNDS, Self::STRENGTH)
    }

    fn half_limbs_from_be_bytes(bytes: &Self::HalfBytes) -> Self::HalfLimbs {
        limbs_from_be_bytes::<32, 256>(bytes)
    }

    fn half_be_bytes_from_limbs(limbs: &Self::HalfLimbs) -> Self::HalfBytes {
        be_bytes_from_limbs::<32, 256>(limbs)
    }

    fn modulus_from_primes(p: &Self::HalfLimbs, q: &Self::HalfLimbs) -> Self::Limbs {
        montgomery::widening_mul::<32, 64>(p, q)
    }

    fn half_is_less(x: &Self::HalfLimbs, y: &Self::HalfLimbs) -> bool {
        nat::sub(x, y).1 == 1
    }
}

impl sealed::PrivateKeyEngine for RSA4096 {
    fn crt_congruences(
        p: &Self::HalfLimbs,
        q: &Self::HalfLimbs,
        d_p: &Self::HalfLimbs,
        d_q: &Self::HalfLimbs,
        q_inv: &Self::HalfLimbs,
        e: u64,
        _: sealed::EngineToken,
    ) -> [Condition<u64>; 3] {
        rsa_core::crt_congruences::<32, 64>(p, q, d_p, d_q, q_inv, e)
    }

    fn validate_key_pair(
        sk: &RsaPrivateComponents<Self>,
        rng: &mut dyn RNG,
        _: sealed::EngineToken,
    ) -> Result<(), SignatureError> {
        validate_key_pair::<Self, 32, 64, 65>(sk, rng)
    }

    fn crt_exp(
        sk: &RsaPrivateComponents<Self>,
        m: &Self::Limbs,
        out: &mut Self::Limbs,
        _: sealed::EngineToken,
    ) -> Condition<u64> {
        rsa_core::crt_exp_checked::<64, 128, 129, 32, 64, 65>(
            sk.p(),
            sk.q(),
            sk.d_p(),
            sk.d_q(),
            sk.q_inv(),
            sk.n(),
            sk.e(),
            m,
            out,
        )
    }
}

/// RSA-8192.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RSA8192;

impl sealed::Sealed for RSA8192 {}

impl RsaSize for RSA8192 {
    const NAME: &'static str = "RSA-8192";
    const BITS_NAME: &'static str = "8192";
    const BITS: usize = 8192;
    const K_LEN: usize = 1024;
    const PK_LEN: usize = 1032;
    const SK_LEN: usize = 2568;
    const STRENGTH: SecurityStrength = modulus_strength(128);

    type Limbs = [u64; 128];
    type HalfLimbs = [u64; 64];
    type Modulus = [u8; 1024];
    type HalfBytes = [u8; 512];
    type PublicKeyEncoded = [u8; 1032];
    type PrivateKeyEncoded = [u8; 2568];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<128, 1024>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<128, 1024>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }
}

impl sealed::PublicKeyEngine<[u64; 128]> for RSA8192 {
    fn public_exp(n: &[u64; 128], e: u64, x: &[u64; 128], _: sealed::EngineToken) -> [u64; 128] {
        rsa_core::public_exp::<128, 256, 257>(n, e, x)
    }
}

const _: () = check_lengths::<RSA8192>();

impl RsaSigningSize for RSA8192 {
    const MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(25).unwrap();
    const VALIDATION_MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(100).unwrap();

    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicComponents<Self>, RsaPrivateComponents<Self>), SignatureError> {
        keygen_from_rng::<Self, 64, 128, 129>(rng, Self::MR_ROUNDS, Self::STRENGTH)
    }

    fn half_limbs_from_be_bytes(bytes: &Self::HalfBytes) -> Self::HalfLimbs {
        limbs_from_be_bytes::<64, 512>(bytes)
    }

    fn half_be_bytes_from_limbs(limbs: &Self::HalfLimbs) -> Self::HalfBytes {
        be_bytes_from_limbs::<64, 512>(limbs)
    }

    fn modulus_from_primes(p: &Self::HalfLimbs, q: &Self::HalfLimbs) -> Self::Limbs {
        montgomery::widening_mul::<64, 128>(p, q)
    }

    fn half_is_less(x: &Self::HalfLimbs, y: &Self::HalfLimbs) -> bool {
        nat::sub(x, y).1 == 1
    }
}

impl sealed::PrivateKeyEngine for RSA8192 {
    fn crt_congruences(
        p: &Self::HalfLimbs,
        q: &Self::HalfLimbs,
        d_p: &Self::HalfLimbs,
        d_q: &Self::HalfLimbs,
        q_inv: &Self::HalfLimbs,
        e: u64,
        _: sealed::EngineToken,
    ) -> [Condition<u64>; 3] {
        rsa_core::crt_congruences::<64, 128>(p, q, d_p, d_q, q_inv, e)
    }

    fn validate_key_pair(
        sk: &RsaPrivateComponents<Self>,
        rng: &mut dyn RNG,
        _: sealed::EngineToken,
    ) -> Result<(), SignatureError> {
        validate_key_pair::<Self, 64, 128, 129>(sk, rng)
    }

    fn crt_exp(
        sk: &RsaPrivateComponents<Self>,
        m: &Self::Limbs,
        out: &mut Self::Limbs,
        _: sealed::EngineToken,
    ) -> Condition<u64> {
        rsa_core::crt_exp_checked::<128, 256, 257, 64, 128, 129>(
            sk.p(),
            sk.q(),
            sk.d_p(),
            sk.d_q(),
            sk.q_inv(),
            sk.n(),
            sk.e(),
            m,
            out,
        )
    }
}

pub(crate) mod sealed {
    use super::{RsaSize, SignatureError};
    use crate::keys::RsaPrivateComponents;
    use bouncycastle_core::traits::RNG;
    use bouncycastle_utils::ct::Condition;

    pub trait Sealed {}

    /// What every method of the two engine traits below takes, and only this crate can
    /// make. A supertrait's methods are callable through a bound on the public trait
    /// (`fn f<K: RsaSize>() { K::public_exp(..) }`) whether or not the supertrait can be
    /// named, so it is this argument that keeps them to the crate.
    pub struct EngineToken(());

    impl EngineToken {
        pub(crate) const fn new() -> Self {
            Self(())
        }
    }

    /// The public-key exponentiation at a size's width, `Limbs` being the size's
    /// `RsaSize::Limbs`: what the schemes are built on and no part of the public API, RSAEP
    /// and RSAVP1 being no way to encrypt or to verify. A supertrait of `RsaSize`, as
    /// [`PrivateKeyEngine`] is of `RsaSigningSize`, whose method takes an [`EngineToken`].
    pub trait PublicKeyEngine<Limbs> {
        /// `x^e mod n`, the public-key operation (RSAVP1 / RSAEP's exponentiation), `x < n`,
        /// for the odd `n` of a key.
        fn public_exp(n: &Limbs, e: u64, x: &Limbs, token: EngineToken) -> Limbs;
    }

    /// What a signing size routes of the private key's arithmetic and is no part of the
    /// public API: the checked exponentiation above all, which is RSADP on any key and a way
    /// to sign nothing. A supertrait of `RsaSigningSize` whose methods each take an
    /// [`EngineToken`], so that code outside the crate cannot call them.
    pub trait PrivateKeyEngine: RsaSize {
        /// Whether the CRT components and `e` belong together, RFC 8017 §3.2, for odd `p` and
        /// `q`: `e * dP == 1 (mod (p - 1))`, `e * dQ == 1 (mod (q - 1))` and
        /// `q * qInv == 1 (mod p)`, in that order. Constant time in the components.
        fn crt_congruences(
            p: &Self::HalfLimbs,
            q: &Self::HalfLimbs,
            d_p: &Self::HalfLimbs,
            d_q: &Self::HalfLimbs,
            q_inv: &Self::HalfLimbs,
            e: u64,
            token: EngineToken,
        ) -> [Condition<u64>; 3];
        /// SP 800-56B Rev. 2 §6.4.1.4.3 validation of the key pair `sk` holds;
        /// [`RsaPrivateComponents::validate`] is the way to it.
        fn validate_key_pair(
            sk: &RsaPrivateComponents<Self>,
            rng: &mut dyn RNG,
            token: EngineToken,
        ) -> Result<(), SignatureError>;
        /// `m^d mod n` by the CRT (RSASP1 / RSADP's exponentiation), `m < n`, into `out`, constant
        /// time in the key, with the result checked before it is released: TRUE if `out^e mod n` is
        /// `m` again, as it is for a sound key and a sound computation. Otherwise FALSE, with
        /// `out` zero, and the caller reports a failure.
        fn crt_exp(
            sk: &RsaPrivateComponents<Self>,
            m: &Self::Limbs,
            out: &mut Self::Limbs,
            token: EngineToken,
        ) -> Condition<u64>;
    }
}
