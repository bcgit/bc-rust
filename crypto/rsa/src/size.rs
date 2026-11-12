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
use crate::keygen::keygen_from_rng;
use crate::keys::{RsaPrivateKey, RsaPublicKey, modulus_strength};
use crate::rsa_core;
use crate::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey};
use bouncycastle_core::errors::{KEMError, SignatureError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_ec::montgomery;
use bouncycastle_ec::nat;
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
pub trait RsaSize:
    sealed::Sealed + Copy + Clone + Debug + Default + PartialEq + Eq + 'static
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
    /// `K_LEN + 4`: the public key's encoding, `n || e`.
    const PK_LEN: usize;
    /// `5 * K_LEN / 2`: the private key's encoding, `p || q || dP || dQ || qInv`.
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
    /// `x^e mod n`, the public-key operation (RSAVP1 / RSAEP's exponentiation), `x < n`.
    fn public_exp(n: &Self::Limbs, e: u32, x: &Self::Limbs) -> Self::Limbs;
}

/// A size this crate signs and generates keys at: RSA-2048 and up (SP 800-131A's 112-bit floor).
pub trait RsaSigningSize: RsaSize {
    /// The Miller-Rabin rounds FIPS 186-5 Table B.1 asks of a prime of this size.
    const MR_ROUNDS: NonZeroUsize;
    /// FIPS 186-5 Appendix A.1.3 key generation from `rng`, which must offer the size's
    /// [`STRENGTH`](RsaSize::STRENGTH).
    ///
    /// # Errors
    /// [`SignatureError::RNGError`] if the RNG is weaker than the size or fails to deliver, or
    /// if no prime was found within the candidate budget.
    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicKey<Self>, RsaPrivateKey<Self>), SignatureError>;

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
    /// `m^d mod n` by the CRT (RSASP1 / RSADP's exponentiation), `m < n`, constant time in the
    /// key.
    fn crt_exp(sk: &RsaPrivateKey<Self>, m: &Self::Limbs) -> Self::Limbs;
}

/// Implemented on a signing size marker: the signature key pair, so a caller starts from the
/// size (`RSA2048::generate_signature_key_pair(&mut rng)`). The RNG is an argument, not a
/// default. The KEM pair is [`KemKeyPair`], a different type, as the crate's `# Key separation`
/// asks.
pub trait SignatureKeyPair {
    /// The size's public key.
    type PublicKey;
    /// The size's private key.
    type PrivateKey;

    /// FIPS 186-5 Appendix A.1.3 key pair generation from `rng`.
    ///
    /// # Errors
    /// As [`RsaSigningSize::keygen`].
    fn generate_signature_key_pair(
        rng: &mut dyn RNG,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), SignatureError>;
}

impl<K: RsaSigningSize> SignatureKeyPair for K {
    type PublicKey = RsaPublicKey<K>;
    type PrivateKey = RsaPrivateKey<K>;

    fn generate_signature_key_pair(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicKey<K>, RsaPrivateKey<K>), SignatureError> {
        K::keygen(rng)
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
        crate::rsasve::keygen_from::<K>(K::keygen(rng))
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
    assert!(K::PK_LEN == K::K_LEN + 4, "PK_LEN is n || e");
    assert!(
        <K::PublicKeyEncoded as Array<u8>>::LEN == K::PK_LEN,
        "PublicKeyEncoded is PK_LEN bytes"
    );
    assert!(K::SK_LEN == 5 * K::K_LEN / 2, "SK_LEN is the five CRT components");
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
    const PK_LEN: usize = 132;
    const SK_LEN: usize = 320;
    const STRENGTH: SecurityStrength = modulus_strength(16);

    type Limbs = [u64; 16];
    type HalfLimbs = [u64; 8];
    type Modulus = [u8; 128];
    type HalfBytes = [u8; 64];
    type PublicKeyEncoded = [u8; 132];
    type PrivateKeyEncoded = [u8; 320];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<16, 128>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<16, 128>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }

    fn public_exp(n: &Self::Limbs, e: u32, x: &Self::Limbs) -> Self::Limbs {
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
    const PK_LEN: usize = 196;
    const SK_LEN: usize = 480;
    const STRENGTH: SecurityStrength = modulus_strength(24);

    type Limbs = [u64; 24];
    type HalfLimbs = [u64; 12];
    type Modulus = [u8; 192];
    type HalfBytes = [u8; 96];
    type PublicKeyEncoded = [u8; 196];
    type PrivateKeyEncoded = [u8; 480];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<24, 192>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<24, 192>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }

    fn public_exp(n: &Self::Limbs, e: u32, x: &Self::Limbs) -> Self::Limbs {
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
    const PK_LEN: usize = 260;
    const SK_LEN: usize = 640;
    const STRENGTH: SecurityStrength = modulus_strength(32);

    type Limbs = [u64; 32];
    type HalfLimbs = [u64; 16];
    type Modulus = [u8; 256];
    type HalfBytes = [u8; 128];
    type PublicKeyEncoded = [u8; 260];
    type PrivateKeyEncoded = [u8; 640];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<32, 256>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<32, 256>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }

    fn public_exp(n: &Self::Limbs, e: u32, x: &Self::Limbs) -> Self::Limbs {
        rsa_core::public_exp::<32, 64, 65>(n, e, x)
    }
}

const _: () = check_lengths::<RSA2048>();

impl RsaSigningSize for RSA2048 {
    const MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(5).unwrap();

    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicKey<Self>, RsaPrivateKey<Self>), SignatureError> {
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

    fn crt_exp(sk: &RsaPrivateKey<Self>, m: &Self::Limbs) -> Self::Limbs {
        rsa_core::crt_exp::<32, 64, 65, 16, 32, 33>(
            sk.p(),
            sk.q(),
            sk.d_p(),
            sk.d_q(),
            sk.q_inv(),
            m,
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
    const PK_LEN: usize = 388;
    const SK_LEN: usize = 960;
    const STRENGTH: SecurityStrength = modulus_strength(48);

    type Limbs = [u64; 48];
    type HalfLimbs = [u64; 24];
    type Modulus = [u8; 384];
    type HalfBytes = [u8; 192];
    type PublicKeyEncoded = [u8; 388];
    type PrivateKeyEncoded = [u8; 960];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<48, 384>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<48, 384>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }

    fn public_exp(n: &Self::Limbs, e: u32, x: &Self::Limbs) -> Self::Limbs {
        rsa_core::public_exp::<48, 96, 97>(n, e, x)
    }
}

const _: () = check_lengths::<RSA3072>();

impl RsaSigningSize for RSA3072 {
    const MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(4).unwrap();

    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicKey<Self>, RsaPrivateKey<Self>), SignatureError> {
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

    fn crt_exp(sk: &RsaPrivateKey<Self>, m: &Self::Limbs) -> Self::Limbs {
        rsa_core::crt_exp::<48, 96, 97, 24, 48, 49>(
            sk.p(),
            sk.q(),
            sk.d_p(),
            sk.d_q(),
            sk.q_inv(),
            m,
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
    const PK_LEN: usize = 516;
    const SK_LEN: usize = 1280;
    const STRENGTH: SecurityStrength = modulus_strength(64);

    type Limbs = [u64; 64];
    type HalfLimbs = [u64; 32];
    type Modulus = [u8; 512];
    type HalfBytes = [u8; 256];
    type PublicKeyEncoded = [u8; 516];
    type PrivateKeyEncoded = [u8; 1280];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<64, 512>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<64, 512>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }

    fn public_exp(n: &Self::Limbs, e: u32, x: &Self::Limbs) -> Self::Limbs {
        rsa_core::public_exp::<64, 128, 129>(n, e, x)
    }
}

const _: () = check_lengths::<RSA4096>();

impl RsaSigningSize for RSA4096 {
    const MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(4).unwrap();

    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicKey<Self>, RsaPrivateKey<Self>), SignatureError> {
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

    fn crt_exp(sk: &RsaPrivateKey<Self>, m: &Self::Limbs) -> Self::Limbs {
        rsa_core::crt_exp::<64, 128, 129, 32, 64, 65>(
            sk.p(),
            sk.q(),
            sk.d_p(),
            sk.d_q(),
            sk.q_inv(),
            m,
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
    const PK_LEN: usize = 1028;
    const SK_LEN: usize = 2560;
    const STRENGTH: SecurityStrength = modulus_strength(128);

    type Limbs = [u64; 128];
    type HalfLimbs = [u64; 64];
    type Modulus = [u8; 1024];
    type HalfBytes = [u8; 512];
    type PublicKeyEncoded = [u8; 1028];
    type PrivateKeyEncoded = [u8; 2560];

    fn limbs_from_be_bytes(bytes: &Self::Modulus) -> Self::Limbs {
        limbs_from_be_bytes::<128, 1024>(bytes)
    }

    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::Modulus {
        be_bytes_from_limbs::<128, 1024>(limbs)
    }

    fn is_less(x: &Self::Limbs, y: &Self::Limbs) -> bool {
        nat::sub(x, y).1 == 1
    }

    fn public_exp(n: &Self::Limbs, e: u32, x: &Self::Limbs) -> Self::Limbs {
        rsa_core::public_exp::<128, 256, 257>(n, e, x)
    }
}

const _: () = check_lengths::<RSA8192>();

impl RsaSigningSize for RSA8192 {
    const MR_ROUNDS: NonZeroUsize = NonZeroUsize::new(4).unwrap();

    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaPublicKey<Self>, RsaPrivateKey<Self>), SignatureError> {
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

    fn crt_exp(sk: &RsaPrivateKey<Self>, m: &Self::Limbs) -> Self::Limbs {
        rsa_core::crt_exp::<128, 256, 257, 64, 128, 129>(
            sk.p(),
            sk.q(),
            sk.d_p(),
            sk.d_q(),
            sk.q_inv(),
            m,
        )
    }
}

mod sealed {
    pub trait Sealed {}
}
