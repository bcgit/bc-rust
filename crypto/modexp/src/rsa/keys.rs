//! RSA key material and the signature keys over it. [`RsaPublicComponents`] (RFC 8017 §3.1's
//! `(n, e)`) and [`RsaPrivateComponents`] (§3.2's "second representation", the CRT quintuple
//! `p`, `q`, `dP`, `dQ`, `qInv`, with `e`), generic over the modulus size [`RsaSize`], are what a key is
//! made of and implement no role. [`RsaPublicKey<A>`] and [`RsaPrivateKey<A>`] wrap them for one
//! signature algorithm `A` ([`RsaSignatureAlgorithm`]: `RSASSA_PSS<RSA2048, SHA256>` and so on),
//! so a key signs and verifies under the scheme and hash its type names, `sk.sign(..)` and
//! `pk.verify(..)`, and a PSS key cannot sign PKCS#1 v1.5: SP 800-57 Part 1 Rev. 5's one scheme
//! per key pair, in the type system, as the ECDSA keys carry their curve and hash. The
//! key-establishment keys of [`crate::rsa::rsasve`] wrap the same components under the KEM roles.
//!
//! Components come either from [`crate::rsa::keygen`] (FIPS 186-5 Appendix A.1.3, through
//! [`RsaSigningSize::keygen`] and the generators of [`crate::rsa::size::SignatureKeyPair`]) or from
//! externally supplied key material (CAVP and Wycheproof vectors, a key produced by another
//! implementation) through [`RsaPrivateComponents::from_crt_components`] or the keys' own
//! `from_crt_components`. RFC 8017's first representation, the plain `(n, d)` pair, is not
//! supported: every real RSA private key ships as the CRT form because CRT-based signing (RFC
//! 8017 §5.2.1 step 2.b) is the only signing path this module implements.
//!
//! The keys implement `bouncycastle_core`'s `PublicKey` / `PrivateKey`, the
//! private key only at a [`RsaSigningSize`], with the byte layouts described on the components.
//! The scheme is not encoded, so a key file is decoded under the key type it is for.

use crate::rsa::rsassa::RsaSignatureAlgorithm;
use crate::rsa::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::{KeyDecodingError, KeyMaterialError, SignatureError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KeyPairGenerator, PrivateKey, PublicKey, RNG};
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use bouncycastle_utils::stack_wipe::{WipeStackBelowScaledOnDrop, wipe_stack_below_scaled};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::marker::PhantomData;

/// RSA public key material: RFC 8017 §3.1's `(n, e)`, at the size `K`. Not a key: the keys over
/// it are [`RsaPublicKey`] and [`crate::rsa::rsasve::RsaKEMPublicKey`].
///
/// # Encoding
///
/// The keys' `PublicKey::encode`/`from_bytes` use the raw layout `n || e`: `n` as `K::K_LEN`
/// big-endian bytes (RFC 8017 §4.1's I2OSP), then `e` as 8 big-endian bytes, `K::PK_LEN` in all.
/// Not an RFC 8017 or ASN.1 format -- this module has no DER encoder/decoder -- just a fixed-width
/// layout that round-trips, for `cli/src/rsa_cmd.rs` to read and write public keys as files.
/// Decoding validates `(n, e)` the same way [`Self::new`] does; the scheme is not encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublicComponents<K: RsaSize> {
    n: K::Limbs,
    e: u64,
}

/// Whether the modulus's top bit is set: `n` has exactly the size's bit length, `K::BITS`.
fn has_full_bit_length<K: RsaSize>(n: &K::Limbs) -> bool {
    n.as_ref()[n.as_ref().len() - 1] >> 63 == 1
}

/// What both constructors return for a modulus shorter than its size.
const MODULUS_NOT_FULL_LENGTH: SignatureError =
    SignatureError::DecodingError("RSA modulus must have its top bit set");

/// RFC 8017 §3.1: `e` is odd and at least 3, in the public key and in the private key's copy.
fn check_public_exponent(e: u64) -> Result<(), SignatureError> {
    if e < 3 || e & 1 == 0 {
        return Err(SignatureError::DecodingError(
            "RSA public exponent must be odd and at least 3",
        ));
    }
    Ok(())
}

impl<K: RsaSize> RsaPublicComponents<K> {
    /// Builds a public key from its modulus and exponent. Returns
    /// `Err(`[`SignatureError::DecodingError`]`)` if `n` is even (a product of two odd primes
    /// never is), if `n` is not exactly `K::BITS` bits long (its top bit is clear), or if `e`
    /// is even or below 3 (RFC 8017 §3.1: `e` is odd and at least 3).
    pub fn new(n: &K::Limbs, e: u64) -> Result<Self, SignatureError> {
        if n.as_ref()[0] & 1 == 0 {
            return Err(SignatureError::DecodingError("RSA modulus must be odd"));
        }
        // A size is its modulus's exact bit length. RSASSA-PSS depends on it: RFC 8017 §8.1.1
        // step 1 and §8.1.2 step 3 encode and verify at emBits = modBits - 1, which
        // `emsa_pss` takes as 8 * K_LEN - 1.
        if !has_full_bit_length::<K>(n) {
            return Err(MODULUS_NOT_FULL_LENGTH);
        }
        check_public_exponent(e)?;
        Ok(Self { n: *n, e })
    }

    /// The modulus `n`, as little-endian limbs.
    pub fn n(&self) -> &K::Limbs {
        &self.n
    }

    /// The public exponent `e`.
    pub fn e(&self) -> u64 {
        self.e
    }

    /// A copy of these components as the public key of `A`.
    pub fn key<A: RsaSignatureAlgorithm<Size = K>>(&self) -> RsaPublicKey<A> {
        RsaPublicKey::from_components(self.clone())
    }

    /// These components as the public key of `A`.
    pub fn into_key<A: RsaSignatureAlgorithm<Size = K>>(self) -> RsaPublicKey<A> {
        RsaPublicKey::from_components(self)
    }

    /// The `# Encoding` layout.
    pub(in crate::rsa) fn encode_raw(&self) -> K::PublicKeyEncoded {
        let mut out = K::PublicKeyEncoded::ZEROED;
        out.as_mut()[..K::K_LEN].copy_from_slice(K::be_bytes_from_limbs(&self.n).as_ref());
        out.as_mut()[K::K_LEN..].copy_from_slice(&self.e.to_be_bytes());
        out
    }

    /// The `# Encoding` layout decoded and validated as [`Self::new`] validates.
    pub(in crate::rsa) fn from_bytes_raw(
        bytes: &K::PublicKeyEncoded,
    ) -> Result<Self, SignatureError> {
        let bytes = bytes.as_ref();
        let mut n_bytes = K::Modulus::ZEROED;
        n_bytes.as_mut().copy_from_slice(&bytes[..K::K_LEN]);
        let n = K::limbs_from_be_bytes(&n_bytes);
        let e_bytes: [u8; 8] = bytes[K::K_LEN..].try_into().expect("PK_LEN is K_LEN + 8");
        Self::new(&n, u64::from_be_bytes(e_bytes))
    }
}

/// RSA private key material in RFC 8017 §3.2's CRT ("second representation") form: `p`, `q`,
/// `dP`, `dQ`, `qInv`, at the size `K`, each component a prime-width integer (`K::HalfLimbs`),
/// and the public exponent `e`, which every private-key operation checks its result against
/// (the `rsa` module's `# Security Considerations`).
/// Not a key: the keys over it are [`RsaPrivateKey`] and [`crate::rsa::rsasve::RsaKEMPrivateKey`].
///
/// # Encoding
///
/// The keys' `PrivateKey::encode`/`from_bytes`, at a signing size, use the raw layout
/// `p || q || dP || dQ || qInv || e`: the five CRT components each `K::K_LEN / 2` big-endian
/// bytes, then `e` as 8 big-endian bytes, `K::SK_LEN = 5 * K::K_LEN / 2 + 8` in all. Not an
/// RFC 8017 or ASN.1 format -- see [`RsaPublicComponents`]'s `# Encoding` for why -- just a
/// fixed-width layout that round-trips, for `cli/src/rsa_cmd.rs` to read and write private
/// keys as files.
/// Decoding validates the components the same way [`Self::from_crt_components`] does.
#[derive(Debug, PartialEq, Eq)]
pub struct RsaPrivateComponents<K: RsaSize> {
    p: Secret<K::HalfLimbs>,
    q: Secret<K::HalfLimbs>,
    d_p: Secret<K::HalfLimbs>,
    d_q: Secret<K::HalfLimbs>,
    q_inv: Secret<K::HalfLimbs>,
    /// `p * q`, kept so signing's range check and the public key need no recomputation; public.
    n: K::Limbs,
    /// The public exponent, kept so a private-key operation can check its result; public.
    e: u64,
}

/// What [`wipe_stack_below_scaled`] overwrites after a private key is constructed or decoded: this
/// many `K::Limbs` values and this many words. Measured in x86-64 release builds (rustc 1.88
/// and 1.97), decoding, the deeper of the two, uses at most 6016 bytes at RSA-2048, 9040 at
/// RSA-3072, 11832 at RSA-4096 and 24104 at RSA-8192; these cover 7232, 10688, 14144 and
/// 27968, the difference being room for a compiler that lays the frames out less tightly.
const KEY_STACK_PER_LIMB: usize = 27;
const KEY_STACK_FIXED: usize = 40;

/// The same after a private key is encoded or cloned, which use 1944, 2856, 3752 and 7336
/// bytes at those sizes; these cover 2304, 3328, 4352 and 8448.
const COPY_STACK_PER_LIMB: usize = 8;
const COPY_STACK_FIXED: usize = 32;

// Written out rather than derived, to run in a frame of its own: a copy of five secret
// components passes through return slots that no `Secret` names.
impl<K: RsaSize> Clone for RsaPrivateComponents<K> {
    fn clone(&self) -> Self {
        let _wipe =
            WipeStackBelowScaledOnDrop::<K::Limbs, COPY_STACK_PER_LIMB, COPY_STACK_FIXED>::new();
        self.clone_in_own_frame()
    }
}

impl<K: RsaSize> RsaPrivateComponents<K> {
    /// The copy [`Clone::clone`] makes. Never inlined, so that what it leaves lies below its
    /// caller's frame, where [`wipe_stack_below_scaled`] reaches it.
    #[inline(never)]
    fn clone_in_own_frame(&self) -> Self {
        Self {
            p: self.p.clone(),
            q: self.q.clone(),
            d_p: self.d_p.clone(),
            d_q: self.d_q.clone(),
            q_inv: self.q_inv.clone(),
            n: self.n,
            e: self.e,
        }
    }
}

// The constructors are a signing size's: RSA-1024 and RSA-1536 verify only, so no private key
// value exists at those sizes (the `rsa` module's `# Scope`).
impl<K: RsaSigningSize> RsaPrivateComponents<K> {
    /// Builds a private key from its CRT components and the public exponent of its key pair,
    /// computing `n = p * q`. Returns `Err(`[`SignatureError::DecodingError`]`)` if `p` or `q`
    /// is even, `p == q`, `dP`, `dQ` or `qInv` is not below its prime, `n` is not exactly
    /// `K::BITS` bits long (its top bit is clear), `e` is even or below 3, or the components
    /// and `e` do not belong together: `dP` and `dQ` are not the inverses of `e` modulo `p - 1`
    /// and `q - 1`, or `qInv` is not the inverse of `q` modulo `p` (RFC 8017 §3.2). Primality
    /// is not checked (see the `rsa` module's `# Security Considerations`); [`Self::validate`] does.
    pub fn from_crt_components(
        p: &K::HalfLimbs,
        q: &K::HalfLimbs,
        d_p: &K::HalfLimbs,
        d_q: &K::HalfLimbs,
        q_inv: &K::HalfLimbs,
        e: u64,
    ) -> Result<Self, SignatureError> {
        Self::from_crt_components_as(p, q, d_p, d_q, q_inv, e, |components| components)
    }

    /// [`Self::from_crt_components`] with its result handed to `finish`, which makes of it what
    /// the caller returns: a key type over the components, another error. `finish` runs inside
    /// the frame that is wiped, so a caller that ends with this call stages no copy of the key
    /// in a frame of its own: the key is written once, into the `Result` that caller returns.
    /// What is done with that `Result` afterwards is not covered: taking the key out of it
    /// is a move, as the `rsa` module's Security Considerations say.
    pub(in crate::rsa) fn from_crt_components_as<T, E>(
        p: &K::HalfLimbs,
        q: &K::HalfLimbs,
        d_p: &K::HalfLimbs,
        d_q: &K::HalfLimbs,
        q_inv: &K::HalfLimbs,
        e: u64,
        finish: impl FnOnce(Result<Self, SignatureError>) -> Result<T, E>,
    ) -> Result<T, E> {
        let _wipe =
            WipeStackBelowScaledOnDrop::<K::Limbs, KEY_STACK_PER_LIMB, KEY_STACK_FIXED>::new();
        Self::from_crt_components_in_own_frame(p, q, d_p, d_q, q_inv, e, finish)
    }

    /// The work of [`Self::from_crt_components_as`]. Never inlined, so that the copies of the
    /// components it leaves lie below its caller's frame, where [`wipe_stack_below_scaled`] reaches
    /// them.
    #[inline(never)]
    fn from_crt_components_in_own_frame<T, E>(
        p: &K::HalfLimbs,
        q: &K::HalfLimbs,
        d_p: &K::HalfLimbs,
        d_q: &K::HalfLimbs,
        q_inv: &K::HalfLimbs,
        e: u64,
        finish: impl FnOnce(Result<Self, SignatureError>) -> Result<T, E>,
    ) -> Result<T, E> {
        finish(Self::validated(p, q, d_p, d_q, q_inv, e))
    }

    /// The checks and the key of [`Self::from_crt_components`], for a caller that runs under a
    /// wipe of its own.
    fn validated(
        p: &K::HalfLimbs,
        q: &K::HalfLimbs,
        d_p: &K::HalfLimbs,
        d_q: &K::HalfLimbs,
        q_inv: &K::HalfLimbs,
        e: u64,
    ) -> Result<Self, SignatureError> {
        check_public_exponent(e)?;
        if p.as_ref()[0] & 1 == 0 {
            return Err(SignatureError::DecodingError("p must be odd"));
        }
        if q.as_ref()[0] & 1 == 0 {
            return Err(SignatureError::DecodingError("q must be odd"));
        }
        if p == q {
            return Err(SignatureError::DecodingError("p and q must be distinct"));
        }
        if !K::half_is_less(d_p, p) {
            return Err(SignatureError::DecodingError("dP must be less than p"));
        }
        if !K::half_is_less(d_q, q) {
            return Err(SignatureError::DecodingError("dQ must be less than q"));
        }
        if !K::half_is_less(q_inv, p) {
            return Err(SignatureError::DecodingError("qInv must be less than p"));
        }

        // `p * q` is exact, never reduced, since it is the modulus itself, and must be full
        // length for the reason `RsaPublicComponents::new` gives.
        let n = K::modulus_from_primes(p, q);
        if !has_full_bit_length::<K>(&n) {
            return Err(MODULUS_NOT_FULL_LENGTH);
        }
        // RFC 8017 §3.2: the components and `e` are one key. All three verdicts are computed
        // before any is looked at.
        let [d_p_ok, d_q_ok, q_inv_ok] = K::crt_congruences(
            p,
            q,
            d_p,
            d_q,
            q_inv,
            e,
            crate::rsa::size::sealed::EngineToken::new(),
        );
        if !d_p_ok.to_bool() {
            return Err(SignatureError::DecodingError("dP is not the inverse of e modulo p - 1"));
        }
        if !d_q_ok.to_bool() {
            return Err(SignatureError::DecodingError("dQ is not the inverse of e modulo q - 1"));
        }
        if !q_inv_ok.to_bool() {
            return Err(SignatureError::DecodingError("qInv is not the inverse of q modulo p"));
        }

        let mut key = Self {
            p: Secret::new(),
            q: Secret::new(),
            d_p: Secret::new(),
            d_q: Secret::new(),
            q_inv: Secret::new(),
            n,
            e,
        };
        *key.p = *p;
        *key.q = *q;
        *key.d_p = *d_p;
        *key.d_q = *d_q;
        *key.q_inv = *q_inv;
        Ok(key)
    }
}

impl<K: RsaSigningSize> RsaPrivateComponents<K> {
    /// Validates the key pair these components and their `n` and `e` make, as SP 800-56B Rev. 2
    /// §6.4.1.4.3 (`crt_pkv`) does: beyond what the constructor checked, that `e` is at least
    /// 65,537, that `p` and `q` are each at least `sqrt(2) * 2^(nBits/2 - 1)`, more than
    /// `2^(nBits/2 - 100)` apart and probably prime, and that the private exponent
    /// `d = e^-1 mod LCM(p - 1, q - 1)` is above `2^(nBits/2)`. A key from this module's key
    /// generation passes; this is for a key from elsewhere.
    ///
    /// Primality is the Miller-Rabin test with bases from `rng`, at
    /// [`VALIDATION_MR_ROUNDS`](RsaSigningSize::VALIDATION_MR_ROUNDS) rounds, so that a composite
    /// passes with probability at most `2^-ES(nBits)` however it was chosen. That is the work
    /// of about that many private-key operations: 56 at RSA-2048.
    ///
    /// # Errors
    /// [`SignatureError::DecodingError`], naming the criterion, if the key pair is not valid;
    /// [`SignatureError::RNGError`] if `rng` is weaker than the size's
    /// [`STRENGTH`](RsaSize::STRENGTH) or fails to deliver; [`SignatureError::GenericError`] if
    /// it gave no usable Miller-Rabin base in 128 draws.
    ///
    /// # 🚨 Security Considerations 🚨
    ///
    /// Not constant time in the key, as key generation is not.
    pub fn validate(&self, rng: &mut dyn RNG) -> Result<(), SignatureError> {
        if !self.is_filled() {
            return Err(KeyMaterialError::ActingOnZeroizedKey.into());
        }
        K::validate_key_pair(self, rng, crate::rsa::size::sealed::EngineToken::new())
    }
}

impl<K: RsaSize> RsaPrivateComponents<K> {
    /// The modulus `n = p * q`, as little-endian limbs.
    pub fn n(&self) -> &K::Limbs {
        &self.n
    }

    /// The public exponent `e` of the key pair.
    pub fn e(&self) -> u64 {
        self.e
    }

    /// A copy of these components as the private key of `A`.
    pub fn key<A: RsaSignatureAlgorithm<Size = K>>(&self) -> RsaPrivateKey<A> {
        // The copy is made in the key, not handed to a constructor through this frame.
        RsaPrivateKey { components: self.clone(), _alg: PhantomData }
    }

    /// These components as the private key of `A`.
    pub fn into_key<A: RsaSignatureAlgorithm<Size = K>>(self) -> RsaPrivateKey<A> {
        RsaPrivateKey::from_components(self)
    }

    /// The components a key generated with `keygen_out` starts from: all zero, which is not
    /// a key, and which [`Self::is_filled`] tells apart from one.
    pub(in crate::rsa) fn zeroized() -> Self {
        Self {
            p: Secret::new(),
            q: Secret::new(),
            d_p: Secret::new(),
            d_q: Secret::new(),
            q_inv: Secret::new(),
            n: K::Limbs::ZEROED,
            e: 0,
        }
    }

    /// Whether these are a key's components rather than [`Self::zeroized`]'s: every key has
    /// `e >= 3`, and `e` is public.
    pub(in crate::rsa) fn is_filled(&self) -> bool {
        self.e != 0
    }

    /// Copies `other` into `self` where it sits, for a generator that fills a key the caller
    /// holds rather than returning one.
    pub(in crate::rsa) fn fill_from(&mut self, other: &Self) {
        *self.p = *other.p;
        *self.q = *other.q;
        *self.d_p = *other.d_p;
        *self.d_q = *other.d_q;
        *self.q_inv = *other.q_inv;
        self.n = other.n;
        self.e = other.e;
    }

    pub(in crate::rsa) fn p(&self) -> &K::HalfLimbs {
        &self.p
    }

    pub(in crate::rsa) fn q(&self) -> &K::HalfLimbs {
        &self.q
    }

    pub(in crate::rsa) fn d_p(&self) -> &K::HalfLimbs {
        &self.d_p
    }

    pub(in crate::rsa) fn d_q(&self) -> &K::HalfLimbs {
        &self.d_q
    }

    pub(in crate::rsa) fn q_inv(&self) -> &K::HalfLimbs {
        &self.q_inv
    }
}

impl<K: RsaSigningSize> RsaPrivateComponents<K> {
    /// The `# Encoding` layout.
    pub(in crate::rsa) fn encode_raw(&self) -> K::PrivateKeyEncoded {
        let _wipe =
            WipeStackBelowScaledOnDrop::<K::Limbs, COPY_STACK_PER_LIMB, COPY_STACK_FIXED>::new();
        self.encode_raw_in_own_frame()
    }

    /// The `# Encoding` layout into `out`.
    pub(in crate::rsa) fn encode_raw_out(&self, out: &mut K::PrivateKeyEncoded) {
        self.encode_raw_out_in_own_frame(out);
        wipe_stack_below_scaled::<K::Limbs, COPY_STACK_PER_LIMB, COPY_STACK_FIXED>();
    }

    /// The work of [`Self::encode_raw`]. Never inlined: see
    /// [`Self::from_crt_components_in_own_frame`].
    #[inline(never)]
    fn encode_raw_in_own_frame(&self) -> K::PrivateKeyEncoded {
        self.encoded()
    }

    /// The work of [`Self::encode_raw_out`]. Never inlined: see
    /// [`Self::from_crt_components_in_own_frame`].
    #[inline(never)]
    fn encode_raw_out_in_own_frame(&self, out: &mut K::PrivateKeyEncoded) {
        *out = self.encoded();
    }

    /// The encoding, for a caller that runs under a wipe of its own.
    fn encoded(&self) -> K::PrivateKeyEncoded {
        let half = K::K_LEN / 2;
        let mut out = K::PrivateKeyEncoded::ZEROED;
        for (i, component) in
            [&self.p, &self.q, &self.d_p, &self.d_q, &self.q_inv].into_iter().enumerate()
        {
            out.as_mut()[i * half..(i + 1) * half]
                .copy_from_slice(K::half_be_bytes_from_limbs(component).as_ref());
        }
        out.as_mut()[5 * half..].copy_from_slice(&self.e.to_be_bytes());
        out
    }

    /// The `# Encoding` layout decoded and validated as [`Self::from_crt_components`]
    /// validates. Each component is staged in a `Secret` on the way to its limbs, scrubbed
    /// before returning; the caller's buffer is the one other copy of the encoding.
    ///
    /// The result is handed to `finish`, as [`Self::from_crt_components_as`] hands its own and
    /// for the same reason.
    pub(in crate::rsa) fn from_bytes_raw_as<T, E>(
        bytes: &K::PrivateKeyEncoded,
        finish: impl FnOnce(Result<Self, SignatureError>) -> Result<T, E>,
    ) -> Result<T, E> {
        let _wipe =
            WipeStackBelowScaledOnDrop::<K::Limbs, KEY_STACK_PER_LIMB, KEY_STACK_FIXED>::new();
        Self::from_bytes_raw_in_own_frame(bytes, finish)
    }

    /// The work of [`Self::from_bytes_raw_as`]. Never inlined: see
    /// [`Self::from_crt_components_in_own_frame`].
    #[inline(never)]
    fn from_bytes_raw_in_own_frame<T, E>(
        bytes: &K::PrivateKeyEncoded,
        finish: impl FnOnce(Result<Self, SignatureError>) -> Result<T, E>,
    ) -> Result<T, E> {
        finish(Self::decoded(bytes))
    }

    /// The decoding, for a caller that runs under a wipe of its own.
    fn decoded(bytes: &K::PrivateKeyEncoded) -> Result<Self, SignatureError> {
        let half = K::K_LEN / 2;
        let bytes = bytes.as_ref();
        let mut staged = Secret::<K::HalfBytes>::new();
        let mut components: [Secret<K::HalfLimbs>; 5] = core::array::from_fn(|_| Secret::new());
        for (i, component) in components.iter_mut().enumerate() {
            staged.as_mut().copy_from_slice(&bytes[i * half..(i + 1) * half]);
            **component = K::half_limbs_from_be_bytes(&staged);
        }
        let [p, q, d_p, d_q, q_inv] = &components;
        let e_bytes: [u8; 8] = bytes[5 * half..].try_into().expect("SK_LEN is 5 * K_LEN / 2 + 8");
        Self::validated(p, q, d_p, d_q, q_inv, u64::from_be_bytes(e_bytes))
    }
}

/// An RSA public key for the signature algorithm `A`: [`RsaPublicComponents`] under
/// [`VerifyingKey`](bouncycastle_core::signature_key::VerifyingKey) for `A`, so `pk.verify(..)`
/// is `A`'s verification. The same bytes decoded under another `A` are another key.
pub struct RsaPublicKey<A: RsaSignatureAlgorithm> {
    components: RsaPublicComponents<A::Size>,
    _alg: PhantomData<A>,
}

impl<A: RsaSignatureAlgorithm> RsaPublicKey<A> {
    /// A key from its modulus and exponent, validated as [`RsaPublicComponents::new`] validates.
    ///
    /// # Errors
    /// As [`RsaPublicComponents::new`].
    pub fn new(n: &<A::Size as RsaSize>::Limbs, e: u64) -> Result<Self, SignatureError> {
        Ok(Self::from_components(RsaPublicComponents::new(n, e)?))
    }

    /// A key over validated components.
    pub fn from_components(components: RsaPublicComponents<A::Size>) -> Self {
        Self { components, _alg: PhantomData }
    }

    /// The components.
    pub fn components(&self) -> &RsaPublicComponents<A::Size> {
        &self.components
    }

    /// The modulus `n`, as little-endian limbs.
    pub fn n(&self) -> &<A::Size as RsaSize>::Limbs {
        self.components.n()
    }

    /// The public exponent `e`.
    pub fn e(&self) -> u64 {
        self.components.e()
    }
}

// Written out rather than derived: a derive would bound `A`, which is a marker.
impl<A: RsaSignatureAlgorithm> Clone for RsaPublicKey<A> {
    fn clone(&self) -> Self {
        Self { components: self.components.clone(), _alg: PhantomData }
    }
}

impl<A: RsaSignatureAlgorithm> Debug for RsaPublicKey<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("algorithm", &A::ALG_NAME)
            .field("components", &self.components)
            .finish()
    }
}

impl<A: RsaSignatureAlgorithm> PartialEq for RsaPublicKey<A> {
    fn eq(&self, other: &Self) -> bool {
        self.components == other.components
    }
}

impl<A: RsaSignatureAlgorithm> Eq for RsaPublicKey<A> {}

impl<A, const PK_LEN: usize> PublicKey<PK_LEN> for RsaPublicKey<A>
where
    A: RsaSignatureAlgorithm,
    A::Size: RsaSize<PublicKeyEncoded = [u8; PK_LEN]>,
{
    fn encode(&self) -> [u8; PK_LEN] {
        self.components.encode_raw()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.components.encode_raw();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let bytes: &[u8; PK_LEN] = bytes.try_into().map_err(|_| {
            KeyDecodingError("an RSA public key is the modulus length plus eight bytes")
        })?;
        Ok(Self::from_components(
            RsaPublicComponents::from_bytes_raw(bytes).map_err(decoding_error)?,
        ))
    }
}

/// `RsaPublicKey<RSASSA-PSS-SHA256, RSA-2048> { n: <hex>, e: <hex> }`, `n` as one big-endian hex
/// string (the limbs are stored least-significant first, so they are printed in reverse).
/// Required by `PublicKey`'s `Display` supertrait; public data only, so nothing is
/// redacted.
impl<A: RsaSignatureAlgorithm> Display for RsaPublicKey<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "RsaPublicKey<{}, {}> {{ n: ", A::ALG_NAME, A::Size::NAME)?;
        for limb in self.components.n().as_ref().iter().rev() {
            write!(f, "{limb:016x}")?;
        }
        write!(f, ", e: {:x} }}", self.components.e())
    }
}

/// An RSA private key for the signature algorithm `A`: [`RsaPrivateComponents`] under
/// [`SigningKey`](bouncycastle_core::signature_key::SigningKey) or
/// [`DeterministicSigningKey`](bouncycastle_core::signature_key::DeterministicSigningKey) for
/// `A`, whichever `A`'s scheme is, so `sk.sign(..)` or `sk.sign_deterministic(..)` is `A`'s
/// signing and no other scheme's. Exists only at a [`RsaSigningSize`].
pub struct RsaPrivateKey<A: RsaSignatureAlgorithm> {
    components: RsaPrivateComponents<A::Size>,
    _alg: PhantomData<A>,
}

impl<A: RsaSignatureAlgorithm> RsaPrivateKey<A>
where
    A::Size: RsaSigningSize,
{
    /// A key from its CRT components and public exponent, validated as
    /// [`RsaPrivateComponents::from_crt_components`] validates.
    ///
    /// # Errors
    /// As [`RsaPrivateComponents::from_crt_components`].
    pub fn from_crt_components(
        p: &<A::Size as RsaSize>::HalfLimbs,
        q: &<A::Size as RsaSize>::HalfLimbs,
        d_p: &<A::Size as RsaSize>::HalfLimbs,
        d_q: &<A::Size as RsaSize>::HalfLimbs,
        q_inv: &<A::Size as RsaSize>::HalfLimbs,
        e: u64,
    ) -> Result<Self, SignatureError> {
        RsaPrivateComponents::from_crt_components_as(p, q, d_p, d_q, q_inv, e, |components| {
            components.map(Self::from_components)
        })
    }
}

impl<A: RsaSignatureAlgorithm> RsaPrivateKey<A> {
    /// The key [`SignatureKeyPair::generate_signature_key_out`](crate::rsa::size::SignatureKeyPair::generate_signature_key_out)
    /// writes into: not a key until it has, so it signs nothing and has no public key
    /// ([`KeyMaterialError::ActingOnZeroizedKey`]), and it encodes as zeros.
    pub fn zeroized() -> Self {
        Self { components: RsaPrivateComponents::zeroized(), _alg: PhantomData }
    }

    /// The public key of the key pair, `(n, e)` under the same algorithm.
    ///
    /// # Errors
    /// [`KeyMaterialError::ActingOnZeroizedKey`] for a key that was never filled.
    pub fn pub_key(&self) -> Result<RsaPublicKey<A>, SignatureError> {
        if !self.components.is_filled() {
            return Err(KeyMaterialError::ActingOnZeroizedKey.into());
        }
        Ok(RsaPublicKey::from_components(RsaPublicComponents {
            n: self.components.n,
            e: self.components.e,
        }))
    }

    /// [`KeyMaterialError::ActingOnZeroizedKey`] for a key that was never filled.
    pub(in crate::rsa) fn check_filled(&self) -> Result<(), SignatureError> {
        if self.components.is_filled() {
            Ok(())
        } else {
            Err(KeyMaterialError::ActingOnZeroizedKey.into())
        }
    }

    /// The components, to fill in place.
    pub(in crate::rsa) fn components_mut(&mut self) -> &mut RsaPrivateComponents<A::Size> {
        &mut self.components
    }

    /// A key over validated components.
    pub fn from_components(components: RsaPrivateComponents<A::Size>) -> Self {
        Self { components, _alg: PhantomData }
    }

    /// The components.
    pub fn components(&self) -> &RsaPrivateComponents<A::Size> {
        &self.components
    }

    /// The modulus `n = p * q`, as little-endian limbs.
    pub fn n(&self) -> &<A::Size as RsaSize>::Limbs {
        self.components.n()
    }

    /// The public exponent `e` of the key pair.
    pub fn e(&self) -> u64 {
        self.components.e()
    }
}

/// Generation is [`SignatureKeyPair::generate_signature_key_out`](crate::rsa::size::SignatureKeyPair::generate_signature_key_out)
/// at the algorithm's size.
impl<A: RsaSignatureAlgorithm> KeyPairGenerator for RsaPrivateKey<A>
where
    A::Size: RsaSigningSize,
{
    type PublicKey = RsaPublicKey<A>;
    type Error = SignatureError;

    fn zeroized() -> Self {
        Self::zeroized()
    }

    fn generate_out(rng: &mut dyn RNG, sk: &mut Self) -> Result<(), SignatureError> {
        <A::Size as crate::rsa::size::SignatureKeyPair>::generate_signature_key_out(rng, sk)
    }

    fn pub_key(&self) -> Result<RsaPublicKey<A>, SignatureError> {
        self.pub_key()
    }
}

impl<A: RsaSignatureAlgorithm> Clone for RsaPrivateKey<A> {
    fn clone(&self) -> Self {
        Self { components: self.components.clone(), _alg: PhantomData }
    }
}

impl<A: RsaSignatureAlgorithm> Debug for RsaPrivateKey<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("algorithm", &A::ALG_NAME)
            .field("components", &self.components)
            .finish()
    }
}

impl<A: RsaSignatureAlgorithm> PartialEq for RsaPrivateKey<A> {
    fn eq(&self, other: &Self) -> bool {
        self.components == other.components
    }
}

impl<A: RsaSignatureAlgorithm> Eq for RsaPrivateKey<A> {}

impl<A, const SK_LEN: usize> PrivateKey<SK_LEN> for RsaPrivateKey<A>
where
    A: RsaSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<PrivateKeyEncoded = [u8; SK_LEN]>,
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.components.encode_raw()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        self.components.encode_raw_out(out);
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let bytes: &[u8; SK_LEN] = bytes.try_into().map_err(|_| {
            KeyDecodingError(
                "an RSA private key is five components of half the modulus length and eight bytes",
            )
        })?;
        RsaPrivateComponents::from_bytes_raw_as(bytes, |components| {
            components.map(Self::from_components).map_err(decoding_error)
        })
    }
}

/// The security strength SP 800-57 Part 1 Rev. 5 Table 2 assigns an RSA modulus of `limbs`
/// 64-bit limbs: 112 bits at 2048, 128 at 3072 and 4096, 192 at 7680 and above, and none below
/// 2048 (the legacy sizes this module verifies with but will not sign with).
pub const fn modulus_strength(limbs: usize) -> SecurityStrength {
    let bits = limbs * 64;
    if bits >= 7680 {
        SecurityStrength::_192bit
    } else if bits >= 3072 {
        SecurityStrength::_128bit
    } else if bits >= 2048 {
        SecurityStrength::_112bit
    } else {
        SecurityStrength::None
    }
}

/// A key layer failure as the error a key's `from_bytes` returns, keeping the message of a
/// decoding failure, which is the only kind the raw decoders produce.
pub(in crate::rsa) fn decoding_error(e: SignatureError) -> KeyDecodingError {
    match e {
        SignatureError::DecodingError(msg) => KeyDecodingError(msg),
        _ => KeyDecodingError("invalid RSA key encoding"),
    }
}

// A private-key operation checks its result (`rsa_core::crt_exp_checked`). The constructor
// above refuses a key whose `dP`, `dQ`, `qInv` or `e` is not its own, so a test of the check on
// one damaged component needs a key built past the constructor: the QUALITY_AND_STYLE.md
// exception for behaviour that cannot be reached through the public API. (A key with a
// composite prime does pass the constructor: `tests/rsa_keys_tests.rs` runs the check on one.)
#[cfg(test)]
mod tests {
    use super::*;

    impl<K: RsaSigningSize> RsaPrivateComponents<K> {
        /// The components as a key, with `n = p * q` and nothing checked.
        pub(in crate::rsa) fn unvalidated(
            p: &K::HalfLimbs,
            q: &K::HalfLimbs,
            d_p: &K::HalfLimbs,
            d_q: &K::HalfLimbs,
            q_inv: &K::HalfLimbs,
            e: u64,
        ) -> Self {
            let mut key = Self {
                p: Secret::new(),
                q: Secret::new(),
                d_p: Secret::new(),
                d_q: Secret::new(),
                q_inv: Secret::new(),
                n: K::modulus_from_primes(p, q),
                e,
            };
            *key.p = *p;
            *key.q = *q;
            *key.d_p = *d_p;
            *key.d_q = *d_q;
            *key.q_inv = *q_inv;
            key
        }
    }
}
