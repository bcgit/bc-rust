//! RSA key material and the signature keys over it. [`RsaPublicComponents`] (RFC 8017 §3.1's
//! `(n, e)`) and [`RsaPrivateComponents`] (§3.2's "second representation", the CRT quintuple
//! `p`, `q`, `dP`, `dQ`, `qInv`), generic over the modulus size [`RsaSize`], are what a key is
//! made of and implement no role. [`RsaPublicKey<A>`] and [`RsaPrivateKey<A>`] wrap them for one
//! signature algorithm `A` ([`RsaSignatureAlgorithm`]: `RSASSA_PSS<RSA2048, SHA256>` and so on),
//! so a key signs and verifies under the scheme and hash its type names, `sk.sign(..)` and
//! `pk.verify(..)`, and a PSS key cannot sign PKCS#1 v1.5: SP 800-57 Part 1 Rev. 5's one scheme
//! per key pair, in the type system, as the ECDSA keys carry their curve and hash. The
//! key-establishment keys of [`crate::rsasve`] wrap the same components under the KEM roles.
//!
//! Components come either from [`crate::keygen`] (FIPS 186-5 Appendix A.1.3, through
//! [`RsaSigningSize::keygen`] and the generators of [`crate::size::SignatureKeyPair`]) or from
//! externally supplied key material (CAVP and Wycheproof vectors, a key produced by another
//! implementation) through [`RsaPrivateComponents::from_crt_components`] or the keys' own
//! `from_crt_components`. RFC 8017's first representation, the plain `(n, d)` pair, is not
//! supported: every real RSA private key ships as the CRT form because CRT-based signing (RFC
//! 8017 §5.2.1 step 2.b) is the only signing path this crate implements.
//!
//! The keys implement `bouncycastle_core`'s `SignaturePublicKey` / `SignaturePrivateKey`, the
//! private key only at a [`RsaSigningSize`], with the byte layouts described on the components.
//! The scheme is not encoded, so a key file is decoded under the key type it is for.

use crate::rsassa::RsaSignatureAlgorithm;
use crate::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::marker::PhantomData;

/// RSA public key material: RFC 8017 §3.1's `(n, e)`, at the size `K`. Not a key: the keys over
/// it are [`RsaPublicKey`] and [`crate::rsasve::RsaKEMPublicKey`].
///
/// # Encoding
///
/// The keys' `SignaturePublicKey::encode`/`from_bytes` use the raw layout `n || e`: `n` as `K::K_LEN`
/// big-endian bytes (RFC 8017 §4.1's I2OSP), then `e` as 4 big-endian bytes, `K::PK_LEN` in all.
/// Not an RFC 8017 or ASN.1 format -- this crate has no DER encoder/decoder -- just a fixed-width
/// layout that round-trips, for `cli/src/rsa_cmd.rs` to read and write public keys as files.
/// Decoding validates `(n, e)` the same way [`Self::new`] does; the scheme is not encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublicComponents<K: RsaSize> {
    n: K::Limbs,
    e: u32,
}

impl<K: RsaSize> RsaPublicComponents<K> {
    /// Builds a public key from its modulus and exponent. Returns
    /// `Err(`[`SignatureError::DecodingError`]`)` if `n` is even (a product of two odd primes
    /// never is) or `e` is even or below 3 (RFC 8017 §3.1: `e` is odd and at least 3).
    pub fn new(n: &K::Limbs, e: u32) -> Result<Self, SignatureError> {
        if n.as_ref()[0] & 1 == 0 {
            return Err(SignatureError::DecodingError("RSA modulus must be odd"));
        }
        if e < 3 || e & 1 == 0 {
            return Err(SignatureError::DecodingError(
                "RSA public exponent must be odd and at least 3",
            ));
        }
        Ok(Self { n: *n, e })
    }

    /// The modulus `n`, as little-endian limbs.
    pub fn n(&self) -> &K::Limbs {
        &self.n
    }

    /// The public exponent `e`.
    pub fn e(&self) -> u32 {
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
    pub(crate) fn encode_raw(&self) -> K::PublicKeyEncoded {
        let mut out = K::PublicKeyEncoded::ZEROED;
        out.as_mut()[..K::K_LEN].copy_from_slice(K::be_bytes_from_limbs(&self.n).as_ref());
        out.as_mut()[K::K_LEN..].copy_from_slice(&self.e.to_be_bytes());
        out
    }

    /// The `# Encoding` layout decoded and validated as [`Self::new`] validates.
    pub(crate) fn from_bytes_raw(bytes: &K::PublicKeyEncoded) -> Result<Self, SignatureError> {
        let bytes = bytes.as_ref();
        let mut n_bytes = K::Modulus::ZEROED;
        n_bytes.as_mut().copy_from_slice(&bytes[..K::K_LEN]);
        let n = K::limbs_from_be_bytes(&n_bytes);
        let e_bytes: [u8; 4] = bytes[K::K_LEN..].try_into().expect("PK_LEN is K_LEN + 4");
        Self::new(&n, u32::from_be_bytes(e_bytes))
    }
}

/// RSA private key material in RFC 8017 §3.2's CRT ("second representation") form: `p`, `q`,
/// `dP`, `dQ`, `qInv`, at the size `K`, each component a prime-width integer (`K::HalfLimbs`).
/// Not a key: the keys over it are [`RsaPrivateKey`] and [`crate::rsasve::RsaKEMPrivateKey`].
///
/// `p` and `q` need not be the same bit length: RFC 8017 §3.2 requires only that both are prime
/// and `p * q = n`, nothing about their relative magnitude. An earlier version of this type
/// required equal bit length anyway, so its CRT recombination could reduce one residue mod the
/// other prime with a single conditional subtraction (valid only when the smaller prime's residue
/// is `< 2 *` the larger prime, which equal bit length guarantees but does not itself require).
/// [`crate::modexp::reduce_wide`]'s general bit-serial reduction handles any magnitude
/// relationship instead, at the same asymptotic cost this crate already pays to reduce the
/// `n`-width message down to each prime's width, so the extra restriction bought nothing and is
/// not reimposed here.
///
/// # Encoding
///
/// The keys' `SignaturePrivateKey::encode`/`from_bytes`, at a signing size, use the raw layout
/// `p || q || dP || dQ || qInv`, each `K::K_LEN / 2` big-endian bytes, `K::SK_LEN` in all. Not an
/// RFC 8017 or ASN.1 format -- see [`RsaPublicKey`]'s `# Encoding` for why -- just a fixed-width
/// layout that round-trips, for `cli/src/rsa_cmd.rs` to read and write private keys as files.
/// Decoding validates the five components the same way [`Self::from_crt_components`] does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPrivateComponents<K: RsaSize> {
    p: Secret<K::HalfLimbs>,
    q: Secret<K::HalfLimbs>,
    d_p: Secret<K::HalfLimbs>,
    d_q: Secret<K::HalfLimbs>,
    q_inv: Secret<K::HalfLimbs>,
    /// `p * q`, kept so signing's range check and the public key need no recomputation; public.
    n: K::Limbs,
}

// The constructors are a signing size's: RSA-1024 and RSA-1536 verify only, so no private key
// value exists at those sizes (the crate's `# Scope`).
impl<K: RsaSigningSize> RsaPrivateComponents<K> {
    /// Builds a private key from its CRT components, computing `n = p * q`. Returns
    /// `Err(`[`SignatureError::DecodingError`]`)` if `p` or `q` is even, `p == q`, or `dP`,
    /// `dQ` or `qInv` is not below its prime. Primality is not checked (see the crate's
    /// `# Security Considerations`).
    pub fn from_crt_components(
        p: &K::HalfLimbs,
        q: &K::HalfLimbs,
        d_p: &K::HalfLimbs,
        d_q: &K::HalfLimbs,
        q_inv: &K::HalfLimbs,
    ) -> Result<Self, SignatureError> {
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

        // `p * q` is exact, never reduced, since it is the modulus itself.
        let n = K::modulus_from_primes(p, q);

        let mut key = Self {
            p: Secret::new(),
            q: Secret::new(),
            d_p: Secret::new(),
            d_q: Secret::new(),
            q_inv: Secret::new(),
            n,
        };
        *key.p = *p;
        *key.q = *q;
        *key.d_p = *d_p;
        *key.d_q = *d_q;
        *key.q_inv = *q_inv;
        Ok(key)
    }
}

impl<K: RsaSize> RsaPrivateComponents<K> {
    /// The modulus `n = p * q`, as little-endian limbs.
    pub fn n(&self) -> &K::Limbs {
        &self.n
    }

    /// A copy of these components as the private key of `A`.
    pub fn key<A: RsaSignatureAlgorithm<Size = K>>(&self) -> RsaPrivateKey<A> {
        RsaPrivateKey::from_components(self.clone())
    }

    /// These components as the private key of `A`.
    pub fn into_key<A: RsaSignatureAlgorithm<Size = K>>(self) -> RsaPrivateKey<A> {
        RsaPrivateKey::from_components(self)
    }

    pub(crate) fn p(&self) -> &K::HalfLimbs {
        &self.p
    }

    pub(crate) fn q(&self) -> &K::HalfLimbs {
        &self.q
    }

    pub(crate) fn d_p(&self) -> &K::HalfLimbs {
        &self.d_p
    }

    pub(crate) fn d_q(&self) -> &K::HalfLimbs {
        &self.d_q
    }

    pub(crate) fn q_inv(&self) -> &K::HalfLimbs {
        &self.q_inv
    }
}

impl<K: RsaSigningSize> RsaPrivateComponents<K> {
    /// The `# Encoding` layout.
    pub(crate) fn encode_raw(&self) -> K::PrivateKeyEncoded {
        let half = K::K_LEN / 2;
        let mut out = K::PrivateKeyEncoded::ZEROED;
        for (i, component) in
            [&self.p, &self.q, &self.d_p, &self.d_q, &self.q_inv].into_iter().enumerate()
        {
            out.as_mut()[i * half..(i + 1) * half]
                .copy_from_slice(K::half_be_bytes_from_limbs(component).as_ref());
        }
        out
    }

    /// The `# Encoding` layout decoded and validated as [`Self::from_crt_components`]
    /// validates. Each component is staged in a `Secret` on the way to its limbs, scrubbed
    /// before returning; the caller's buffer is the one other copy of the encoding.
    pub(crate) fn from_bytes_raw(bytes: &K::PrivateKeyEncoded) -> Result<Self, SignatureError> {
        let half = K::K_LEN / 2;
        let bytes = bytes.as_ref();
        let mut staged = Secret::<K::HalfBytes>::new();
        let mut components: [Secret<K::HalfLimbs>; 5] = core::array::from_fn(|_| Secret::new());
        for (i, component) in components.iter_mut().enumerate() {
            staged.as_mut().copy_from_slice(&bytes[i * half..(i + 1) * half]);
            **component = K::half_limbs_from_be_bytes(&staged);
        }
        let [p, q, d_p, d_q, q_inv] = &components;
        Self::from_crt_components(p, q, d_p, d_q, q_inv)
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
    pub fn new(n: &<A::Size as RsaSize>::Limbs, e: u32) -> Result<Self, SignatureError> {
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
    pub fn e(&self) -> u32 {
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

impl<A, const PK_LEN: usize> SignaturePublicKey<PK_LEN> for RsaPublicKey<A>
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

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; PK_LEN] = bytes.try_into().map_err(|_| {
            SignatureError::DecodingError("an RSA public key is the modulus length plus four bytes")
        })?;
        Ok(Self::from_components(RsaPublicComponents::from_bytes_raw(bytes)?))
    }
}

/// `RsaPublicKey<RSASSA-PSS-SHA256, RSA-2048> { n: <hex>, e: <hex> }`, `n` as one big-endian hex
/// string (the limbs are stored least-significant first, so they are printed in reverse).
/// Required by `SignaturePublicKey`'s `Display` supertrait; public data only, so nothing is
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
    /// A key from its CRT components, validated as
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
    ) -> Result<Self, SignatureError> {
        Ok(Self::from_components(RsaPrivateComponents::from_crt_components(p, q, d_p, d_q, q_inv)?))
    }
}

impl<A: RsaSignatureAlgorithm> RsaPrivateKey<A> {
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

impl<A, const SK_LEN: usize> SignaturePrivateKey<SK_LEN> for RsaPrivateKey<A>
where
    A: RsaSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<PrivateKeyEncoded = [u8; SK_LEN]>,
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.components.encode_raw()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        *out = self.components.encode_raw();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; SK_LEN] = bytes.try_into().map_err(|_| {
            SignatureError::DecodingError(
                "an RSA private key is five components of half the modulus length",
            )
        })?;
        Ok(Self::from_components(RsaPrivateComponents::from_bytes_raw(bytes)?))
    }
}

/// The security strength SP 800-57 Part 1 Rev. 5 Table 2 assigns an RSA modulus of `limbs`
/// 64-bit limbs: 112 bits at 2048, 128 at 3072 and 4096, 192 at 7680 and above, and none below
/// 2048 (the legacy sizes this crate verifies with but will not sign with).
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
