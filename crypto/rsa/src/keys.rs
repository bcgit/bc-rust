//! RSA key types: [`RsaPublicKey`] (RFC 8017 §3.1's `(n, e)`) and [`RsaPrivateKey`] (§3.2's
//! "second representation", the CRT quintuple `p`, `q`, `dP`, `dQ`, `qInv`), generic over the
//! modulus size [`RsaSize`].
//!
//! Keys come either from [`crate::keygen`] (FIPS 186-5 Appendix A.1.3, through
//! [`RsaSigningSize::keygen`]) or from externally supplied
//! key material (loaded from CAVP/wycheproof test vectors, or a key produced by another
//! implementation) through [`RsaPrivateKey::from_crt_components`]. RFC 8017's first
//! representation, the plain `(n, d)` pair, is not supported -- every real RSA private key ships
//! as the CRT form because CRT-based signing (RFC 8017 §5.2.1 step 2.b) is the only signing path
//! this crate implements.
//!
//! The key types implement `bouncycastle_core`'s `SignaturePublicKey` / `SignaturePrivateKey`,
//! the private key only at a [`RsaSigningSize`], with the byte
//! layouts described on each type below.

use crate::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::fmt;
use core::fmt::{Display, Formatter};

/// An RSA public key: RFC 8017 §3.1's `(n, e)`, at the size `K`.
///
/// # Encoding
///
/// `SignaturePublicKey::encode`/`from_bytes` use the raw layout `n || e`: `n` as `K::K_LEN`
/// big-endian bytes (RFC 8017 §4.1's I2OSP), then `e` as 4 big-endian bytes, `K::PK_LEN` in all.
/// Not an RFC 8017 or ASN.1 format -- this crate has no DER encoder/decoder -- just a fixed-width
/// layout that round-trips, for `cli/src/rsa_cmd.rs` to read and write public keys as files.
/// Decoding validates `(n, e)` the same way [`Self::new`] does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublicKey<K: RsaSize> {
    n: K::Limbs,
    e: u32,
}

impl<K: RsaSize> RsaPublicKey<K> {
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

impl<K, const PK_LEN: usize> SignaturePublicKey<PK_LEN> for RsaPublicKey<K>
where
    K: RsaSize<PublicKeyEncoded = [u8; PK_LEN]>,
{
    fn encode(&self) -> [u8; PK_LEN] {
        self.encode_raw()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.encode_raw();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; PK_LEN] = bytes.try_into().map_err(|_| {
            SignatureError::DecodingError("an RSA public key is the modulus length plus four bytes")
        })?;
        Self::from_bytes_raw(bytes)
    }
}

/// `RsaPublicKey<RSA-2048> { n: <hex>, e: <hex> }`, `n` as one big-endian hex string (the limbs
/// are stored least-significant first, so they are printed in reverse). Required by
/// `SignaturePublicKey`'s `Display` supertrait; public data only, so nothing is redacted.
impl<K: RsaSize> Display for RsaPublicKey<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "RsaPublicKey<{}> {{ n: ", K::NAME)?;
        for limb in self.n.as_ref().iter().rev() {
            write!(f, "{limb:016x}")?;
        }
        write!(f, ", e: {:x} }}", self.e)
    }
}

/// An RSA private key in RFC 8017 §3.2's CRT ("second representation") form: `p`, `q`, `dP`,
/// `dQ`, `qInv`, at the size `K`, each component a prime-width integer (`K::HalfLimbs`).
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
/// `SignaturePrivateKey::encode`/`from_bytes`, at a signing size, use the raw layout
/// `p || q || dP || dQ || qInv`, each `K::K_LEN / 2` big-endian bytes, `K::SK_LEN` in all. Not an
/// RFC 8017 or ASN.1 format -- see [`RsaPublicKey`]'s `# Encoding` for why -- just a fixed-width
/// layout that round-trips, for `cli/src/rsa_cmd.rs` to read and write private keys as files.
/// Decoding validates the five components the same way [`Self::from_crt_components`] does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPrivateKey<K: RsaSize> {
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
impl<K: RsaSigningSize> RsaPrivateKey<K> {
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

impl<K: RsaSize> RsaPrivateKey<K> {
    /// The modulus `n = p * q`, as little-endian limbs.
    pub fn n(&self) -> &K::Limbs {
        &self.n
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

impl<K: RsaSigningSize> RsaPrivateKey<K> {
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

impl<K, const SK_LEN: usize> SignaturePrivateKey<SK_LEN> for RsaPrivateKey<K>
where
    K: RsaSigningSize + RsaSize<PrivateKeyEncoded = [u8; SK_LEN]>,
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.encode_raw()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        *out = self.encode_raw();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; SK_LEN] = bytes.try_into().map_err(|_| {
            SignatureError::DecodingError(
                "an RSA private key is five components of half the modulus length",
            )
        })?;
        Self::from_bytes_raw(bytes)
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
