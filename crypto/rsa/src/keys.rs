//! RSA key types: [`RsaPublicKey`] (RFC 8017 §3.1's `(n, e)`) and [`RsaPrivateKey`] (§3.2's
//! "second representation", the CRT quintuple `p`, `q`, `dP`, `dQ`, `qInv`), generic over the
//! modulus's limb count `L` and each prime's limb count `HALF`.
//!
//! This crate does not generate keys: callers construct these from externally supplied key
//! material (e.g. loaded from CAVP/wycheproof test vectors, or a key produced by another
//! implementation), not from primes generated here. RFC 8017's first representation, the plain
//! `(n, d)` pair, is not supported -- every real RSA private key ships as the CRT form because
//! CRT-based signing (RFC 8017 §5.2.1 step 2.b) is the only signing path this crate implements.
//!
//! Each concrete modulus size's aliases of these types (`crate::rsa_2048::RSA2048PrivateKey` and
//! siblings) implement `bouncycastle_core`'s `SignaturePrivateKey`/`SignaturePublicKey` traits,
//! in that size's module, with the byte layouts described on each type below; the generic types
//! here only carry the layout's implementation (`encode_raw`/`from_bytes_raw`, crate-private),
//! since the traits' `SK_LEN`/`PK_LEN` are fixed per size and stable Rust cannot derive them from
//! `L`.

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_ec::montgomery;
use bouncycastle_ec::nat;
use bouncycastle_utils::secret::Secret;
use core::fmt;
use core::fmt::{Display, Formatter};

/// An RSA public key: RFC 8017 §3.1's `(n, e)`.
///
/// # Encoding
///
/// `SignaturePublicKey::encode`/`from_bytes` (implemented per size, e.g. for
/// `crate::rsa_2048::RSA2048PublicKey`) use the raw layout `n || e`: `n` as `8 * L` big-endian
/// bytes (RFC 8017 §4.1's I2OSP), then `e` as 4 big-endian bytes, `PK_LEN = 8 * L + 4` in all.
/// Not an RFC 8017 or ASN.1 format -- this crate has no DER encoder/decoder -- just a fixed-width
/// layout that round-trips, for `cli/src/rsa_cmd.rs` to read and write public keys as files.
/// Decoding validates `(n, e)` the same way [`Self::new`] does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublicKey<const L: usize> {
    n: [u64; L],
    e: u32,
}

impl<const L: usize> RsaPublicKey<L> {
    /// Builds a public key from its modulus and exponent. Returns
    /// `Err(`[`SignatureError::DecodingError`]`)` if `n` is even, or if `e` is even or less than 3
    /// (RFC 8017 §3.1: "the RSA public exponent e is an integer between 3 and n - 1"; the upper
    /// bound is not checked here -- it needs a full multi-limb comparison against `n` for a
    /// boundary no key from a real implementation will ever hit). There is no separate all-zero
    /// check on `n`: a zero value's low limb is `0`, which the oddness check already rejects.
    pub fn new(n: &[u64; L], e: u32) -> Result<Self, SignatureError> {
        if n[0] & 1 == 0 {
            return Err(SignatureError::DecodingError("RSA modulus must be odd"));
        }
        if e < 3 || e & 1 == 0 {
            return Err(SignatureError::DecodingError(
                "RSA public exponent must be odd and at least 3",
            ));
        }
        Ok(Self { n: *n, e })
    }

    /// The modulus `n`.
    pub fn n(&self) -> &[u64; L] {
        &self.n
    }

    /// The public exponent `e`.
    pub fn e(&self) -> u32 {
        self.e
    }

    /// The `# Encoding` layout (see the type's docs), `n || e`, with `N_BYTES = 8 * L` and
    /// `PK_LEN = N_BYTES + 4` supplied by the per-size `SignaturePublicKey` impl that wraps this.
    pub(crate) fn encode_raw<const N_BYTES: usize, const PK_LEN: usize>(&self) -> [u8; PK_LEN] {
        debug_assert_eq!(N_BYTES, 8 * L, "RsaPublicKey::encode_raw needs N_BYTES == 8 * L");
        debug_assert_eq!(
            PK_LEN,
            N_BYTES + 4,
            "RsaPublicKey::encode_raw needs PK_LEN == N_BYTES + 4"
        );
        let mut out = [0u8; PK_LEN];
        out[..N_BYTES].copy_from_slice(&be_bytes_from_limbs::<L, N_BYTES>(&self.n));
        out[N_BYTES..].copy_from_slice(&self.e.to_be_bytes());
        out
    }

    /// Decodes [`Self::encode_raw`]'s layout, validated the same way [`Self::new`] validates
    /// `(n, e)`. Takes the exact-length array; the per-size `SignaturePublicKey::from_bytes` that
    /// wraps this is where a wrong-length slice is rejected.
    pub(crate) fn from_bytes_raw<const N_BYTES: usize, const PK_LEN: usize>(
        bytes: &[u8; PK_LEN],
    ) -> Result<Self, SignatureError> {
        debug_assert_eq!(N_BYTES, 8 * L, "RsaPublicKey::from_bytes_raw needs N_BYTES == 8 * L");
        debug_assert_eq!(
            PK_LEN,
            N_BYTES + 4,
            "RsaPublicKey::from_bytes_raw needs PK_LEN == N_BYTES + 4"
        );
        let n_bytes: [u8; N_BYTES] = bytes[..N_BYTES].try_into().expect("N_BYTES-byte slice");
        let n = limbs_from_be_bytes::<L, N_BYTES>(&n_bytes);
        let e_bytes: [u8; 4] = bytes[N_BYTES..].try_into().expect("4-byte slice");
        Self::new(&n, u32::from_be_bytes(e_bytes))
    }
}

/// `RsaPublicKey<L> { n: <hex>, e: <hex> }`, `n` as one big-endian hex string (the limbs are
/// stored least-significant first, so they are printed in reverse). Required by
/// `SignaturePublicKey`'s `Display` supertrait; public data only, so nothing is redacted.
impl<const L: usize> Display for RsaPublicKey<L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "RsaPublicKey<{L}> {{ n: ")?;
        for limb in self.n.iter().rev() {
            write!(f, "{limb:016x}")?;
        }
        write!(f, ", e: {:x} }}", self.e)
    }
}

/// An RSA private key in RFC 8017 §3.2's CRT ("second representation") form: `p`, `q`, `dP`,
/// `dQ`, `qInv`. `L` (the modulus's limb count) must be exactly `2 * HALF`; like
/// `bouncycastle_ec::montgomery`'s `L2 = 2 * L`, that relationship is enforced at construction
/// (see [`Self::from_crt_components`]) rather than expressed in the type, because stable Rust has
/// no way to compute one const generic from another.
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
/// `SignaturePrivateKey::encode`/`from_bytes` (implemented per size, e.g. for
/// `crate::rsa_2048::RSA2048PrivateKey`) use the raw layout `p || q || dP || dQ || qInv`, each
/// `8 * HALF` big-endian bytes, `SK_LEN = 40 * HALF` in all. Not an RFC 8017 or ASN.1 format --
/// see [`RsaPublicKey`]'s `# Encoding` for why -- just a fixed-width layout that round-trips, for
/// `cli/src/rsa_cmd.rs` to read and write private keys as files. Decoding validates the five
/// components the same way [`Self::from_crt_components`] does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPrivateKey<const L: usize, const HALF: usize> {
    p: Secret<[u64; HALF]>,
    q: Secret<[u64; HALF]>,
    d_p: Secret<[u64; HALF]>,
    d_q: Secret<[u64; HALF]>,
    q_inv: Secret<[u64; HALF]>,
    /// `n = p * q`, computed once here. Public: `n` is shared with the matching public key (RFC
    /// 8017 §3.2, "the RSA modulus n is the same as in the corresponding RSA public key").
    n: [u64; L],
}

impl<const L: usize, const HALF: usize> RsaPrivateKey<L, HALF> {
    /// Builds a private key from its CRT components. Returns
    /// `Err(`[`SignatureError::DecodingError`]`)` if:
    ///
    /// * `L != 2 * HALF` (a caller programming error -- every concrete instantiation in this
    ///   crate pairs a fixed `L` with a fixed `HALF`, so this cannot happen through the crate's
    ///   own public API, only through an explicit, wrong turbofish);
    /// * `p` or `q` is even or equal to each other. There is no separate all-zero check: a zero
    ///   value's low limb is `0`, which the oddness check already rejects.
    /// * `dP >= p`, `dQ >= q`, or `qInv >= p` (RFC 8017 §3.2: `dP`/`dQ`/`qInv` are each "a
    ///   positive integer less than" their modulus).
    pub fn from_crt_components(
        p: &[u64; HALF],
        q: &[u64; HALF],
        d_p: &[u64; HALF],
        d_q: &[u64; HALF],
        q_inv: &[u64; HALF],
    ) -> Result<Self, SignatureError> {
        if L != 2 * HALF {
            return Err(SignatureError::DecodingError("RSA modulus width must be 2 * prime width"));
        }
        if p[0] & 1 == 0 {
            return Err(SignatureError::DecodingError("p must be odd"));
        }
        if q[0] & 1 == 0 {
            return Err(SignatureError::DecodingError("q must be odd"));
        }
        if p == q {
            return Err(SignatureError::DecodingError("p and q must be distinct"));
        }
        if nat::sub(d_p, p).1 != 1 {
            return Err(SignatureError::DecodingError("dP must be less than p"));
        }
        if nat::sub(d_q, q).1 != 1 {
            return Err(SignatureError::DecodingError("dQ must be less than q"));
        }
        if nat::sub(q_inv, p).1 != 1 {
            return Err(SignatureError::DecodingError("qInv must be less than p"));
        }

        // `L == 2 * HALF` (checked above), so this widening multiply's `L2 = L` output is exactly
        // the modulus width -- `p * q` is exact, never reduced, since it is the modulus itself.
        let n = montgomery::widening_mul::<HALF, L>(p, q);

        let mut key = Self {
            p: Secret::default(),
            q: Secret::default(),
            d_p: Secret::default(),
            d_q: Secret::default(),
            q_inv: Secret::default(),
            n,
        };
        *key.p = *p;
        *key.q = *q;
        *key.d_p = *d_p;
        *key.d_q = *d_q;
        *key.q_inv = *q_inv;
        Ok(key)
    }

    /// The modulus `n = p * q`.
    pub fn n(&self) -> &[u64; L] {
        &self.n
    }

    pub(crate) fn p(&self) -> &[u64; HALF] {
        &self.p
    }

    pub(crate) fn q(&self) -> &[u64; HALF] {
        &self.q
    }

    pub(crate) fn d_p(&self) -> &[u64; HALF] {
        &self.d_p
    }

    pub(crate) fn d_q(&self) -> &[u64; HALF] {
        &self.d_q
    }

    pub(crate) fn q_inv(&self) -> &[u64; HALF] {
        &self.q_inv
    }

    /// The `# Encoding` layout (see the type's docs), `p || q || dP || dQ || qInv`, with
    /// `HALF_BYTES = 8 * HALF` and `SK_LEN = 5 * HALF_BYTES` supplied by the per-size
    /// `SignaturePrivateKey` impl that wraps this.
    pub(crate) fn encode_raw<const HALF_BYTES: usize, const SK_LEN: usize>(&self) -> [u8; SK_LEN] {
        debug_assert_eq!(
            HALF_BYTES,
            8 * HALF,
            "RsaPrivateKey::encode_raw needs HALF_BYTES == 8 * HALF"
        );
        debug_assert_eq!(
            SK_LEN,
            5 * HALF_BYTES,
            "RsaPrivateKey::encode_raw needs SK_LEN == 5 * HALF_BYTES"
        );
        let mut out = [0u8; SK_LEN];
        out[..HALF_BYTES].copy_from_slice(&be_bytes_from_limbs::<HALF, HALF_BYTES>(&self.p));
        out[HALF_BYTES..2 * HALF_BYTES]
            .copy_from_slice(&be_bytes_from_limbs::<HALF, HALF_BYTES>(&self.q));
        out[2 * HALF_BYTES..3 * HALF_BYTES]
            .copy_from_slice(&be_bytes_from_limbs::<HALF, HALF_BYTES>(&self.d_p));
        out[3 * HALF_BYTES..4 * HALF_BYTES]
            .copy_from_slice(&be_bytes_from_limbs::<HALF, HALF_BYTES>(&self.d_q));
        out[4 * HALF_BYTES..]
            .copy_from_slice(&be_bytes_from_limbs::<HALF, HALF_BYTES>(&self.q_inv));
        out
    }

    /// Decodes [`Self::encode_raw`]'s layout, validated the same way
    /// [`Self::from_crt_components`] validates its five components. Takes the exact-length array;
    /// the per-size `SignaturePrivateKey::from_bytes` that wraps this is where a wrong-length
    /// slice is rejected.
    pub(crate) fn from_bytes_raw<const HALF_BYTES: usize, const SK_LEN: usize>(
        bytes: &[u8; SK_LEN],
    ) -> Result<Self, SignatureError> {
        debug_assert_eq!(
            HALF_BYTES,
            8 * HALF,
            "RsaPrivateKey::from_bytes_raw needs HALF_BYTES == 8 * HALF"
        );
        debug_assert_eq!(
            SK_LEN,
            5 * HALF_BYTES,
            "RsaPrivateKey::from_bytes_raw needs SK_LEN == 5 * HALF_BYTES"
        );
        let p_bytes: [u8; HALF_BYTES] = bytes[..HALF_BYTES].try_into().expect("HALF_BYTES bytes");
        let q_bytes: [u8; HALF_BYTES] =
            bytes[HALF_BYTES..2 * HALF_BYTES].try_into().expect("HALF_BYTES bytes");
        let d_p_bytes: [u8; HALF_BYTES] =
            bytes[2 * HALF_BYTES..3 * HALF_BYTES].try_into().expect("HALF_BYTES bytes");
        let d_q_bytes: [u8; HALF_BYTES] =
            bytes[3 * HALF_BYTES..4 * HALF_BYTES].try_into().expect("HALF_BYTES bytes");
        let q_inv_bytes: [u8; HALF_BYTES] =
            bytes[4 * HALF_BYTES..].try_into().expect("HALF_BYTES bytes");

        let p = limbs_from_be_bytes::<HALF, HALF_BYTES>(&p_bytes);
        let q = limbs_from_be_bytes::<HALF, HALF_BYTES>(&q_bytes);
        let d_p = limbs_from_be_bytes::<HALF, HALF_BYTES>(&d_p_bytes);
        let d_q = limbs_from_be_bytes::<HALF, HALF_BYTES>(&d_q_bytes);
        let q_inv = limbs_from_be_bytes::<HALF, HALF_BYTES>(&q_inv_bytes);
        Self::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
    }
}
