//! RSASVE, RSA Secret-Value Encapsulation (NIST SP 800-56B Rev. 2 §7.2.1), as a
//! [`bouncycastle_core`] KEM on the key objects: the KEM-only key types [`RsaKEMPublicKey`] and
//! [`RsaKEMPrivateKey`] implement the `EncapsulatingKey` / `DecapsulatingKey` roles over `()`
//! at every signing size, naming [`RSASVE<K>`](RSASVE) as the algorithm and handing out the workers
//! [`RsasveEncapsulator`] and [`RsasveDecapsulator`], whose `encaps_out` is RSASVE.GENERATE
//! (§7.2.1.2) and whose `decaps_out` is RSASVE.RECOVER (§7.2.1.3).
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
//! The key types here wrap the signature schemes' [`RsaPublicComponents`]/[`RsaPrivateComponents`] rather than
//! reusing them, so the type system keeps key-establishment and signing keys apart. There is no
//! signing-role impl for an [`RsaKEMPrivateKey`] and no decapsulating role for an
//! [`RsaPrivateComponents`]. SP 800-56B Rev. 2 §6.1 item 5 is the requirement: "One key pair shall not
//! be used for different cryptographic purposes (for example, a digital-signature key pair shall
//! not be used for key establishment or vice versa)". BC FIPS Java checks the same thing at runtime with
//! `canBeUsed(ENCRYPT_OR_DECRYPT)`. Nothing stops a caller from building both kinds of key from
//! the same CRT components, and nothing can.
//!
//! # Key validation
//!
//! On top of what [`RsaPublicComponents::new`]/[`RsaPrivateComponents::from_crt_components`] already check,
//! the KEM key types enforce two things:
//!
//! * `65,537 <= e` (§6.2.1 item 2, "65,537 ≤ e < 2^256"; the upper bound holds by construction,
//!   because `e` is a `u32`). This applies to the public key only: the CRT private key does not
//!   carry `e`.
//! * `n` is exactly the size's `nLen` bits long, i.e. its top bit is set. §6.2.1 item 1 gives the key an
//!   `nBits`, and §6.4.2.2's partial public-key validation requires "that the bit length of the
//!   modulus shall be a length that is approved in this Recommendation". A 2048-bit key type holding
//!   a shorter modulus would also break RSASVE.GENERATE's `nLen`, which is fixed at `K::K_LEN` bytes
//!   here. And with the top bit set, each draw of step 2's rejection loop succeeds with probability
//!   above one half.
//!
//! The rest of SP 800-89 §5.3.3's plausibility tests, which §6.4.2.2 also requires, are not
//! performed (beyond `n` odd and `e` odd, which [`RsaPublicComponents::new`] checks). Nothing here
//! amounts to full public-key validation, which §6.4.2.2 notes "is not specified in this
//! Recommendation".

use crate::keys::{RsaPrivateComponents, RsaPublicComponents};
use crate::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::{KEMError, RNGError, SignatureError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey, KEMAlgorithm};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey, RNG,
};
use bouncycastle_utils::const_str::ConstStr;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::fmt;
use core::fmt::{Display, Formatter};
use core::marker::PhantomData;

/// The smallest public exponent SP 800-56B Rev. 2 §6.2.1 item 2 allows a key-establishment key.
pub const MIN_PUBLIC_EXPONENT: u32 = 65537;

/// How many draws RSASVE.GENERATE (§7.2.1.2 step 2) makes before giving up on an RNG whose
/// output never lands in `(1, n - 1)`: with the modulus's top bit set each draw succeeds with
/// probability above one half, so a genuine RNG fails this `2^-128` of the time.
pub const MAX_GENERATE_ATTEMPTS: usize = 128;

fn kem_error(e: SignatureError) -> KEMError {
    match e {
        SignatureError::DecodingError(msg) => KEMError::DecodingError(msg),
        SignatureError::RNGError(e) => KEMError::RNGError(e),
        SignatureError::GenericError(s) => KEMError::GenericError(s),
        _ => KEMError::GenericError("unexpected error from the RSA key layer"),
    }
}

/// Whether the modulus's top bit is set: `n` has exactly the size's bit length.
fn has_full_bit_length<K: RsaSize>(n: &K::Limbs) -> bool {
    n.as_ref()[n.as_ref().len() - 1] >> 63 == 1
}

/// Whether `1 < x < n - 1` (§7.2.1.2 step 2's range, §7.2.1.3 step 1's check).
fn in_open_range<K: RsaSize>(x: &K::Limbs, n: &K::Limbs) -> bool {
    // `n` is odd (every key type here checks it), so `n - 1` is `n` with its low bit cleared and
    // needs no borrow propagation.
    let mut n_minus_1 = *n;
    n_minus_1.as_mut()[0] &= !1;
    let mut one = K::Limbs::ZEROED;
    one.as_mut()[0] = 1;
    K::is_less(x, &n_minus_1) && K::is_less(&one, x)
}

/// An RSA key-establishment public key at the size `K`: [`RsaPublicComponents`] under the KEM roles
/// and the `# Key validation` checks, encoded as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaKEMPublicKey<K: RsaSize>(pub(crate) RsaPublicComponents<K>);

impl<K: RsaSize> RsaKEMPublicKey<K> {
    /// Builds a public key from its modulus and exponent. Returns
    /// `Err(`[`KEMError::DecodingError`]`)` in the cases [`RsaPublicComponents::new`] rejects, and also
    /// if `e < 65,537` or `n`'s top bit is clear (see the module docs' `# Key validation`).
    pub fn new(n: &K::Limbs, e: u32) -> Result<Self, KEMError> {
        Self::from_rsa_key(RsaPublicComponents::new(n, e).map_err(kem_error)?)
    }

    pub(crate) fn from_rsa_key(pk: RsaPublicComponents<K>) -> Result<Self, KEMError> {
        if pk.e() < MIN_PUBLIC_EXPONENT {
            return Err(KEMError::DecodingError(
                "RSA key-establishment public exponent must be at least 65537",
            ));
        }
        if !has_full_bit_length::<K>(pk.n()) {
            return Err(KEMError::DecodingError("RSA modulus must have its top bit set"));
        }
        Ok(Self(pk))
    }

    /// The modulus `n`, as little-endian limbs.
    pub fn n(&self) -> &K::Limbs {
        self.0.n()
    }

    /// The public exponent `e`.
    pub fn e(&self) -> u32 {
        self.0.e()
    }
}

/// `RsaKEMPublicKey<RSA-2048> { n: <hex>, e: <hex> }`, `n` as one big-endian hex string; public
/// data only.
impl<K: RsaSize> Display for RsaKEMPublicKey<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "RsaKEMPublicKey<{}> {{ n: ", K::NAME)?;
        for limb in self.0.n().as_ref().iter().rev() {
            write!(f, "{limb:016x}")?;
        }
        write!(f, ", e: {:x} }}", self.0.e())
    }
}

/// An RSA key-establishment private key at the size `K`: [`RsaPrivateComponents`] under the KEM roles
/// and the `# Key validation` checks, encoded as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaKEMPrivateKey<K: RsaSize>(pub(crate) RsaPrivateComponents<K>);

impl<K: RsaSigningSize> RsaKEMPrivateKey<K> {
    /// Builds a private key from its CRT components. Returns
    /// `Err(`[`KEMError::DecodingError`]`)` in the cases [`RsaPrivateComponents::from_crt_components`]
    /// rejects, and also if `n = p * q`'s top bit is clear (see the module docs'
    /// `# Key validation`).
    pub fn from_crt_components(
        p: &K::HalfLimbs,
        q: &K::HalfLimbs,
        d_p: &K::HalfLimbs,
        d_q: &K::HalfLimbs,
        q_inv: &K::HalfLimbs,
    ) -> Result<Self, KEMError> {
        Self::from_rsa_key(
            RsaPrivateComponents::from_crt_components(p, q, d_p, d_q, q_inv).map_err(kem_error)?,
        )
    }

    pub(crate) fn from_rsa_key(sk: RsaPrivateComponents<K>) -> Result<Self, KEMError> {
        if !has_full_bit_length::<K>(sk.n()) {
            return Err(KEMError::DecodingError("RSA modulus must have its top bit set"));
        }
        Ok(Self(sk))
    }

    /// The modulus `n = p * q`, as little-endian limbs.
    pub fn n(&self) -> &K::Limbs {
        self.0.n()
    }
}

/// RSASVE (SP 800-56B Rev. 2 §7.2.1) at the modulus size `K`: the algorithm the KEM key types
/// name, `RSASVE-2048` and so on, at the size's strength. The ciphertext and the shared secret
/// are each `nLen = K::K_LEN` bytes.
#[allow(non_camel_case_types)]
pub struct RSASVE<K: RsaSize> {
    _size: PhantomData<K>,
}

impl<K: RsaSize> RSASVE<K> {
    const NAME: ConstStr<16> = ConstStr::concat(&["RSASVE-", K::BITS_NAME]);
}

impl<K: RsaSigningSize> RSASVE<K> {
    /// The same FIPS 186-5 Appendix A.1.3 generator the signature keys use, in the KEM key types.
    ///
    /// # Errors
    /// As [`RsaSigningSize::keygen`], as a [`KEMError`].
    pub fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RsaKEMPublicKey<K>, RsaKEMPrivateKey<K>), KEMError> {
        keygen_from::<K>(K::keygen(rng))
    }
}

impl<K: RsaSize> Algorithm for RSASVE<K> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength = K::STRENGTH;
}

impl<K: RsaSize> KEMAlgorithm for RSASVE<K> {}

/// The worker [`EncapsulatingKey::create_encapsulator`] hands out: the public key, borrowed.
pub struct RsasveEncapsulator<'k, K: RsaSize> {
    pk: &'k RsaKEMPublicKey<K>,
}

impl<K: RsaSize> Algorithm for RsasveEncapsulator<'_, K> {
    const ALG_NAME: &'static str = RSASVE::<K>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = RSASVE::<K>::MAX_SECURITY_STRENGTH;
}

impl<K, const N: usize> KEMEncapsulator<N, N> for RsasveEncapsulator<'_, K>
where
    K: RsaSize<Modulus = [u8; N]>,
{
    /// RSASVE.GENERATE (§7.2.1.2): `Z` from the RNG until `1 < z < n - 1` (step 2), `C = z^e mod
    /// n` (step 3) into `ct`, and `Z` into `ss` typed `CryptographicRandom` at the size's
    /// strength (step 4's output). Both buffers are zeroized first and left so on error.
    #[allow(non_snake_case)]
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; N],
        ss: &mut KeyMaterial<N>,
    ) -> Result<usize, KEMError> {
        ct.fill(0);
        ss.zeroize();
        if rng.security_strength() < K::STRENGTH {
            return Err(KEMError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm));
        }
        let mut Z = Secret::<[u8; N]>::new();
        let mut z = Secret::<K::Limbs>::new();
        let mut attempts = 0;
        loop {
            if attempts == MAX_GENERATE_ATTEMPTS {
                return Err(KEMError::GenericError(
                    "RSASVE.GENERATE: RNG output never fell within (1, n - 1)",
                ));
            }
            attempts += 1;
            rng.next_bytes_out(&mut *Z)?;
            *z = K::limbs_from_be_bytes(&Z);
            if in_open_range::<K>(&z, self.pk.n()) {
                break;
            }
        }
        let c = K::public_exp(self.pk.n(), self.pk.e(), &z);
        *ct = K::be_bytes_from_limbs(&c);
        if let Err(e) = secret_value_into::<K, N>(&Z, ss) {
            ct.fill(0);
            return Err(e);
        }
        Ok(N)
    }
}

/// `Z` into the caller's buffer, typed `CryptographicRandom` (§7.2.1.2 step 2 draws it so) at
/// the size's strength; zeroized first and left so on error.
#[allow(non_snake_case)]
fn secret_value_into<K: RsaSize, const N: usize>(
    Z: &[u8; N],
    ss: &mut KeyMaterial<N>,
) -> Result<(), KEMError> {
    ss.zeroize();
    let result = do_hazardous_operations(ss, |ss| {
        ss.set_bytes_as_type(Z, KeyType::CryptographicRandom)?;
        ss.set_security_strength(K::STRENGTH)
    });
    if let Err(e) = result {
        ss.zeroize();
        return Err(e.into());
    }
    Ok(())
}

/// The worker [`DecapsulatingKey::create_decapsulator`] hands out: the private key, borrowed.
pub struct RsasveDecapsulator<'k, K: RsaSize> {
    sk: &'k RsaKEMPrivateKey<K>,
}

impl<K: RsaSize> Algorithm for RsasveDecapsulator<'_, K> {
    const ALG_NAME: &'static str = RSASVE::<K>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = RSASVE::<K>::MAX_SECURITY_STRENGTH;
}

impl<K, const N: usize> KEMDecapsulator<N, N> for RsasveDecapsulator<'_, K>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
{
    /// RSASVE.RECOVER (§7.2.1.3): `C` in `(1, n - 1)` or [`KEMError::DecapsulationFailed`]
    /// (step 1), `z = C^d mod n` by the CRT (step 2) and `Z = I2BS(z, nLen)` into `ss` (step 3),
    /// zeroized first and left so on error.
    #[allow(non_snake_case)]
    fn decaps_out(&self, ct: &[u8; N], ss: &mut KeyMaterial<N>) -> Result<usize, KEMError> {
        ss.zeroize();
        let c = K::limbs_from_be_bytes(ct);
        if !in_open_range::<K>(&c, self.sk.n()) {
            return Err(KEMError::DecapsulationFailed);
        }
        let mut z = Secret::<K::Limbs>::new();
        *z = K::crt_exp(&self.sk.0, &c);
        let mut Z = Secret::<[u8; N]>::new();
        *Z = K::be_bytes_from_limbs(&z);
        secret_value_into::<K, N>(&Z, ss)?;
        Ok(N)
    }
}

impl<K, const N: usize> EncapsulatingKey<(), N, N> for RsaKEMPublicKey<K>
where
    K: RsaSize<Modulus = [u8; N]>,
{
    type Algorithm = RSASVE<K>;
    type Encapsulator<'k> = RsasveEncapsulator<'k, K>;

    /// Cannot fail: RSASVE takes no parameters beyond the key.
    fn create_encapsulator<'k>(&'k self, _params: ()) -> Result<Self::Encapsulator<'k>, KEMError> {
        Ok(RsasveEncapsulator { pk: self })
    }
}

impl<K, const N: usize> DecapsulatingKey<(), N, N> for RsaKEMPrivateKey<K>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
{
    type Algorithm = RSASVE<K>;
    type Decapsulator<'k> = RsasveDecapsulator<'k, K>;

    /// Cannot fail: RSASVE takes no parameters beyond the key.
    fn create_decapsulator<'k>(&'k self, _params: ()) -> Result<Self::Decapsulator<'k>, KEMError> {
        Ok(RsasveDecapsulator { sk: self })
    }
}

impl<K, const SK_LEN: usize> KEMPrivateKey<SK_LEN> for RsaKEMPrivateKey<K>
where
    K: RsaSigningSize + RsaSize<PrivateKeyEncoded = [u8; SK_LEN]>,
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.0.encode_raw()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        *out = self.0.encode_raw();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        let bytes: &[u8; SK_LEN] = bytes.try_into().map_err(|_| {
            KEMError::DecodingError(
                "an RSA private key is five components of half the modulus length",
            )
        })?;
        Self::from_rsa_key(RsaPrivateComponents::from_bytes_raw(bytes).map_err(kem_error)?)
    }
}

impl<K, const PK_LEN: usize> KEMPublicKey<PK_LEN> for RsaKEMPublicKey<K>
where
    K: RsaSize<PublicKeyEncoded = [u8; PK_LEN]>,
{
    fn encode(&self) -> [u8; PK_LEN] {
        self.0.encode_raw()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.0.encode_raw();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        let bytes: &[u8; PK_LEN] = bytes.try_into().map_err(|_| {
            KEMError::DecodingError("an RSA public key is the modulus length plus four bytes")
        })?;
        Self::from_rsa_key(RsaPublicComponents::from_bytes_raw(bytes).map_err(kem_error)?)
    }
}

/// The signature generator's pair as KEM keys, for [`RSASVE::keygen`] and the markers'
/// `generate_kem_key_pair`.
pub(crate) fn keygen_from<K: RsaSigningSize>(
    pair: Result<(RsaPublicComponents<K>, RsaPrivateComponents<K>), SignatureError>,
) -> Result<(RsaKEMPublicKey<K>, RsaKEMPrivateKey<K>), KEMError> {
    let (pk, sk) = pair.map_err(kem_error)?;
    Ok((RsaKEMPublicKey::from_rsa_key(pk)?, RsaKEMPrivateKey::from_rsa_key(sk)?))
}
