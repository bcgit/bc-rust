//! RSAES-OAEP (RFC 8017 §7.1; SP 800-56B Rev. 2 §7.2.2, RSA-OAEP) on the key-establishment
//! keys [`RsaKEMPublicKey`] and [`RsaKEMPrivateKey`], as key transport: the plaintext is always
//! a key.
//!
//! Two roles over one implementation, both selected by [`OaepParams`]:
//!
//! * **A KEM**, KTS-OAEP-basic of SP 800-56B Rev. 2 §9.2.3 with the key drawn here: the
//!   [`EncapsulatingKey`] / [`DecapsulatingKey`] roles, whose shared secret is the transported
//!   key, `LEN` bytes from the caller's RNG.
//! * **Transport of a key the caller holds** (a CMS or JOSE content-encryption key): the
//!   [`KeyTransportEncryptingKey`] / [`KeyTransportDecryptingKey`] roles.
//!
//! The parameters name the label hash `H` and the MGF1 hash `M`, which SP 800-56B Rev. 2
//! §7.2.2.1 item 2 allows to differ, and carry the label `L` (the "additional input" `A` of
//! §7.2.2.3), which both sides must supply and which may be empty.
//!
//! # 🚨 Security Considerations 🚨
//!
//! * **The ciphertext does not say who made it.** Anyone with the public key can transport a
//!   key to its owner; a protocol that needs to know the sender must authenticate it.
//! * **Every decryption failure is one error** ([`KEMError::DecapsulationFailed`],
//!   [`KeyTransportError::DecryptionFailed`]), computed without branching on the padding, as
//!   RFC 8017 §7.1.2's note asks; a private-key result that fails its check (the crate's
//!   `# Security Considerations`) is that error as well, by the same path. A caller must keep
//!   it that way: do not report, log or time anything that tells a peer why a ciphertext was
//!   refused.
//! * **The label is not secret and is not sent.** It binds a ciphertext to its use; a
//!   ciphertext made under one label does not decrypt under another.
//! * **The hashes are RFC 8017's** ([`OaepHash`]). **SHA-1** is among them, for peers that use it.
//!   OAEP does not rest on collision resistance, so the algorithm's strength is the modulus's,
//!   capped by what the shorter hash output can carry; prefer SHA-256 or longer where the
//!   choice is open.

use crate::eme_oaep::{self, HashBuf};
use crate::keygen::fill_bytes;
use crate::rsa_core::wipe_stack_below;
use crate::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey, in_open_range};
use crate::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::{KEMError, KeyMaterialError, KeyTransportError, RNGError};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey, KEMAlgorithm};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::key_transport_key::{
    KeyTransportAlgorithm, KeyTransportDecryptingKey, KeyTransportEncryptingKey,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, HashAlgParams, HashOneShot, KEMDecapsulator, KEMEncapsulator, RNG,
};
use bouncycastle_digest::sha1::SHA1;
use bouncycastle_digest::sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle_utils::const_str::ConstStr;
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

mod sealed {
    pub trait Sealed {}
}

/// A hash RSAES-OAEP may use for its label and under MGF1: the `OAEP-PSSDigestAlgorithms` of
/// RFC 8017 Appendix A.2.1, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and
/// SHA-512/256. Sealed: the buffers and the strength below are sized for these.
pub trait OaepHash: HashOneShot + HashAlgParams + sealed::Sealed {}

impl sealed::Sealed for SHA1 {}
impl OaepHash for SHA1 {}
impl sealed::Sealed for SHA224 {}
impl OaepHash for SHA224 {}
impl sealed::Sealed for SHA256 {}
impl OaepHash for SHA256 {}
impl sealed::Sealed for SHA384 {}
impl OaepHash for SHA384 {}
impl sealed::Sealed for SHA512 {}
impl OaepHash for SHA512 {}
impl sealed::Sealed for SHA512_224 {}
impl OaepHash for SHA512_224 {}
impl sealed::Sealed for SHA512_256 {}
impl OaepHash for SHA512_256 {}

/// RSAES-OAEP at the modulus size `K` with the label hash `H` and MGF1 over `M`: the algorithm
/// the key-establishment keys run under [`OaepParams`], named
/// `RSAES-OAEP-2048-SHA256-MGF1-SHA256` and so on.
///
/// The encapsulating and key-transporting roles exist at a signing size, RSA-2048 and up, as
/// their private counterparts do. Nothing is encapsulated or transported toward RSA-1024 or
/// RSA-1536:
///
/// ```compile_fail,E0277
/// use bouncycastle_core::kem_key::EncapsulatingKey;
/// use bouncycastle_rsa::RSA1024;
/// use bouncycastle_rsa::rsaes_oaep::OaepParams;
/// use bouncycastle_rsa::rsasve::RsaKEMPublicKey;
/// use bouncycastle_digest::sha2::SHA256;
///
/// type Params = OaepParams<'static, SHA256, SHA256, 32>;
/// fn encapsulates<PK: EncapsulatingKey<Params, N, 32>, const N: usize>() {}
/// encapsulates::<RsaKEMPublicKey<RSA1024>, 128>();
/// ```
///
/// ```compile_fail,E0277
/// use bouncycastle_core::key_transport_key::KeyTransportEncryptingKey;
/// use bouncycastle_rsa::RSA1024;
/// use bouncycastle_rsa::rsaes_oaep::OaepParams;
/// use bouncycastle_rsa::rsasve::RsaKEMPublicKey;
/// use bouncycastle_digest::sha2::SHA256;
///
/// type Params = OaepParams<'static, SHA256>;
/// fn transports<PK: KeyTransportEncryptingKey<Params, N>, const N: usize>() {}
/// transports::<RsaKEMPublicKey<RSA1024>, 128>();
/// ```
///
/// ```
/// use bouncycastle_core::kem_key::EncapsulatingKey;
/// use bouncycastle_core::key_transport_key::KeyTransportEncryptingKey;
/// use bouncycastle_rsa::RSA2048;
/// use bouncycastle_rsa::rsaes_oaep::OaepParams;
/// use bouncycastle_rsa::rsasve::RsaKEMPublicKey;
/// use bouncycastle_digest::sha2::SHA256;
///
/// type Kem = OaepParams<'static, SHA256, SHA256, 32>;
/// type Transport = OaepParams<'static, SHA256>;
/// fn encapsulates<PK: EncapsulatingKey<Kem, N, 32>, const N: usize>() {}
/// fn transports<PK: KeyTransportEncryptingKey<Transport, N>, const N: usize>() {}
/// encapsulates::<RsaKEMPublicKey<RSA2048>, 256>();
/// transports::<RsaKEMPublicKey<RSA2048>, 256>();
/// ```
#[allow(non_camel_case_types)]
pub struct RSAES_OAEP<K: RsaSize, H, M = H> {
    _params: PhantomData<(K, H, M)>,
}

/// What a hash output of `h_len` bytes can carry as a preimage strength, which for the hashes
/// of [`OaepHash`] is the output's length: OAEP's hashes are used as random oracles, not for
/// collision resistance.
const fn hash_output_strength(h_len: usize) -> SecurityStrength {
    match h_len {
        32.. => SecurityStrength::_256bit,
        24..32 => SecurityStrength::_192bit,
        16..24 => SecurityStrength::_128bit,
        _ => SecurityStrength::None,
    }
}

/// The lesser of two strengths, in a const.
const fn min_strength(a: SecurityStrength, b: SecurityStrength) -> SecurityStrength {
    if (a as u8) < (b as u8) { a } else { b }
}

impl<K: RsaSize, H: OaepHash, M: OaepHash> RSAES_OAEP<K, H, M> {
    const NAME: ConstStr<64> =
        ConstStr::concat(&["RSAES-OAEP-", K::BITS_NAME, "-", H::ALG_NAME, "-MGF1-", M::ALG_NAME]);

    /// The modulus's strength, capped by what each hash's output length can carry.
    const STRENGTH: SecurityStrength = min_strength(
        K::STRENGTH,
        min_strength(hash_output_strength(H::OUTPUT_LEN), hash_output_strength(M::OUTPUT_LEN)),
    );

    /// `k - 2hLen - 2`, the longest message (RFC 8017 §7.1.1 step 1.b). Evaluating it checks
    /// §7.1.2 step 1.c, `k >= 2hLen + 2`, at compile time.
    const MAX_MESSAGE_LEN: usize = {
        assert!(K::K_LEN >= 2 * H::OUTPUT_LEN + 2, "the modulus is too short for this hash");
        K::K_LEN - 2 * H::OUTPUT_LEN - 2
    };
}

impl<K: RsaSize, H: OaepHash, M: OaepHash> Algorithm for RSAES_OAEP<K, H, M> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength = Self::STRENGTH;
}

impl<K: RsaSize, H: OaepHash, M: OaepHash> KEMAlgorithm for RSAES_OAEP<K, H, M> {}

impl<K: RsaSize, H: OaepHash, M: OaepHash> KeyTransportAlgorithm for RSAES_OAEP<K, H, M> {}

/// The parameters of RSAES-OAEP: the label hash `H`, the MGF1 hash `M` (the same hash unless
/// spelled), the label, and for the KEM roles the length `LEN` of the key to transport.
///
/// The KEM roles check `LEN` against the modulus when they are compiled; RSA-2048 with
/// SHA-256 carries at most 190 bytes, so 190 builds (`tests/rsaes_oaep_tests.rs`) and 191 does
/// not:
///
/// ```compile_fail,E0080
/// use bouncycastle_core::kem_key::EncapsulatingKey;
/// use bouncycastle_rng::HashDRBG_SHA512;
/// use bouncycastle_rsa::rsa_2048::RSASVE;
/// use bouncycastle_rsa::rsaes_oaep::OaepParams;
/// use bouncycastle_digest::sha2::SHA256;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let (pk, _sk) = RSASVE::keygen(&mut rng).unwrap();
/// let _ = pk.encaps(&mut rng, OaepParams::<SHA256, SHA256, 191>::new(b""));
/// ```
pub struct OaepParams<'l, H, M = H, const LEN: usize = 32> {
    label: &'l [u8],
    _hashes: PhantomData<(H, M)>,
}

// Not derived: the derive would ask `H: Clone` and `M: Clone` of a marker that holds neither.
impl<H, M, const LEN: usize> Clone for OaepParams<'_, H, M, LEN> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H, M, const LEN: usize> Copy for OaepParams<'_, H, M, LEN> {}

impl<'l, H, M, const LEN: usize> OaepParams<'l, H, M, LEN> {
    /// The parameters with the label `label`, which may be empty (RFC 8017 §7.1.1: "the
    /// default value for L, if L is not provided, is the empty string").
    pub fn new(label: &'l [u8]) -> Self {
        Self { label, _hashes: PhantomData }
    }
}

/// RSAES-OAEP-ENCRYPT (RFC 8017 §7.1.1) of `msg` under `pk` and `label` into `ct`, which is
/// zeroized first and left so on an error. The caller has checked `mLen <= k - 2hLen - 2` and
/// the RNG's strength.
fn encrypt<K, H, M, const N: usize>(
    pk: &RsaKEMPublicKey<K>,
    label: &[u8],
    msg: &[u8],
    rng: &mut dyn RNG,
    ct: &mut [u8; N],
) -> Result<(), RNGError>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: OaepHash,
    M: OaepHash,
{
    ct.fill(0);
    let h_len = H::OUTPUT_LEN;
    // Step 2.a: lHash = Hash(L).
    let mut l_hash = HashBuf::new();
    eme_oaep::label_hash::<H>(label, &mut l_hash);
    // Step 2.d: a random octet string seed of length hLen.
    let mut seed = HashBuf::new();
    fill_bytes(rng, &mut seed[..h_len])?;
    // Steps 2.b to 2.i: EM = 0x00 || maskedSeed || maskedDB.
    let mut em = Secret::<[u8; N]>::new();
    eme_oaep::encode::<H, M>(&l_hash[..h_len], &seed[..h_len], msg, &mut *em);
    // Step 3: m = OS2IP(EM); c = RSAEP((n, e), m); C = I2OSP(c, k). EM's leading octet is 0x00
    // and a key-establishment key's modulus has its top bit set, so m < n.
    let mut m = Secret::<K::Limbs>::new();
    *m = K::limbs_from_be_bytes(&em);
    let c = K::public_exp(pk.n(), pk.e(), &m, crate::size::sealed::EngineToken::new());
    *ct = K::be_bytes_from_limbs(&c);
    Ok(())
}

/// RSAES-OAEP-DECRYPT (RFC 8017 §7.1.2) of `ct` under `sk` and `label` into `out`, which is
/// zeroized first and left so on failure: the message length, or `None` for a decryption error
/// of any kind. `exact_len` is as [`eme_oaep::decode_out`]'s.
fn decrypt<K, H, M, const N: usize>(
    sk: &RsaKEMPrivateKey<K>,
    label: &[u8],
    ct: &[u8; N],
    exact_len: Option<usize>,
    out: &mut [u8],
) -> Option<usize>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: OaepHash,
    M: OaepHash,
{
    let len = decrypt_in_own_frame::<K, H, M, N>(sk, label, ct, exact_len, out);
    // The encoded message and the seed pass through return slots and through the frames of
    // the mask generation; the whole operation's stack is overwritten, the CRT's own wipe
    // being inside it.
    wipe_stack_below::<K::Limbs, DECRYPT_STACK_PER_LIMB, DECRYPT_STACK_FIXED>();
    len
}

/// What [`wipe_stack_below`] overwrites after RSAES-OAEP-DECRYPT: this many `K::Limbs` values
/// and this many words. Measured in x86-64 release builds (rustc 1.88 and 1.97) with SHA-256,
/// the operation uses 9544 bytes at RSA-2048, 12632 at RSA-3072, 16344 at RSA-4096 and 32232
/// at RSA-8192; these cover 11008, 15360, 19712 and 37120, the difference being room for a
/// compiler that lays the frames out less tightly.
const DECRYPT_STACK_PER_LIMB: usize = 34;
const DECRYPT_STACK_FIXED: usize = 288;

/// The work of [`decrypt`]. Never inlined, so that what it leaves lies below its caller's
/// frame, where [`wipe_stack_below`] reaches it.
#[inline(never)]
fn decrypt_in_own_frame<K, H, M, const N: usize>(
    sk: &RsaKEMPrivateKey<K>,
    label: &[u8],
    ct: &[u8; N],
    exact_len: Option<usize>,
    out: &mut [u8],
) -> Option<usize>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: OaepHash,
    M: OaepHash,
{
    out.fill(0);
    // Step 2.a: c = OS2IP(C). RFC 8017 step 2.b refuses c >= n ("ciphertext representative
    // out of range"); SP 800-56B Rev. 2 §7.2.2.4 step 2.c is narrower, "If the ciphertext
    // integer c is not such that 1 < c < (n - 1), output an indication of erroneous input",
    // and is what is applied. The ciphertext and the modulus are public, so this branch tells
    // an observer nothing it could not compute; the error is the one every failure gives.
    let c = K::limbs_from_be_bytes(ct);
    if !in_open_range::<K>(&c, sk.n()) {
        return None;
    }
    // Step 2.b: m = RSADP(K, c), constant time in the key, and `m` zero if it failed its check
    // (m^e mod n is not c); step 2.c: EM = I2OSP(m, k).
    let mut m = Secret::<K::Limbs>::new();
    let checked = K::crt_exp(&sk.0, &c, &mut m, crate::size::sealed::EngineToken::new());
    let mut em = Secret::<[u8; N]>::new();
    *em = K::be_bytes_from_limbs(&m);
    // A failed check must end as the one decryption error, and no sooner or later than a bad
    // encoding does, so it is not branched on: it sets EM's first octet, which step 3.g
    // refuses when it is not zero ("if Y is nonzero"), and the decoding runs as for any EM.
    em[0] |= checked.select(0x00, 0xFF) as u8;
    // Step 3.
    let mut l_hash = HashBuf::new();
    let h_len = eme_oaep::label_hash::<H>(label, &mut l_hash);
    eme_oaep::decode_out::<H, M>(&l_hash[..h_len], &mut *em, exact_len, out)
}

/// The transported key into the caller's buffer, typed `CryptographicRandom` at the lesser of
/// `strength` and what its length carries; zeroized first and left so on error. An empty or
/// all-zero key is a value, not an error: the buffer types it `Zeroized`, with no strength.
fn key_into<const N: usize>(
    bytes: &[u8],
    strength: SecurityStrength,
    key: &mut KeyMaterial<N>,
) -> Result<(), KeyMaterialError> {
    key.zeroize();
    match key.set_bytes_as_type(bytes, KeyType::CryptographicRandom) {
        Ok(()) => {}
        Err(KeyMaterialError::ActingOnZeroizedKey) => return Ok(()),
        Err(e) => {
            key.zeroize();
            return Err(e);
        }
    }
    if key.security_strength() > strength {
        // Lowering a strength is always permitted.
        if let Err(e) = key.set_security_strength(strength) {
            key.zeroize();
            return Err(e);
        }
    }
    Ok(())
}

/// The worker [`EncapsulatingKey::create_encapsulator`] hands out under [`OaepParams`]: the
/// public key, borrowed, and the parameters.
pub struct RsaOaepEncapsulator<'k, 'l, K: RsaSize, H, M, const LEN: usize> {
    pk: &'k RsaKEMPublicKey<K>,
    params: OaepParams<'l, H, M, LEN>,
}

impl<K: RsaSize, H: OaepHash, M: OaepHash, const LEN: usize> Algorithm
    for RsaOaepEncapsulator<'_, '_, K, H, M, LEN>
{
    const ALG_NAME: &'static str = RSAES_OAEP::<K, H, M>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = RSAES_OAEP::<K, H, M>::MAX_SECURITY_STRENGTH;
}

impl<K, H, M, const N: usize, const LEN: usize> KEMEncapsulator<N, LEN>
    for RsaOaepEncapsulator<'_, '_, K, H, M, LEN>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: OaepHash,
    M: OaepHash,
{
    /// KTS-OAEP-basic, party U (SP 800-56B Rev. 2 §9.2.3), with the keying material drawn
    /// here: `LEN` bytes from `rng` into `ss`, and `C = RSA-OAEP.ENCRYPT(PubKeyV, K, A)` into
    /// `ct`. Both buffers are zeroized first and left so on error.
    ///
    /// # Errors
    /// [`KEMError::RNGError`] if `rng` is weaker than the algorithm or fails to deliver.
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; N],
        ss: &mut KeyMaterial<LEN>,
    ) -> Result<usize, KEMError> {
        ct.fill(0);
        ss.zeroize();
        if rng.security_strength() < RSAES_OAEP::<K, H, M>::STRENGTH {
            return Err(KEMError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm));
        }
        let mut key = Secret::<[u8; LEN]>::new();
        fill_bytes(rng, &mut *key)?;
        encrypt::<K, H, M, N>(self.pk, self.params.label, &*key, rng, ct)?;
        if let Err(e) = key_into(&*key, RSAES_OAEP::<K, H, M>::STRENGTH, ss) {
            ct.fill(0);
            return Err(e.into());
        }
        Ok(N)
    }
}

/// The worker [`DecapsulatingKey::create_decapsulator`] hands out under [`OaepParams`]: the
/// private key, borrowed, and the parameters.
pub struct RsaOaepDecapsulator<'k, 'l, K: RsaSize, H, M, const LEN: usize> {
    sk: &'k RsaKEMPrivateKey<K>,
    params: OaepParams<'l, H, M, LEN>,
}

impl<K: RsaSize, H: OaepHash, M: OaepHash, const LEN: usize> Algorithm
    for RsaOaepDecapsulator<'_, '_, K, H, M, LEN>
{
    const ALG_NAME: &'static str = RSAES_OAEP::<K, H, M>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = RSAES_OAEP::<K, H, M>::MAX_SECURITY_STRENGTH;
}

impl<K, H, M, const N: usize, const LEN: usize> KEMDecapsulator<N, LEN>
    for RsaOaepDecapsulator<'_, '_, K, H, M, LEN>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: OaepHash,
    M: OaepHash,
{
    /// KTS-OAEP-basic, party V (SP 800-56B Rev. 2 §9.2.3):
    /// `K = RSA-OAEP.DECRYPT(PrivKeyV, C, A)` into `ss`, zeroized first and left so on error.
    /// A recovered key that is not exactly `LEN` bytes is a decryption error like any other.
    ///
    /// # Errors
    /// [`KEMError::DecapsulationFailed`] for a decryption error of any kind.
    fn decaps_out(&self, ct: &[u8; N], ss: &mut KeyMaterial<LEN>) -> Result<usize, KEMError> {
        ss.zeroize();
        let mut key = Secret::<[u8; LEN]>::new();
        decrypt::<K, H, M, N>(self.sk, self.params.label, ct, Some(LEN), &mut *key)
            .ok_or(KEMError::DecapsulationFailed)?;
        key_into(&*key, RSAES_OAEP::<K, H, M>::STRENGTH, ss)?;
        Ok(LEN)
    }
}

impl<'l, K, H, M, const N: usize, const LEN: usize>
    EncapsulatingKey<OaepParams<'l, H, M, LEN>, N, LEN> for RsaKEMPublicKey<K>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: OaepHash,
    M: OaepHash,
{
    type Algorithm = RSAES_OAEP<K, H, M>;
    type Encapsulator<'k>
        = RsaOaepEncapsulator<'k, 'l, K, H, M, LEN>
    where
        Self: 'k;

    /// Cannot fail: the key length is checked against the modulus at compile time.
    fn create_encapsulator<'k>(
        &'k self,
        params: OaepParams<'l, H, M, LEN>,
    ) -> Result<Self::Encapsulator<'k>, KEMError> {
        const {
            assert!(LEN > 0, "a key has at least one byte");
            assert!(LEN <= RSAES_OAEP::<K, H, M>::MAX_MESSAGE_LEN, "LEN > k - 2hLen - 2");
        }
        Ok(RsaOaepEncapsulator { pk: self, params })
    }
}

impl<'l, K, H, M, const N: usize, const LEN: usize>
    DecapsulatingKey<OaepParams<'l, H, M, LEN>, N, LEN> for RsaKEMPrivateKey<K>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: OaepHash,
    M: OaepHash,
{
    type Algorithm = RSAES_OAEP<K, H, M>;
    type Decapsulator<'k>
        = RsaOaepDecapsulator<'k, 'l, K, H, M, LEN>
    where
        Self: 'k;

    /// As [`EncapsulatingKey::create_encapsulator`]: cannot fail.
    fn create_decapsulator<'k>(
        &'k self,
        params: OaepParams<'l, H, M, LEN>,
    ) -> Result<Self::Decapsulator<'k>, KEMError> {
        const {
            assert!(LEN > 0, "a key has at least one byte");
            assert!(LEN <= RSAES_OAEP::<K, H, M>::MAX_MESSAGE_LEN, "LEN > k - 2hLen - 2");
        }
        Ok(RsaOaepDecapsulator { sk: self, params })
    }
}

/// Transport of a key the caller holds: `C = RSA-OAEP.ENCRYPT(PubKeyV, K, A)` (SP 800-56B Rev. 2
/// §9.2.3, party U). The parameters' `LEN` is not used: the key's own length is.
impl<'l, K, H, M, const N: usize, const LEN: usize>
    KeyTransportEncryptingKey<OaepParams<'l, H, M, LEN>, N> for RsaKEMPublicKey<K>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: OaepHash,
    M: OaepHash,
{
    type Algorithm = RSAES_OAEP<K, H, M>;

    /// `k - 2hLen - 2` (RFC 8017 §7.1.1 step 1.b).
    fn max_key_len(&self, _params: OaepParams<'l, H, M, LEN>) -> usize {
        RSAES_OAEP::<K, H, M>::MAX_MESSAGE_LEN
    }

    fn transport_out(
        &self,
        rng: &mut dyn RNG,
        params: OaepParams<'l, H, M, LEN>,
        key: &dyn KeyMaterialTrait,
        ct: &mut [u8; N],
    ) -> Result<usize, KeyTransportError> {
        ct.fill(0);
        if key.key_type() == KeyType::Zeroized {
            return Err(KeyMaterialError::ActingOnZeroizedKey.into());
        }
        // RFC 8017 §7.1.1 step 1.b: "If mLen > k - 2hLen - 2, output "message too long" and
        // stop."
        if key.key_len() > RSAES_OAEP::<K, H, M>::MAX_MESSAGE_LEN {
            return Err(KeyTransportError::KeyTooLong);
        }
        if rng.security_strength() < RSAES_OAEP::<K, H, M>::STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
        }
        encrypt::<K, H, M, N>(self, params.label, key.ref_to_bytes(), rng, ct)?;
        Ok(N)
    }
}

/// Recovery of a transported key: `K = RSA-OAEP.DECRYPT(PrivKeyV, C, A)` (SP 800-56B Rev. 2
/// §9.2.3, party V). The parameters' `LEN` is not used: the key is as long as it was sent.
impl<'l, K, H, M, const N: usize, const LEN: usize>
    KeyTransportDecryptingKey<OaepParams<'l, H, M, LEN>, N> for RsaKEMPrivateKey<K>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: OaepHash,
    M: OaepHash,
{
    type Algorithm = RSAES_OAEP<K, H, M>;

    fn recover_out<const KEY_LEN: usize>(
        &self,
        ct: &[u8; N],
        params: OaepParams<'l, H, M, LEN>,
        key: &mut KeyMaterial<KEY_LEN>,
    ) -> Result<usize, KeyTransportError> {
        key.zeroize();
        let mut bytes = Secret::<[u8; KEY_LEN]>::new();
        let len = decrypt::<K, H, M, N>(self, params.label, ct, None, &mut *bytes)
            .ok_or(KeyTransportError::DecryptionFailed)?;
        key_into(&bytes[..len], RSAES_OAEP::<K, H, M>::STRENGTH, key)?;
        Ok(len)
    }
}
