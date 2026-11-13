//! RSASSA-PSS (RFC 8017 §8.1) over the modulus size `K` ([`RsaSize`]), the hash `H` and the
//! parameters `P` that EMSA-PSS is parameterized by beyond the hash (§9.1: the mask generation
//! function and the salt length): [`RSASSA_PSS<K, H, P>`] is the algorithm marker a key names.
//! `P` is [`Conventional`] unless spelled, what [`PssHash`] says the hash is conventionally
//! paired with: MGF1 over `H` and a salt one hash output long for SHA-2 and SHA-3, the §8.1
//! recommendation and §9.1 note 4's "typical" choice, and for SHAKE128/256 the XOF itself as
//! the mask (RFC 8702 §3.2.1), so `RSASSA_PSS<K, SHAKE128>` is RSASSA-PSS-SHAKE128;
//! [`Mgf1<M, SALT_LEN>`] spells another MGF1 hash or salt length, which §8.1 allows ("the provable security of
//! RSASSA-PSS does not rely on the hash function in the mask generation function being the same
//! as the hash function applied to the message"; matching them prevents hash substitution, which
//! a key that names its hash prevents anyway); and [`NoSalt<M>`] is the zero salt of §9.1 note 4,
//! which makes the scheme deterministic and its keys sign through `DeterministicSigningKey`. A
//! key is for one `(H, P)`, so a verifier never guesses the mask or the salt length. The keys,
//! the workers and the `*_from_hash` entry points are [`crate::rsassa`]'s, once over every
//! algorithm; the encoding is `emsa_pss`'s, once over `H` and `P`.

use crate::emsa_pss::{emsa_pss_encode_from_hash, emsa_pss_verify_from_hash};
use crate::mgf1::{MAX_HASH_LEN, mgf1};
use crate::rsassa::{
    RsaDeterministicSignatureAlgorithm, RsaRandomizedSignatureAlgorithm, RsaSignatureAlgorithm,
};
use crate::size::{RsaSize, min_strength};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::SignatureAlgorithm;
use bouncycastle_core::traits::{Algorithm, HashAlgParams, HashOneShot, XOF};
use bouncycastle_sha2::{SHA256InitValue, SHA256Internal, SHA512InitValue, SHA512Internal};
use bouncycastle_sha3::{SHA3Internal, SHA3Params, SHAKEInternal, SHAKEParams};
use bouncycastle_utils::const_str::ConstStr;
use core::marker::PhantomData;

/// A hash and how RSASSA-PSS conventionally uses it, which [`Conventional`] reads: SHA-2 and
/// SHA-3 through MGF1 over the same hash with a salt one output long (RFC 8017 §8.1, §9.1
/// note 4), SHAKE128 and SHAKE256 natively as the mask with a salt of the output length
/// RFC 8702 §3.2.1 fixes (32 and 64 bytes). Implemented for this workspace's SHA-2, SHA-3 and
/// SHAKE types; another hash takes spelled parameters, [`Mgf1`].
pub trait PssHash: HashOneShot + HashAlgParams {
    /// `sLen` under the conventional parameters.
    const SALT_LEN: usize;
    /// The conventional `MGF(seed, maskLen)`: `mask` filled from `seed`.
    fn mask(seed: &[u8], mask: &mut [u8]);
}

impl<P: SHA256InitValue> PssHash for SHA256Internal<P>
where
    Self: HashOneShot + HashAlgParams,
{
    const SALT_LEN: usize = Self::OUTPUT_LEN;

    fn mask(seed: &[u8], mask: &mut [u8]) {
        mgf1::<Self>(seed, mask);
    }
}

impl<P: SHA512InitValue> PssHash for SHA512Internal<P>
where
    Self: HashOneShot + HashAlgParams,
{
    const SALT_LEN: usize = Self::OUTPUT_LEN;

    fn mask(seed: &[u8], mask: &mut [u8]) {
        mgf1::<Self>(seed, mask);
    }
}

impl<P: SHA3Params> PssHash for SHA3Internal<P>
where
    Self: HashOneShot + HashAlgParams,
{
    const SALT_LEN: usize = Self::OUTPUT_LEN;

    fn mask(seed: &[u8], mask: &mut [u8]) {
        mgf1::<Self>(seed, mask);
    }
}

impl<P: SHAKEParams> PssHash for SHAKEInternal<P>
where
    Self: XOF + HashOneShot + HashAlgParams,
{
    const SALT_LEN: usize = Self::OUTPUT_LEN;

    fn mask(seed: &[u8], mask: &mut [u8]) {
        Self::default().xof_out(seed, mask);
    }
}

/// What EMSA-PSS is parameterized by beyond its hash `H` (RFC 8017 §9.1): the mask generation
/// function and the salt length. Implemented by [`Conventional`], [`Mgf1`] and [`NoSalt`]; a
/// caller may implement it for a mask of its own.
pub trait PssParams<H: HashAlgParams> {
    /// `sLen`, the salt length in bytes; at most 64 (`MAX_HASH_LEN`, the signer's buffer).
    const SALT_LEN: usize;
    /// What the algorithm name says after `RSASSA-PSS-<hash>`: nothing for the conventional
    /// pairing, `-MGF1-<hash>-<sLen>` for a spelled one.
    const NAME_SUFFIX: ConstStr<32>;
    /// `MGF(seed, maskLen)`: `mask` filled from `seed`.
    fn mask(seed: &[u8], mask: &mut [u8]);
}

/// The parameters whose salt is drawn: a key over them signs through `SigningKey`.
pub trait SaltedPss {}

/// The parameters with no salt: a key over them signs through `DeterministicSigningKey`.
pub trait UnsaltedPss {}

/// The hash's conventional parameters ([`PssHash`]): MGF1 over the message hash and a salt one
/// hash output long for SHA-2 and SHA-3, the XOF as the mask for SHAKE. The default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Conventional;

impl<H: PssHash> PssParams<H> for Conventional {
    const SALT_LEN: usize = H::SALT_LEN;
    const NAME_SUFFIX: ConstStr<32> = ConstStr::concat(&[]);

    fn mask(seed: &[u8], mask: &mut [u8]) {
        H::mask(seed, mask);
    }
}

impl SaltedPss for Conventional {}

/// MGF1 over `M`, which need not be the message hash, and a salt of `SALT_LEN` bytes, at least
/// one: the parameters a key made elsewhere may carry (the ASN.1 parameters of RFC 8017
/// Appendix A.2.3 name the mask's hash and the salt length separately). Named
/// `-MGF1-<M>-<SALT_LEN>`.
pub struct Mgf1<M, const SALT_LEN: usize> {
    _hash: PhantomData<M>,
}

impl<H: HashAlgParams, M: HashOneShot + HashAlgParams, const SALT_LEN: usize> PssParams<H>
    for Mgf1<M, SALT_LEN>
{
    const SALT_LEN: usize = {
        assert!(SALT_LEN > 0 && SALT_LEN <= MAX_HASH_LEN, "a drawn salt is 1 to 64 bytes");
        SALT_LEN
    };
    const NAME_SUFFIX: ConstStr<32> =
        ConstStr::concat(&["-MGF1-", M::ALG_NAME, "-", ConstStr::<8>::decimal(SALT_LEN).as_str()]);

    fn mask(seed: &[u8], mask: &mut [u8]) {
        mgf1::<M>(seed, mask);
    }
}

impl<M, const SALT_LEN: usize> SaltedPss for Mgf1<M, SALT_LEN> {}

/// MGF1 over `M` and no salt, RFC 8017 §9.1 note 4's other typical length: the encoding is a
/// function of the key and the message alone, so the keys sign through
/// `DeterministicSigningKey`. Named `-MGF1-<M>-0`.
pub struct NoSalt<M> {
    _hash: PhantomData<M>,
}

impl<H: HashAlgParams, M: HashOneShot + HashAlgParams> PssParams<H> for NoSalt<M> {
    const SALT_LEN: usize = 0;
    const NAME_SUFFIX: ConstStr<32> = ConstStr::concat(&["-MGF1-", M::ALG_NAME, "-0"]);

    fn mask(seed: &[u8], mask: &mut [u8]) {
        mgf1::<M>(seed, mask);
    }
}

impl<M> UnsaltedPss for NoSalt<M> {}

/// RSASSA-PSS over the size `K`, the hash `H` and the parameters `P` (see the module docs): the
/// algorithm marker a key names, `RSASSA-PSS-<hash>` for the conventional parameters
/// (`RSASSA-PSS-SHA256`, `RSASSA-PSS-SHAKE128`) and `RSASSA-PSS-<hash>-MGF1-<mask hash>-<sLen>`
/// for spelled ones, at the lesser of the size's and the hash's strength (§8.1: the mask's hash
/// does not enter the proof). A key over it signs through `SigningKey`,
/// `sk.sign(&mut rng, msg, None)`, or for [`NoSalt`] through `DeterministicSigningKey`,
/// `sk.sign_deterministic(msg, None)`; `ctx` is accepted and ignored, since RSA has no context
/// string.
#[allow(non_camel_case_types)]
pub struct RSASSA_PSS<K: RsaSize, H, P = Conventional> {
    _params: PhantomData<(K, H, P)>,
}

impl<K: RsaSize, H: HashAlgParams, P: PssParams<H>> RSASSA_PSS<K, H, P> {
    const NAME: ConstStr<80> =
        ConstStr::concat(&["RSASSA-PSS-", H::ALG_NAME, P::NAME_SUFFIX.as_str()]);
}

impl<K: RsaSize, H: HashAlgParams, P: PssParams<H>> Algorithm for RSASSA_PSS<K, H, P> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        min_strength(K::STRENGTH, H::MAX_SECURITY_STRENGTH);
}

impl<K: RsaSize, H: HashAlgParams, P: PssParams<H>> SignatureAlgorithm for RSASSA_PSS<K, H, P> {}

impl<K: RsaSize, H: HashOneShot + HashAlgParams, P: PssParams<H>> RsaSignatureAlgorithm
    for RSASSA_PSS<K, H, P>
{
    type Size = K;
    type Hash = H;

    fn emsa_verify<const K_LEN: usize>(m_hash: &[u8], em: &[u8; K_LEN]) -> bool {
        emsa_pss_verify_from_hash::<H, P, K_LEN>(m_hash, em)
    }
}

impl<K: RsaSize, H: HashOneShot + HashAlgParams, P: PssParams<H> + SaltedPss>
    RsaRandomizedSignatureAlgorithm for RSASSA_PSS<K, H, P>
{
    const SALT_LEN: usize = P::SALT_LEN;

    fn emsa_encode<const K_LEN: usize>(m_hash: &[u8], salt: &[u8]) -> [u8; K_LEN] {
        emsa_pss_encode_from_hash::<H, P, K_LEN>(m_hash, salt)
    }
}

impl<K: RsaSize, H: HashOneShot + HashAlgParams, P: PssParams<H> + UnsaltedPss>
    RsaDeterministicSignatureAlgorithm for RSASSA_PSS<K, H, P>
{
    fn emsa_encode<const K_LEN: usize>(m_hash: &[u8]) -> [u8; K_LEN] {
        emsa_pss_encode_from_hash::<H, P, K_LEN>(m_hash, &[])
    }
}
