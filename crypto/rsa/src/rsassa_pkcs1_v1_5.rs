//! RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) over the modulus size `K` ([`RsaSize`]) and the hash `H`:
//! [`RSASSA_PKCS1_v1_5<K, H>`] is the algorithm marker a key names, named
//! `RSASSA-PKCS1-v1_5-<hash>` at the lesser of the size's and the hash's strength, and its
//! [`RsaDeterministicSignatureAlgorithm`] impl is `emsa_pkcs1_v1_5`'s deterministic encoding;
//! the keys, the workers and the `*_from_hash` entry points are [`crate::rsassa`]'s, once over
//! every algorithm.

use crate::emsa_pkcs1_v1_5::{emsa_pkcs1_v1_5_encode_from_hash, emsa_pkcs1_v1_5_verify_from_hash};
use crate::rsassa::{RsaDeterministicSignatureAlgorithm, RsaSignatureAlgorithm};
use crate::size::{RsaSize, min_strength};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::SignatureAlgorithm;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams, HashOneShot};
use bouncycastle_utils::const_str::ConstStr;
use core::marker::PhantomData;

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) over the hash `H` at the modulus size `K`: the algorithm
/// marker the key role traits are implemented over, named `RSASSA-PKCS1-v1_5-<hash>`
/// (`RSASSA-PKCS1-v1_5-SHA256`), at the lesser of the size's and the hash's strength.
/// [`RsaPrivateKey`](crate::keys::RsaPrivateKey) signs through [`DeterministicSigningKey`](bouncycastle_core::signature_key::DeterministicSigningKey) at a signing size: PKCS#1 v1.5
/// draws nothing, so the same key and message always give the same signature.
/// [`RsaPublicKey`](crate::keys::RsaPublicKey) verifies through [`VerifyingKey`](bouncycastle_core::signature_key::VerifyingKey) at any size. One key type serves every
/// scheme and hash, so a call names the marker:
/// a key over it signs through `DeterministicSigningKey`, `sk.sign_deterministic(msg, None)`.
/// `ctx` is accepted and ignored, since RSA has no context string.
#[allow(non_camel_case_types)]
pub struct RSASSA_PKCS1_v1_5<K: RsaSize, H> {
    _params: PhantomData<(K, H)>,
}

impl<K: RsaSize, H: HashAlgParams> RSASSA_PKCS1_v1_5<K, H> {
    const NAME: ConstStr<40> = ConstStr::concat(&["RSASSA-PKCS1-v1_5-", H::ALG_NAME]);
}

impl<K: RsaSize, H: HashAlgParams> Algorithm for RSASSA_PKCS1_v1_5<K, H> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        min_strength(K::STRENGTH, H::MAX_SECURITY_STRENGTH);
}

impl<K: RsaSize, H: HashAlgParams> SignatureAlgorithm for RSASSA_PKCS1_v1_5<K, H> {}

impl<K: RsaSize, H: HashOneShot + HashAlgParams + AlgorithmOID> RsaSignatureAlgorithm
    for RSASSA_PKCS1_v1_5<K, H>
{
    type Size = K;
    type Hash = H;

    fn emsa_verify<const K_LEN: usize>(m_hash: &[u8], em: &[u8; K_LEN]) -> bool {
        emsa_pkcs1_v1_5_verify_from_hash::<H, K_LEN>(m_hash, em)
    }
}

impl<K: RsaSize, H: HashOneShot + HashAlgParams + AlgorithmOID> RsaDeterministicSignatureAlgorithm
    for RSASSA_PKCS1_v1_5<K, H>
{
    fn emsa_encode<const K_LEN: usize>(m_hash: &[u8]) -> [u8; K_LEN] {
        emsa_pkcs1_v1_5_encode_from_hash::<H, K_LEN>(m_hash)
    }
}
