//! RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) over the modulus size `K` ([`RsaSize`]) and the hash `H`:
//! [`RSASSA_PKCS1_v1_5<K, H>`] is the algorithm marker a key names, named
//! `RSASSA-PKCS1-v1_5-<hash>` at the lesser of the size's and the hash's strength, and its
//! [`RsaDeterministicSignatureAlgorithm`] impl is `emsa_pkcs1_v1_5`'s deterministic encoding;
//! the keys, the workers and the `*_from_hash` entry points are [`crate::rsa::rsassa`]'s, once over
//! every algorithm.

use crate::rsa::emsa_pkcs1_v1_5::{
    emsa_pkcs1_v1_5_encode_from_hash, emsa_pkcs1_v1_5_verify_from_hash,
};
use crate::rsa::rsassa::{RsaDeterministicSignatureAlgorithm, RsaSignatureAlgorithm};
use crate::rsa::size::{RsaSize, min_strength};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::SignatureAlgorithm;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, CollisionResistantHash, HashAlgParams, HashOneShot,
};
use bouncycastle_utils::const_str::ConstStr;
use core::marker::PhantomData;

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) over the hash `H` at the modulus size `K`: the algorithm
/// marker the key role traits are implemented over, named `RSASSA-PKCS1-v1_5-<hash>`
/// (`RSASSA-PKCS1-v1_5-SHA256`), at the lesser of the size's and the hash's strength.
/// [`RsaPrivateKey`](crate::rsa::keys::RsaPrivateKey) signs through [`DeterministicSigningKey`](bouncycastle_core::signature_key::DeterministicSigningKey) at a signing size: PKCS#1 v1.5
/// draws nothing, so the same key and message always give the same signature.
/// [`RsaPublicKey`](crate::rsa::keys::RsaPublicKey) verifies through [`VerifyingKey`](bouncycastle_core::signature_key::VerifyingKey) at any size. The key names
/// the marker, so a call names nothing: `sk.sign_deterministic(msg, None)`.
/// `ctx` must be `None` or empty, since RSA has no context: a non-empty one is a
/// [`SignatureError::LengthError`] from signing and from verification.
///
/// Signing requires a [`CollisionResistantHash`]; verification does not. A key over SHA-1
/// verifies and does not sign:
///
/// ```compile_fail,E0277
/// use bouncycastle_core::signature_key::DeterministicOneShotSigningKey;
/// use bouncycastle_modexp::rsa::RSA2048;
/// use bouncycastle_modexp::rsa::keys::RsaPrivateComponents;
/// use bouncycastle_modexp::rsa::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
/// use bouncycastle_digest::sha1::SHA1;
///
/// let z = [0u64; 16];
/// let sk = RsaPrivateComponents::<RSA2048>::from_crt_components(&z, &z, &z, &z, &z, 65537).unwrap();
/// let sk = sk.key::<RSASSA_PKCS1_v1_5<RSA2048, SHA1>>();
/// let _ = DeterministicOneShotSigningKey::<RSASSA_PKCS1_v1_5<RSA2048, SHA1>, 256>::sign_deterministic(
///     &sk, b"message", None,
/// );
/// ```
///
/// A caller who must make such a signature names the hash as
/// [`WithoutCollisionResistance<SHA1>`](bouncycastle_core::hazmat::WithoutCollisionResistance).
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
        const { assert!(K_LEN == K::K_LEN, "K_LEN is the size's modulus length") };
        emsa_pkcs1_v1_5_verify_from_hash::<H, K_LEN>(m_hash, em)
    }
}

impl<K: RsaSize, H: HashOneShot + HashAlgParams + AlgorithmOID + CollisionResistantHash>
    RsaDeterministicSignatureAlgorithm for RSASSA_PKCS1_v1_5<K, H>
{
    fn emsa_encode<const K_LEN: usize>(m_hash: &[u8]) -> Result<[u8; K_LEN], SignatureError> {
        const { assert!(K_LEN == K::K_LEN, "K_LEN is the size's modulus length") };
        emsa_pkcs1_v1_5_encode_from_hash::<H, K_LEN>(m_hash)
    }
}
