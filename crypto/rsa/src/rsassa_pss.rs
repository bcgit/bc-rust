//! RSASSA-PSS (RFC 8017 §8.1) over the modulus size `K` ([`RsaSize`]) and the hash `H` (also
//! MGF1's hash): [`RSASSA_PSS<K, H>`] is the algorithm marker a key names, named
//! `RSASSA-PSS-<hash>` at the lesser of the size's and the hash's strength, and its
//! [`RsaRandomizedSignatureAlgorithm`] impl is `emsa_pss`'s probabilistic encoding, the salt one
//! hash output long (RFC 8017 §9.1 note 4's "typical" choice); the keys, the workers (with
//! `set_salt` for a known answer) and the `*_from_hash` entry points are [`crate::rsassa`]'s,
//! once over every algorithm.

use crate::emsa_pss::{emsa_pss_encode_from_hash, emsa_pss_verify_from_hash};
use crate::rsassa::{RsaRandomizedSignatureAlgorithm, RsaSignatureAlgorithm};
use crate::size::{RsaSize, min_strength};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::SignatureAlgorithm;
use bouncycastle_core::traits::{Algorithm, HashAlgParams, HashOneShot};
use bouncycastle_utils::const_str::ConstStr;
use core::marker::PhantomData;

/// RSASSA-PSS (RFC 8017 §8.1) over the hash `H`, with MGF1 over `H`, at the modulus size `K`: the algorithm marker the key role traits are implemented
/// over, named `RSASSA-PSS-<hash>` (`RSASSA-PSS-SHA256`), at the lesser of the size's and the hash's
/// strength. [`RsaPrivateKey`](crate::keys::RsaPrivateKey) signs through [`SigningKey`](bouncycastle_core::signature_key::SigningKey) at a signing size: a fresh salt, one
/// hash output long, from the caller's RNG per signer (EMSA-PSS-ENCODE step 4), so two
/// signatures of one message differ. [`RsaPublicKey`](crate::keys::RsaPublicKey) verifies through [`VerifyingKey`](bouncycastle_core::signature_key::VerifyingKey) at any
/// size. One key type serves every scheme and hash, so a call names the marker:
/// a key over it signs through `SigningKey`, `sk.sign(&mut rng, msg, None)`. `ctx` is accepted and
/// ignored, since RSA has no context string.
#[allow(non_camel_case_types)]
pub struct RSASSA_PSS<K: RsaSize, H> {
    _params: PhantomData<(K, H)>,
}

impl<K: RsaSize, H: HashAlgParams> RSASSA_PSS<K, H> {
    const NAME: ConstStr<40> = ConstStr::concat(&["RSASSA-PSS-", H::ALG_NAME]);
}

impl<K: RsaSize, H: HashAlgParams> Algorithm for RSASSA_PSS<K, H> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        min_strength(K::STRENGTH, H::MAX_SECURITY_STRENGTH);
}

impl<K: RsaSize, H: HashAlgParams> SignatureAlgorithm for RSASSA_PSS<K, H> {}

impl<K: RsaSize, H: HashOneShot + HashAlgParams> RsaSignatureAlgorithm for RSASSA_PSS<K, H> {
    type Size = K;
    type Hash = H;

    fn emsa_verify<const K_LEN: usize>(m_hash: &[u8], em: &[u8; K_LEN]) -> bool {
        emsa_pss_verify_from_hash::<H, K_LEN>(m_hash, em)
    }
}

impl<K: RsaSize, H: HashOneShot + HashAlgParams> RsaRandomizedSignatureAlgorithm
    for RSASSA_PSS<K, H>
{
    fn emsa_encode<const K_LEN: usize>(m_hash: &[u8], salt: &[u8]) -> [u8; K_LEN] {
        emsa_pss_encode_from_hash::<H, K_LEN>(m_hash, salt)
    }
}
