//! RSASSA-PSS with SHAKE128 or SHAKE256 as both the hash and the (native, non-MGF1) mask
//! generation function, `id-RSASSA-PSS-SHAKE128` / `id-RSASSA-PSS-SHAKE256` (RFC 8702 §3.2.1),
//! over the modulus size `K` ([`RsaSize`]) and the XOF `X`: [`RSASSA_PSS_SHAKE<K, X>`] is the
//! algorithm marker a key names, named `RSASSA-PSS-<xof>`, and its
//! [`RsaRandomizedSignatureAlgorithm`] impl is `emsa_pss_shake`'s encoding in place of
//! [`crate::rsassa_pss`]'s; the keys, the workers and the `*_from_hash` entry points are
//! [`crate::rsassa`]'s, once over every algorithm.

use crate::emsa_pss_shake::{emsa_pss_encode_shake_from_hash, emsa_pss_verify_shake_from_hash};
use crate::rsassa::{RsaRandomizedSignatureAlgorithm, RsaSignatureAlgorithm};
use crate::size::{RsaSize, min_strength};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::SignatureAlgorithm;
use bouncycastle_core::traits::{Algorithm, HashAlgParams, HashOneShot, XOF};
use bouncycastle_utils::const_str::ConstStr;
use core::marker::PhantomData;

/// RSASSA-PSS with a SHAKE XOF `X` as both hash and mask (RFC 8702 §3.2.1), at the modulus size `K`: the algorithm marker the key role traits are implemented
/// over, named `RSASSA-PSS-<hash>` (`RSASSA-PSS-SHAKE128`), at the lesser of the size's and the hash's
/// strength. [`RsaPrivateKey`](crate::keys::RsaPrivateKey) signs through [`SigningKey`](bouncycastle_core::signature_key::SigningKey) at a signing size: a fresh salt, one
/// hash output long, from the caller's RNG per signer (EMSA-PSS-ENCODE step 4), so two
/// signatures of one message differ. [`RsaPublicKey`](crate::keys::RsaPublicKey) verifies through [`VerifyingKey`](bouncycastle_core::signature_key::VerifyingKey) at any
/// size. One key type serves every scheme and hash, so a call names the marker:
/// a key over it signs through `SigningKey`, `sk.sign(&mut rng, msg, None)`. `ctx` is accepted and
/// ignored, since RSA has no context string.
#[allow(non_camel_case_types)]
pub struct RSASSA_PSS_SHAKE<K: RsaSize, X> {
    _params: PhantomData<(K, X)>,
}

impl<K: RsaSize, X: HashAlgParams> RSASSA_PSS_SHAKE<K, X> {
    const NAME: ConstStr<40> = ConstStr::concat(&["RSASSA-PSS-", X::ALG_NAME]);
}

impl<K: RsaSize, X: HashAlgParams> Algorithm for RSASSA_PSS_SHAKE<K, X> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        min_strength(K::STRENGTH, X::MAX_SECURITY_STRENGTH);
}

impl<K: RsaSize, X: HashAlgParams> SignatureAlgorithm for RSASSA_PSS_SHAKE<K, X> {}

impl<K: RsaSize, X: XOF + HashOneShot + HashAlgParams> RsaSignatureAlgorithm
    for RSASSA_PSS_SHAKE<K, X>
{
    type Size = K;
    type Hash = X;

    fn emsa_verify<const K_LEN: usize>(m_hash: &[u8], em: &[u8; K_LEN]) -> bool {
        emsa_pss_verify_shake_from_hash::<X, K_LEN>(m_hash, em)
    }
}

impl<K: RsaSize, X: XOF + HashOneShot + HashAlgParams> RsaRandomizedSignatureAlgorithm
    for RSASSA_PSS_SHAKE<K, X>
{
    fn emsa_encode<const K_LEN: usize>(m_hash: &[u8], salt: &[u8]) -> [u8; K_LEN] {
        emsa_pss_encode_shake_from_hash::<X, K_LEN>(m_hash, salt)
    }
}
