//! RSASSA-PSS with SHAKE128 or SHAKE256 as both the hash and the (native, non-MGF1) mask
//! generation function -- `id-RSASSA-PSS-SHAKE128`/`id-RSASSA-PSS-SHAKE256` (RFC 8702 §3.2.1).
//! Otherwise identical to [`crate::rsassa_pss`] (RFC 8017 §8.1): same RSASP1/RSAVP1 orchestration,
//! same fresh-salt-per-signature approach, just built on [`crate::emsa_pss_shake`] in place of
//! [`crate::emsa_pss`].

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use crate::emsa_pss_shake::{emsa_pss_encode_shake_from_hash, emsa_pss_verify_shake_from_hash};
use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsa_core::{rsasp1, rsavp1};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, XOF};

/// RSASSA-PSS-SIGN (RFC 8017 §8.1.1) with the salt supplied directly rather than drawn from an
/// RNG, mirroring [`crate::rsassa_pss::sign_with_salt`]: EMSA-PSS is randomized only in its choice
/// of salt, so fixing it makes this deterministic and directly testable. [`sign`] is the
/// RNG-backed entry point real callers want. Hashes `message` (EMSA-PSS step 2) and hands `mHash`
/// to [`sign_from_hash_with_salt`].
pub fn sign_with_salt<
    X: XOF + Default,
    const H_LEN: usize,
    const S_LEN: usize,
    const M_PRIME_LEN: usize,
    const DB_LEN: usize,
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
    const K_LEN: usize,
>(
    sk: &RsaPrivateKey<L, HALF>,
    message: &[u8],
    salt: &[u8; S_LEN],
) -> Result<[u8; K_LEN], SignatureError> {
    let mut m_hash = [0u8; H_LEN];
    X::default().hash_out(message, &mut m_hash);
    sign_from_hash_with_salt::<
        X,
        H_LEN,
        S_LEN,
        M_PRIME_LEN,
        DB_LEN,
        L,
        L2,
        L21,
        HALF,
        HALF2,
        HALF21,
        K_LEN,
    >(sk, &m_hash, salt)
}

/// [`sign_with_salt`] given the message's hash `m_hash` (`X`'s `H_LEN`-byte output over the
/// message) instead of the message itself -- for a caller that hashed the message incrementally,
/// such as a streaming `Signer`.
pub fn sign_from_hash_with_salt<
    X: XOF + Default,
    const H_LEN: usize,
    const S_LEN: usize,
    const M_PRIME_LEN: usize,
    const DB_LEN: usize,
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
    const K_LEN: usize,
>(
    sk: &RsaPrivateKey<L, HALF>,
    m_hash: &[u8; H_LEN],
    salt: &[u8; S_LEN],
) -> Result<[u8; K_LEN], SignatureError> {
    let em = emsa_pss_encode_shake_from_hash::<X, H_LEN, S_LEN, M_PRIME_LEN, DB_LEN, K_LEN>(
        m_hash, salt,
    );
    let m = limbs_from_be_bytes::<L, K_LEN>(&em);
    let s = rsasp1::<L, L2, L21, HALF, HALF2, HALF21>(sk, &m)?;
    Ok(be_bytes_from_limbs::<L, K_LEN>(&s))
}

/// RSASSA-PSS-SIGN (RFC 8017 §8.1.1), drawing a fresh `S_LEN`-byte salt from `rng` for each
/// signature (step 4 of EMSA-PSS-ENCODE). RFC 8702 §3.2.1 fixes `S_LEN` at 32 bytes for
/// `id-RSASSA-PSS-SHAKE128` and 64 for `id-RSASSA-PSS-SHAKE256`. Hashes `message` and hands
/// `mHash` to [`sign_from_hash`].
pub fn sign<
    X: XOF + Default,
    const H_LEN: usize,
    const S_LEN: usize,
    const M_PRIME_LEN: usize,
    const DB_LEN: usize,
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
    const K_LEN: usize,
>(
    sk: &RsaPrivateKey<L, HALF>,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; K_LEN], SignatureError> {
    let mut m_hash = [0u8; H_LEN];
    X::default().hash_out(message, &mut m_hash);
    sign_from_hash::<X, H_LEN, S_LEN, M_PRIME_LEN, DB_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN>(
        sk, &m_hash, rng,
    )
}

/// [`sign`] given the message's hash `m_hash` instead of the message: draws the salt from `rng`
/// (EMSA-PSS-ENCODE step 4) and hands both to [`sign_from_hash_with_salt`].
pub fn sign_from_hash<
    X: XOF + Default,
    const H_LEN: usize,
    const S_LEN: usize,
    const M_PRIME_LEN: usize,
    const DB_LEN: usize,
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
    const K_LEN: usize,
>(
    sk: &RsaPrivateKey<L, HALF>,
    m_hash: &[u8; H_LEN],
    rng: &mut dyn RNG,
) -> Result<[u8; K_LEN], SignatureError> {
    let mut salt = [0u8; S_LEN];
    rng.next_bytes_out(&mut salt).map_err(SignatureError::RNGError)?;
    sign_from_hash_with_salt::<
        X,
        H_LEN,
        S_LEN,
        M_PRIME_LEN,
        DB_LEN,
        L,
        L2,
        L21,
        HALF,
        HALF2,
        HALF21,
        K_LEN,
    >(sk, m_hash, &salt)
}

/// RSASSA-PSS-VERIFY (RFC 8017 §8.1.2), mirroring [`crate::rsassa_pss::verify`] but built on the
/// SHAKE-native EMSA-PSS-VERIFY, which recovers the salt from `EM` itself. Hashes `message` and
/// hands `mHash` to [`verify_from_hash`].
pub fn verify<
    X: XOF + Default,
    const H_LEN: usize,
    const S_LEN: usize,
    const M_PRIME_LEN: usize,
    const DB_LEN: usize,
    const L: usize,
    const L2: usize,
    const L21: usize,
    const K_LEN: usize,
>(
    pk: &RsaPublicKey<L>,
    message: &[u8],
    signature: &[u8; K_LEN],
) -> Result<(), SignatureError> {
    let mut m_hash = [0u8; H_LEN];
    X::default().hash_out(message, &mut m_hash);
    verify_from_hash::<X, H_LEN, S_LEN, M_PRIME_LEN, DB_LEN, L, L2, L21, K_LEN>(
        pk, &m_hash, signature,
    )
}

/// [`verify`] given the message's hash `m_hash` instead of the message -- the counterpart of
/// [`sign_from_hash`], for a streaming `SignatureVerifier`.
pub fn verify_from_hash<
    X: XOF + Default,
    const H_LEN: usize,
    const S_LEN: usize,
    const M_PRIME_LEN: usize,
    const DB_LEN: usize,
    const L: usize,
    const L2: usize,
    const L21: usize,
    const K_LEN: usize,
>(
    pk: &RsaPublicKey<L>,
    m_hash: &[u8; H_LEN],
    signature: &[u8; K_LEN],
) -> Result<(), SignatureError> {
    let s = limbs_from_be_bytes::<L, K_LEN>(signature);
    let m = rsavp1::<L, L2, L21>(pk, &s)?;
    let em = be_bytes_from_limbs::<L, K_LEN>(&m);

    if emsa_pss_verify_shake_from_hash::<X, H_LEN, S_LEN, M_PRIME_LEN, DB_LEN, K_LEN>(m_hash, &em) {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}
