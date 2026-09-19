//! RSASSA-PSS (RFC 8017 §8.1): sign and verify, built on [`crate::rsa_core`]'s RSASP1/RSAVP1 and
//! [`crate::emsa_pss`]'s probabilistic encoding. Generic over the same width parameters as
//! [`crate::rsassa_pkcs1_v1_5`] plus PSS's own `S_LEN` (salt length) and `M_PRIME_LEN`
//! (`8 + H_LEN + S_LEN`); a concrete modulus size wires these to literals (RSA-2048/SHA-256 in
//! [`crate::rsa_2048`]).

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use crate::emsa_pss::{emsa_pss_encode, emsa_pss_verify};
use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsa_core::{rsasp1, rsavp1};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{Hash, RNG};

/// RSASSA-PSS-SIGN (RFC 8017 §8.1.1) with the salt supplied directly rather than drawn from an
/// RNG: EMSA-PSS is randomized only in its choice of salt (§9.1's own note 5), so fixing it makes
/// this deterministic and directly testable against a known salt. [`sign`] is the RNG-backed
/// entry point real callers want.
pub fn sign_with_salt<
    H: Hash + Default,
    const H_LEN: usize,
    const SEED_LEN: usize,
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
    let em =
        emsa_pss_encode::<H, H_LEN, SEED_LEN, S_LEN, M_PRIME_LEN, DB_LEN, K_LEN>(message, salt);
    let m = limbs_from_be_bytes::<L, K_LEN>(&em);
    let s = rsasp1::<L, L2, L21, HALF, HALF2, HALF21>(sk, &m)?;
    Ok(be_bytes_from_limbs::<L, K_LEN>(&s))
}

/// RSASSA-PSS-SIGN (RFC 8017 §8.1.1), drawing a fresh `S_LEN`-byte salt from `rng` for each
/// signature (step 4 of EMSA-PSS-ENCODE).
pub fn sign<
    H: Hash + Default,
    const H_LEN: usize,
    const SEED_LEN: usize,
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
    let mut salt = [0u8; S_LEN];
    rng.next_bytes_out(&mut salt).map_err(SignatureError::RNGError)?;
    sign_with_salt::<
        H,
        H_LEN,
        SEED_LEN,
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
    >(sk, message, &salt)
}

/// RSASSA-PSS-VERIFY (RFC 8017 §8.1.2): recovers `EM = I2OSP(RSAVP1((n, e), OS2IP(S)), emLen)`
/// and checks it against `message` via [`emsa_pss_verify`], which recovers the salt from `EM`
/// itself (EMSA-PSS's own verification operation, §9.1.2) rather than needing it supplied.
pub fn verify<
    H: Hash + Default,
    const H_LEN: usize,
    const SEED_LEN: usize,
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
    let s = limbs_from_be_bytes::<L, K_LEN>(signature);
    let m = rsavp1::<L, L2, L21>(pk, &s)?;
    let em = be_bytes_from_limbs::<L, K_LEN>(&m);

    if emsa_pss_verify::<H, H_LEN, SEED_LEN, S_LEN, M_PRIME_LEN, DB_LEN, K_LEN>(message, &em) {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}
