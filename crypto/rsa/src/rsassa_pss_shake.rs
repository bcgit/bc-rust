//! RSASSA-PSS with SHAKE128 or SHAKE256 as both the hash and the (native, non-MGF1) mask
//! generation function -- `id-RSASSA-PSS-SHAKE128`/`id-RSASSA-PSS-SHAKE256` (RFC 8702 §3.2.1).
//! Otherwise identical to [`crate::rsassa_pss`] (RFC 8017 §8.1): same RSASP1/RSAVP1
//! orchestration, same fresh-salt-per-signature approach, just built on `emsa_pss_shake` in
//! place of `emsa_pss` -- and the same [`RSASSA_PSS_SHAKE`] marker over `*_from_hash`
//! functions, with `X: XOF` in place of `H: Hash`.

use crate::emsa_pss_shake::{emsa_pss_encode_shake_from_hash, emsa_pss_verify_shake_from_hash};
use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::mgf1::MAX_HASH_LEN;
use crate::rsa_core::{rsasp1, rsavp1};
use crate::size::{RsaSigningSize, RsaSize, min_strength};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{SignatureAlgorithm, SigningKey, VerifyingKey};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, HashAlgParams, HashOneShot, RNG, SignatureSigner, SignatureVerifier,
    XOF,
};
use bouncycastle_utils::const_str::ConstStr;
use core::marker::PhantomData;

/// RSASSA-PSS with a SHAKE XOF `X` as both hash and mask (RFC 8702 §3.2.1), at the modulus size `K`: the algorithm marker the key role traits are implemented
/// over, named `RSASSA-PSS-<hash>` (`RSASSA-PSS-SHAKE128`), at the lesser of the size's and the hash's
/// strength. [`RsaPrivateKey`] signs through [`SigningKey`] at a signing size: a fresh salt, one
/// hash output long, from the caller's RNG per signer (EMSA-PSS-ENCODE step 4), so two
/// signatures of one message differ. [`RsaPublicKey`] verifies through [`VerifyingKey`] at any
/// size. One key type serves every scheme and hash, so a call names the marker:
/// `SigningKey::<rsa_2048::RSASSA_PSS_SHAKE_SHAKE128, 256>::sign(&sk, ..)`. `ctx` is accepted and
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

/// The signer [`SigningKey::create_signer`] hands out: the key, borrowed, the running hash and
/// the salt (the first `X::OUTPUT_LEN` bytes of the buffer).
pub struct RsaPssShakeSigner<'k, K: RsaSize, X> {
    sk: &'k RsaPrivateKey<K>,
    hash: X,
    salt: [u8; MAX_HASH_LEN],
}

impl<K: RsaSize, X: XOF + HashOneShot + HashAlgParams> RsaPssShakeSigner<'_, K, X> {
    /// Replaces the salt drawn when the signer was created, for a known-answer test; `N` must be
    /// the hash's output length, which is checked when the call is compiled.
    pub fn set_salt<const N: usize>(&mut self, salt: [u8; N]) {
        const { assert!(N == X::OUTPUT_LEN, "the PSS salt is one hash output long") };
        self.salt[..N].copy_from_slice(&salt);
    }
}

/// The verifier [`VerifyingKey::create_verifier`] hands out: the key, borrowed, and the running
/// hash.
pub struct RsaPssShakeVerifier<'k, K: RsaSize, X> {
    pk: &'k RsaPublicKey<K>,
    hash: X,
}

impl<K, X, const K_LEN: usize> SigningKey<RSASSA_PSS_SHAKE<K, X>, K_LEN> for RsaPrivateKey<K>
where
    // Only a signing size signs: the verify-only sizes, RSA-1024/1536, do not implement
    // RsaSigningSize, so this impl does not exist for them -- the crate's `# Scope` at compile
    // time.
    K: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
    X: XOF + HashOneShot + HashAlgParams,
{
    type Signer<'k>
        = RsaPssShakeSigner<'k, K, X>
    where
        Self: 'k;

    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        // EMSA-PSS-ENCODE step 4's salt, drawn when the signer is created, as ECDSA draws `k`.
        let mut salt = [0u8; MAX_HASH_LEN];
        rng.next_bytes_out(&mut salt[..X::OUTPUT_LEN]).map_err(SignatureError::RNGError)?;
        Ok(RsaPssShakeSigner { sk: self, hash: X::default(), salt })
    }
}

impl<K, X, const K_LEN: usize> VerifyingKey<RSASSA_PSS_SHAKE<K, X>, K_LEN> for RsaPublicKey<K>
where
    K: RsaSize<Modulus = [u8; K_LEN]>,
    X: XOF + HashOneShot + HashAlgParams,
{
    type Verifier<'k>
        = RsaPssShakeVerifier<'k, K, X>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        Ok(RsaPssShakeVerifier { pk: self, hash: X::default() })
    }
}

impl<K: RsaSize, X: HashAlgParams> AlgorithmInfo for RsaPssShakeSigner<'_, K, X> {
    fn alg_name(&self) -> &'static str {
        RSASSA_PSS_SHAKE::<K, X>::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        RSASSA_PSS_SHAKE::<K, X>::MAX_SECURITY_STRENGTH
    }
}

impl<K, X, const K_LEN: usize> SignatureSigner<K_LEN> for RsaPssShakeSigner<'_, K, X>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
    X: XOF + HashOneShot + HashAlgParams,
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; K_LEN], SignatureError> {
        let mut m_hash = [0u8; MAX_HASH_LEN];
        self.hash.do_final_out(&mut m_hash[..X::OUTPUT_LEN]);
        sign_from_hash_with_salt::<K, X, K_LEN>(
            self.sk,
            &m_hash[..X::OUTPUT_LEN],
            &self.salt[..X::OUTPUT_LEN],
        )
    }

    fn do_final_out(self, output: &mut [u8; K_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(K_LEN)
    }
}

impl<K: RsaSize, X: HashAlgParams> AlgorithmInfo for RsaPssShakeVerifier<'_, K, X> {
    fn alg_name(&self) -> &'static str {
        RSASSA_PSS_SHAKE::<K, X>::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        RSASSA_PSS_SHAKE::<K, X>::MAX_SECURITY_STRENGTH
    }
}

impl<K, X, const K_LEN: usize> SignatureVerifier for RsaPssShakeVerifier<'_, K, X>
where
    K: RsaSize<Modulus = [u8; K_LEN]>,
    X: XOF + HashOneShot + HashAlgParams,
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        // RFC 8017 §8.1.2 step 1: a signature of the wrong length is rejected for its length.
        let sig: &[u8; K_LEN] = sig.try_into().map_err(|_| {
            SignatureError::LengthError("RSA signature must be exactly the modulus length")
        })?;
        let mut m_hash = [0u8; MAX_HASH_LEN];
        self.hash.do_final_out(&mut m_hash[..X::OUTPUT_LEN]);
        verify_from_hash::<K, X, K_LEN>(self.pk, &m_hash[..X::OUTPUT_LEN], sig)
            .map_err(|_| SignatureError::SignatureVerificationFailed)
    }
}

/// RSASSA-PSS-SIGN (RFC 8017 §8.1.1) from the message hash (`X::OUTPUT_LEN` bytes) with the
/// salt given (the same length): the EMSA-PSS encoding, then RSASP1. The known-answer entry
/// point; [`sign_from_hash`] draws the salt.
///
/// # Errors
/// [`SignatureError::DecodingError`] if the encoded message is not below `n`, which the
/// encoding's cleared top bit rules out.
pub fn sign_from_hash_with_salt<K, X, const K_LEN: usize>(
    sk: &RsaPrivateKey<K>,
    m_hash: &[u8],
    salt: &[u8],
) -> Result<[u8; K_LEN], SignatureError>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
    X: XOF + HashOneShot + HashAlgParams,
{
    let em = emsa_pss_encode_shake_from_hash::<X, K_LEN>(m_hash, salt);
    let m = K::limbs_from_be_bytes(&em);
    let s = rsasp1::<K>(sk, &m)?;
    Ok(K::be_bytes_from_limbs(&s))
}

/// RSASSA-PSS-SIGN (RFC 8017 §8.1.1) from the message hash, with a fresh salt of one hash
/// output drawn from `rng` (EMSA-PSS-ENCODE step 4).
///
/// # Errors
/// [`SignatureError::RNGError`] if the RNG fails to deliver; otherwise as
/// [`sign_from_hash_with_salt`].
pub fn sign_from_hash<K, X, const K_LEN: usize>(
    sk: &RsaPrivateKey<K>,
    m_hash: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; K_LEN], SignatureError>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
    X: XOF + HashOneShot + HashAlgParams,
{
    let mut salt = [0u8; MAX_HASH_LEN];
    rng.next_bytes_out(&mut salt[..X::OUTPUT_LEN]).map_err(SignatureError::RNGError)?;
    sign_from_hash_with_salt::<K, X, K_LEN>(sk, m_hash, &salt[..X::OUTPUT_LEN])
}

/// RSASSA-PSS-VERIFY (RFC 8017 §8.1.2) from the message hash: RSAVP1, then the EMSA-PSS
/// verification against `m_hash`.
///
/// # Errors
/// [`SignatureError::DecodingError`] for a signature representative not below `n` (step 2.b's
/// "invalid signature" from RSAVP1), [`SignatureError::SignatureVerificationFailed`] for an
/// encoding that does not verify.
pub fn verify_from_hash<K, X, const K_LEN: usize>(
    pk: &RsaPublicKey<K>,
    m_hash: &[u8],
    signature: &[u8; K_LEN],
) -> Result<(), SignatureError>
where
    K: RsaSize<Modulus = [u8; K_LEN]>,
    X: XOF + HashOneShot + HashAlgParams,
{
    let s = K::limbs_from_be_bytes(signature);
    let m = rsavp1::<K>(pk, &s)?;
    let em = K::be_bytes_from_limbs(&m);
    if emsa_pss_verify_shake_from_hash::<X, K_LEN>(m_hash, &em) {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}
