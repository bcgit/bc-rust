//! RSASSA-PKCS1-v1_5 (RFC 8017 §8.2): sign and verify, built on `rsa_core`'s RSASP1/RSAVP1 and
//! `emsa_pkcs1_v1_5`'s deterministic encoding, once over the modulus size `K` ([`RsaSize`])
//! and the hash `H`. [`RSASSA_PKCS1_v1_5<K, H>`] is the algorithm marker the key role traits
//! ([`DeterministicSigningKey`], [`VerifyingKey`]) are implemented over -- one-shot and
//! streaming, with a `&[u8]`-typed signature on the verify side -- on top of
//! [`sign_from_hash`]/[`verify_from_hash`], which take the message hash rather than the message
//! and are the pre-hash entry points for a caller that has already computed it.

use crate::emsa_pkcs1_v1_5::{emsa_pkcs1_v1_5_encode_from_hash, emsa_pkcs1_v1_5_verify_from_hash};
use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::mgf1::MAX_HASH_LEN;
use crate::rsa_core::{rsasp1, rsavp1};
use crate::size::{RsaSigningSize, RsaSize, min_strength};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{DeterministicSigningKey, SignatureAlgorithm, VerifyingKey};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, AlgorithmOID, HashAlgParams, HashOneShot, SignatureSigner,
    SignatureVerifier,
};
use bouncycastle_utils::const_str::ConstStr;
use core::marker::PhantomData;

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) over the hash `H` at the modulus size `K`: the algorithm
/// marker the key role traits are implemented over, named `RSASSA-PKCS1-v1_5-<hash>`
/// (`RSASSA-PKCS1-v1_5-SHA256`), at the lesser of the size's and the hash's strength.
/// [`RsaPrivateKey`] signs through [`DeterministicSigningKey`] at a signing size: PKCS#1 v1.5
/// draws nothing, so the same key and message always give the same signature.
/// [`RsaPublicKey`] verifies through [`VerifyingKey`] at any size. One key type serves every
/// scheme and hash, so a call names the marker:
/// `DeterministicSigningKey::<rsa_2048::RSASSA_PKCS1_v1_5_SHA256, 256>::sign_deterministic(&sk, ..)`.
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

/// The signer [`DeterministicSigningKey::create_signer_deterministic`] hands out: the key,
/// borrowed, and the running hash.
pub struct RsaPkcs1v15Signer<'k, K: RsaSize, H> {
    sk: &'k RsaPrivateKey<K>,
    hash: H,
}

/// The verifier [`VerifyingKey::create_verifier`] hands out: the key, borrowed, and the running
/// hash.
pub struct RsaPkcs1v15Verifier<'k, K: RsaSize, H> {
    pk: &'k RsaPublicKey<K>,
    hash: H,
}

impl<K, H, const K_LEN: usize> DeterministicSigningKey<RSASSA_PKCS1_v1_5<K, H>, K_LEN>
    for RsaPrivateKey<K>
where
    // Only a signing size signs: the verify-only sizes, RSA-1024/1536, do not implement
    // RsaSigningSize, so this impl does not exist for them -- the crate's `# Scope` at compile
    // time.
    K: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
    H: HashOneShot + HashAlgParams + AlgorithmOID,
{
    type Signer<'k>
        = RsaPkcs1v15Signer<'k, K, H>
    where
        Self: 'k;

    fn create_signer_deterministic<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        Ok(RsaPkcs1v15Signer { sk: self, hash: H::default() })
    }
}

impl<K, H, const K_LEN: usize> VerifyingKey<RSASSA_PKCS1_v1_5<K, H>, K_LEN> for RsaPublicKey<K>
where
    K: RsaSize<Modulus = [u8; K_LEN]>,
    H: HashOneShot + HashAlgParams + AlgorithmOID,
{
    type Verifier<'k>
        = RsaPkcs1v15Verifier<'k, K, H>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        Ok(RsaPkcs1v15Verifier { pk: self, hash: H::default() })
    }
}

impl<K: RsaSize, H: HashAlgParams> AlgorithmInfo for RsaPkcs1v15Signer<'_, K, H> {
    fn alg_name(&self) -> &'static str {
        RSASSA_PKCS1_v1_5::<K, H>::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        RSASSA_PKCS1_v1_5::<K, H>::MAX_SECURITY_STRENGTH
    }
}

impl<K, H, const K_LEN: usize> SignatureSigner<K_LEN> for RsaPkcs1v15Signer<'_, K, H>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
    H: HashOneShot + HashAlgParams + AlgorithmOID,
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; K_LEN], SignatureError> {
        let mut m_hash = [0u8; MAX_HASH_LEN];
        self.hash.do_final_out(&mut m_hash[..H::OUTPUT_LEN]);
        sign_from_hash::<K, H, K_LEN>(self.sk, &m_hash[..H::OUTPUT_LEN])
    }

    fn do_final_out(self, output: &mut [u8; K_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(K_LEN)
    }
}

impl<K: RsaSize, H: HashAlgParams> AlgorithmInfo for RsaPkcs1v15Verifier<'_, K, H> {
    fn alg_name(&self) -> &'static str {
        RSASSA_PKCS1_v1_5::<K, H>::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        RSASSA_PKCS1_v1_5::<K, H>::MAX_SECURITY_STRENGTH
    }
}

impl<K, H, const K_LEN: usize> SignatureVerifier for RsaPkcs1v15Verifier<'_, K, H>
where
    K: RsaSize<Modulus = [u8; K_LEN]>,
    H: HashOneShot + HashAlgParams + AlgorithmOID,
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        // RFC 8017 §8.2.2 step 1: a signature of the wrong length is rejected for its length.
        let sig: &[u8; K_LEN] = sig.try_into().map_err(|_| {
            SignatureError::LengthError("RSA signature must be exactly the modulus length")
        })?;
        let mut m_hash = [0u8; MAX_HASH_LEN];
        self.hash.do_final_out(&mut m_hash[..H::OUTPUT_LEN]);
        // Step 2.b: RSAVP1's "signature representative out of range" is "invalid signature" here;
        // one answer for every way a signature can fail.
        verify_from_hash::<K, H, K_LEN>(self.pk, &m_hash[..H::OUTPUT_LEN], sig)
            .map_err(|_| SignatureError::SignatureVerificationFailed)
    }
}

/// RSASSA-PKCS1-V1_5-SIGN (RFC 8017 §8.2.1) from the message hash (`H::OUTPUT_LEN` bytes): the
/// EMSA-PKCS1-v1_5 encoding of `digest`, then RSASP1.
///
/// # Errors
/// [`SignatureError::DecodingError`] if the encoded message is not below `n`, which no modulus
/// with its top bit set allows.
pub fn sign_from_hash<K, H, const K_LEN: usize>(
    sk: &RsaPrivateKey<K>,
    digest: &[u8],
) -> Result<[u8; K_LEN], SignatureError>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
    H: HashAlgParams + AlgorithmOID,
{
    let em = emsa_pkcs1_v1_5_encode_from_hash::<H, K_LEN>(digest);
    let m = K::limbs_from_be_bytes(&em);
    let s = rsasp1::<K>(sk, &m)?;
    Ok(K::be_bytes_from_limbs(&s))
}

/// RSASSA-PKCS1-V1_5-VERIFY (RFC 8017 §8.2.2) from the message hash: RSAVP1, then the EMSA
/// decoding compared against `digest`.
///
/// # Errors
/// [`SignatureError::DecodingError`] for a signature representative not below `n` (step 2.b's
/// "invalid signature" from RSAVP1), [`SignatureError::SignatureVerificationFailed`] for an
/// encoding that does not match.
pub fn verify_from_hash<K, H, const K_LEN: usize>(
    pk: &RsaPublicKey<K>,
    digest: &[u8],
    signature: &[u8; K_LEN],
) -> Result<(), SignatureError>
where
    K: RsaSize<Modulus = [u8; K_LEN]>,
    H: AlgorithmOID,
{
    let s = K::limbs_from_be_bytes(signature);
    let m = rsavp1::<K>(pk, &s)?;
    let em_prime = K::be_bytes_from_limbs(&m);

    if emsa_pkcs1_v1_5_verify_from_hash::<H, K_LEN>(digest, &em_prime) {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}
