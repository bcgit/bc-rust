//! The signature roles over any RSA signature algorithm: [`RsaSignatureAlgorithm`] is what a
//! scheme-and-hash marker ([`RSASSA_PKCS1_v1_5<K, H>`](crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5),
//! [`RSASSA_PSS<K, H>`](crate::rsassa_pss::RSASSA_PSS),
//! [`RSASSA_PSS_SHAKE<K, X>`](crate::rsassa_pss_shake::RSASSA_PSS_SHAKE)) implements, the size,
//! the hash and the scheme's EMSA verification, with its signing side on
//! [`RsaDeterministicSignatureAlgorithm`] (PKCS#1 v1.5, which draws nothing) or
//! [`RsaRandomizedSignatureAlgorithm`] (PSS, with its salt); the three workers and the role
//! impls on [`RsaPrivateKey<A>`] and [`RsaPublicKey<A>`] are written once over them, RSASP1 /
//! RSAVP1 around the scheme's encoding (RFC 8017 §8.1.1, §8.1.2, §8.2.1, §8.2.2 and RFC 8702
//! §3.2.1 as one orchestration). The `*_from_hash` functions take the message hash rather than
//! the message, for a caller that already holds the digest. Sealed: the markers are the
//! library's, so a role impl exists for every pairing and no other.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::mgf1::MAX_HASH_LEN;
use crate::rsa_core::{rsasp1, rsavp1};
use crate::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicSigningKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    AlgorithmInfo, Hash, HashAlgParams, HashOneShot, RNG, SignatureSigner, SignatureVerifier,
};

/// An RSA signature algorithm: the modulus size, the message hash, and the scheme's EMSA
/// verification. A key over it, [`RsaPrivateKey<A>`] / [`RsaPublicKey<A>`], is a key for it and
/// for nothing else.
pub trait RsaSignatureAlgorithm: SignatureAlgorithm + sealed::Sealed {
    /// The modulus size.
    type Size: RsaSize;
    /// The message hash (for PSS-SHAKE, the XOF read at its hash length).
    type Hash: HashOneShot + HashAlgParams;

    /// The scheme's verification of the recovered `EM` against the message hash: EMSA-PKCS1-v1_5's
    /// decoding or EMSA-PSS-VERIFY.
    fn emsa_verify<const K_LEN: usize>(m_hash: &[u8], em: &[u8; K_LEN]) -> bool;
}

/// An RSA signature algorithm whose encoding takes nothing but the hash: RSASSA-PKCS1-v1_5. Its
/// keys sign through [`DeterministicSigningKey`].
pub trait RsaDeterministicSignatureAlgorithm: RsaSignatureAlgorithm {
    /// EMSA-PKCS1-v1_5-ENCODE of the message hash.
    fn emsa_encode<const K_LEN: usize>(m_hash: &[u8]) -> [u8; K_LEN];
}

/// An RSA signature algorithm whose encoding takes a salt: RSASSA-PSS, with MGF1 or a native
/// XOF mask. Its keys sign through [`SigningKey`], the salt (one hash output, RFC 8017 §9.1
/// note 4's "typical" choice) drawn from the RNG when the signer is made.
pub trait RsaRandomizedSignatureAlgorithm: RsaSignatureAlgorithm {
    /// EMSA-PSS-ENCODE of the message hash with `salt`.
    fn emsa_encode<const K_LEN: usize>(m_hash: &[u8], salt: &[u8]) -> [u8; K_LEN];
}

/// The signer [`SigningKey::create_signer`] hands out for a randomized algorithm: the key,
/// borrowed, the hash state, and the salt drawn when it was made.
pub struct RsaSigner<'k, A: RsaRandomizedSignatureAlgorithm> {
    sk: &'k RsaPrivateKey<A>,
    hash: A::Hash,
    salt: [u8; MAX_HASH_LEN],
}

impl<A: RsaRandomizedSignatureAlgorithm> RsaSigner<'_, A> {
    /// Replaces the drawn salt with `salt`, one hash output long (a compile-time check), for a
    /// known-answer test: the signature is then a function of the key and the message alone.
    pub fn set_salt<const N: usize>(&mut self, salt: [u8; N]) {
        const { assert!(N == A::Hash::OUTPUT_LEN, "the PSS salt is one hash output long") };
        self.salt[..N].copy_from_slice(&salt);
    }
}

/// The signer [`DeterministicSigningKey::create_signer_deterministic`] hands out: the key,
/// borrowed, and the hash state.
pub struct RsaDeterministicSigner<'k, A: RsaDeterministicSignatureAlgorithm> {
    sk: &'k RsaPrivateKey<A>,
    hash: A::Hash,
}

/// The verifier [`VerifyingKey::create_verifier`] hands out: the key, borrowed, and the hash
/// state.
pub struct RsaVerifier<'k, A: RsaSignatureAlgorithm> {
    pk: &'k RsaPublicKey<A>,
    hash: A::Hash,
}

impl<A, const K_LEN: usize> SigningKey<A, K_LEN> for RsaPrivateKey<A>
where
    A: RsaRandomizedSignatureAlgorithm,
    // Only a signing size signs: the verify-only sizes, RSA-1024/1536, do not implement
    // RsaSigningSize, so this impl does not exist for them -- the crate's `# Scope` at compile
    // time.
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    type Signer<'k>
        = RsaSigner<'k, A>
    where
        Self: 'k;

    /// Draws EMSA-PSS-ENCODE step 4's salt from `rng` when the signer is made, as ECDSA draws
    /// `k`; `ctx` is accepted and ignored, RSA having no context string.
    ///
    /// # Errors
    /// [`SignatureError::RNGError`] if the RNG fails to deliver.
    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        let mut salt = [0u8; MAX_HASH_LEN];
        rng.next_bytes_out(&mut salt[..A::Hash::OUTPUT_LEN]).map_err(SignatureError::RNGError)?;
        Ok(RsaSigner { sk: self, hash: A::Hash::default(), salt })
    }
}

impl<A, const K_LEN: usize> DeterministicSigningKey<A, K_LEN> for RsaPrivateKey<A>
where
    A: RsaDeterministicSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    type Signer<'k>
        = RsaDeterministicSigner<'k, A>
    where
        Self: 'k;

    /// Cannot fail; `ctx` is accepted and ignored, RSA having no context string.
    fn create_signer_deterministic<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        Ok(RsaDeterministicSigner { sk: self, hash: A::Hash::default() })
    }
}

impl<A, const K_LEN: usize> VerifyingKey<A, K_LEN> for RsaPublicKey<A>
where
    A: RsaSignatureAlgorithm,
    A::Size: RsaSize<Modulus = [u8; K_LEN]>,
{
    type Verifier<'k>
        = RsaVerifier<'k, A>
    where
        Self: 'k;

    /// Cannot fail; `ctx` is accepted and ignored.
    fn create_verifier<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        Ok(RsaVerifier { pk: self, hash: A::Hash::default() })
    }
}

impl<A: RsaRandomizedSignatureAlgorithm> AlgorithmInfo for RsaSigner<'_, A> {
    fn alg_name(&self) -> &'static str {
        A::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        A::MAX_SECURITY_STRENGTH
    }
}

impl<A, const K_LEN: usize> SignatureSigner<K_LEN> for RsaSigner<'_, A>
where
    A: RsaRandomizedSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; K_LEN], SignatureError> {
        let h_len = A::Hash::OUTPUT_LEN;
        let mut m_hash = [0u8; MAX_HASH_LEN];
        self.hash.do_final_out(&mut m_hash[..h_len]);
        sign_from_hash_with_salt::<A, K_LEN>(self.sk, &m_hash[..h_len], &self.salt[..h_len])
    }

    fn do_final_out(self, output: &mut [u8; K_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(K_LEN)
    }
}

impl<A: RsaDeterministicSignatureAlgorithm> AlgorithmInfo for RsaDeterministicSigner<'_, A> {
    fn alg_name(&self) -> &'static str {
        A::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        A::MAX_SECURITY_STRENGTH
    }
}

impl<A, const K_LEN: usize> SignatureSigner<K_LEN> for RsaDeterministicSigner<'_, A>
where
    A: RsaDeterministicSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; K_LEN], SignatureError> {
        let h_len = A::Hash::OUTPUT_LEN;
        let mut m_hash = [0u8; MAX_HASH_LEN];
        self.hash.do_final_out(&mut m_hash[..h_len]);
        sign_from_hash_deterministic::<A, K_LEN>(self.sk, &m_hash[..h_len])
    }

    fn do_final_out(self, output: &mut [u8; K_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(K_LEN)
    }
}

impl<A: RsaSignatureAlgorithm> AlgorithmInfo for RsaVerifier<'_, A> {
    fn alg_name(&self) -> &'static str {
        A::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        A::MAX_SECURITY_STRENGTH
    }
}

impl<A, const K_LEN: usize> SignatureVerifier for RsaVerifier<'_, A>
where
    A: RsaSignatureAlgorithm,
    A::Size: RsaSize<Modulus = [u8; K_LEN]>,
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        // RFC 8017 §8.1.2 / §8.2.2 step 1: a signature of the wrong length is rejected for its
        // length.
        let sig: &[u8; K_LEN] = sig.try_into().map_err(|_| {
            SignatureError::LengthError("RSA signature must be exactly the modulus length")
        })?;
        let h_len = A::Hash::OUTPUT_LEN;
        let mut m_hash = [0u8; MAX_HASH_LEN];
        self.hash.do_final_out(&mut m_hash[..h_len]);
        // Step 2.b: RSAVP1's "signature representative out of range" is "invalid signature" here;
        // one answer for every way a signature can fail.
        verify_from_hash::<A, K_LEN>(self.pk, &m_hash[..h_len], sig)
            .map_err(|_| SignatureError::SignatureVerificationFailed)
    }
}

/// A randomized algorithm's signature of the message hash `m_hash` under `salt` (RFC 8017
/// §8.1.1 with the salt the caller's): the scheme's encoding, then RSASP1.
///
/// # Errors
/// [`SignatureError::DecodingError`] if the encoded message is not below `n` (RSASP1 step 1),
/// which a correct encoding never is.
pub fn sign_from_hash_with_salt<A, const K_LEN: usize>(
    sk: &RsaPrivateKey<A>,
    m_hash: &[u8],
    salt: &[u8],
) -> Result<[u8; K_LEN], SignatureError>
where
    A: RsaRandomizedSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    let em = A::emsa_encode::<K_LEN>(m_hash, salt);
    let m = A::Size::limbs_from_be_bytes(&em);
    let s = rsasp1::<A::Size>(sk.components(), &m)?;
    Ok(A::Size::be_bytes_from_limbs(&s))
}

/// A randomized algorithm's signature of the message hash `m_hash`, the salt drawn from `rng`:
/// RFC 8017 §8.1.1.
///
/// # Errors
/// [`SignatureError::RNGError`] if the RNG fails to deliver, else as
/// [`sign_from_hash_with_salt`].
pub fn sign_from_hash<A, const K_LEN: usize>(
    sk: &RsaPrivateKey<A>,
    m_hash: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; K_LEN], SignatureError>
where
    A: RsaRandomizedSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    let h_len = A::Hash::OUTPUT_LEN;
    let mut salt = [0u8; MAX_HASH_LEN];
    rng.next_bytes_out(&mut salt[..h_len]).map_err(SignatureError::RNGError)?;
    sign_from_hash_with_salt::<A, K_LEN>(sk, m_hash, &salt[..h_len])
}

/// A deterministic algorithm's signature of the message hash `m_hash`: RFC 8017 §8.2.1, the
/// scheme's encoding, then RSASP1.
///
/// # Errors
/// As [`sign_from_hash_with_salt`].
pub fn sign_from_hash_deterministic<A, const K_LEN: usize>(
    sk: &RsaPrivateKey<A>,
    m_hash: &[u8],
) -> Result<[u8; K_LEN], SignatureError>
where
    A: RsaDeterministicSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    let em = A::emsa_encode::<K_LEN>(m_hash);
    let m = A::Size::limbs_from_be_bytes(&em);
    let s = rsasp1::<A::Size>(sk.components(), &m)?;
    Ok(A::Size::be_bytes_from_limbs(&s))
}

/// Verification of `signature` against the message hash `m_hash` (RFC 8017 §8.1.2 / §8.2.2):
/// RSAVP1, then the scheme's verification of the recovered encoding.
///
/// # Errors
/// [`SignatureError::DecodingError`] if the signature representative is not below `n`
/// (RSAVP1 step 1), [`SignatureError::SignatureVerificationFailed`] if the encoding does not
/// verify.
pub fn verify_from_hash<A, const K_LEN: usize>(
    pk: &RsaPublicKey<A>,
    m_hash: &[u8],
    signature: &[u8; K_LEN],
) -> Result<(), SignatureError>
where
    A: RsaSignatureAlgorithm,
    A::Size: RsaSize<Modulus = [u8; K_LEN]>,
{
    let s = A::Size::limbs_from_be_bytes(signature);
    let m = rsavp1::<A::Size>(pk.components(), &s)?;
    let em = A::Size::be_bytes_from_limbs(&m);
    if A::emsa_verify::<K_LEN>(m_hash, &em) {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}

mod sealed {
    pub trait Sealed {}
    impl<K: crate::size::RsaSize, H> Sealed for crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5<K, H> {}
    impl<K: crate::size::RsaSize, H> Sealed for crate::rsassa_pss::RSASSA_PSS<K, H> {}
    impl<K: crate::size::RsaSize, X> Sealed for crate::rsassa_pss_shake::RSASSA_PSS_SHAKE<K, X> {}
}
