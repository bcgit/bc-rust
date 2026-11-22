//! The signature roles over any RSA signature algorithm: [`RsaSignatureAlgorithm`] is what a
//! scheme-and-hash marker ([`RSASSA_PKCS1_v1_5<K, H>`](crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5),
//! [`RSASSA_PSS<K, H, P>`](crate::rsassa_pss::RSASSA_PSS)) implements, the size,
//! the hash and the scheme's EMSA verification, with its signing side on
//! [`RsaDeterministicSignatureAlgorithm`] (PKCS#1 v1.5, which draws nothing) or
//! [`RsaRandomizedSignatureAlgorithm`] (PSS, with its salt); the three workers and the role
//! impls on [`RsaPrivateKey<A>`] and [`RsaPublicKey<A>`] are written once over them, RSASP1 /
//! RSAVP1 around the scheme's encoding (RFC 8017 §8.1.1, §8.1.2, §8.2.1, §8.2.2 and RFC 8702
//! §3.2.1 as one orchestration). The `*_from_hash` functions take the message hash rather than
//! the message, for a caller that already holds the digest. Sealed: the markers are the
//! library's, so a role impl exists for every pairing and no other.

use crate::emsa_pkcs1_v1_5::HASH_LEN_ERROR;
use crate::keygen::fill_bytes;
use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::mgf1::MAX_HASH_LEN;
use crate::rsa_core::{rsasp1, rsavp1};
use crate::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotSigningKey,
    OneShotVerifyingKey, SignatureAlgorithm, SigningKey, VerifyingKey, sign_out_with_signer,
    verify_with_verifier,
};
use bouncycastle_core::traits::{
    AlgorithmInfo, FinishToken, Hash, HashAlgParams, HashOneShot, RNG, SignatureSigner,
    SignatureVerifier,
};

/// An RSA signature algorithm: the modulus size, the message hash, and the scheme's EMSA
/// verification. A key over it, [`RsaPrivateKey<A>`] / [`RsaPublicKey<A>`], is a key for it and
/// for nothing else.
///
/// The encodings' `K_LEN` is the size's modulus length and no other, checked when the method is
/// instantiated:
///
/// ```compile_fail,E0080
/// use bouncycastle_rsa::RSA2048;
/// use bouncycastle_rsa::rsassa::RsaSignatureAlgorithm;
/// use bouncycastle_rsa::rsassa_pss::RSASSA_PSS;
/// use bouncycastle_sha2::SHA256;
/// let _ = RSASSA_PSS::<RSA2048, SHA256>::emsa_verify::<128>(&[0u8; 32], &[0u8; 128]);
/// ```
///
/// ```
/// use bouncycastle_rsa::RSA2048;
/// use bouncycastle_rsa::rsassa::RsaSignatureAlgorithm;
/// use bouncycastle_rsa::rsassa_pss::RSASSA_PSS;
/// use bouncycastle_sha2::SHA256;
/// assert!(!RSASSA_PSS::<RSA2048, SHA256>::emsa_verify::<256>(&[0u8; 32], &[0u8; 256]));
/// ```
pub trait RsaSignatureAlgorithm: SignatureAlgorithm + sealed::Sealed {
    /// The modulus size.
    type Size: RsaSize;
    /// The message hash (for PSS-SHAKE, the XOF read at its hash length).
    type Hash: HashOneShot + HashAlgParams;

    /// The scheme's verification of the recovered `EM` against the message hash: EMSA-PKCS1-v1_5's
    /// decoding or EMSA-PSS-VERIFY. False for an `m_hash` that is not one output of the hash.
    fn emsa_verify<const K_LEN: usize>(m_hash: &[u8], em: &[u8; K_LEN]) -> bool;
}

/// An RSA signature algorithm whose encoding takes nothing but the hash: RSASSA-PKCS1-v1_5. Its
/// keys sign through [`DeterministicSigningKey`].
pub trait RsaDeterministicSignatureAlgorithm: RsaSignatureAlgorithm {
    /// EMSA-PKCS1-v1_5-ENCODE of the message hash.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] if `m_hash` is not one output of the hash.
    fn emsa_encode<const K_LEN: usize>(m_hash: &[u8]) -> Result<[u8; K_LEN], SignatureError>;
}

/// An RSA signature algorithm whose encoding takes a salt: RSASSA-PSS under salted parameters.
/// Its keys sign through [`SigningKey`], the salt drawn from the RNG when the signer is made.
pub trait RsaRandomizedSignatureAlgorithm: RsaSignatureAlgorithm {
    /// The salt length in bytes, at most 64 (`MAX_HASH_LEN`, the signer's buffer).
    const SALT_LEN: usize;

    /// EMSA-PSS-ENCODE of the message hash with `salt`, `SALT_LEN` bytes.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] if `m_hash` is not one output of the hash or `salt` is
    /// not `SALT_LEN` bytes.
    fn emsa_encode<const K_LEN: usize>(
        m_hash: &[u8],
        salt: &[u8],
    ) -> Result<[u8; K_LEN], SignatureError>;
}

/// RSA signatures take no context: RSASSA-PSS-SIGN and RSASSA-PKCS1-V1_5-SIGN (RFC 8017 §8.1.1,
/// §8.2.1) and their verifications are over a key and a message, and nothing else. So `None` and
/// the empty context are accepted and a non-empty one is refused where it is given, when a
/// worker is made, rather than dropped.
fn refuse_context(ctx: Option<&[u8]>) -> Result<(), SignatureError> {
    match ctx {
        Some(ctx) if !ctx.is_empty() => Err(SignatureError::LengthError("RSA takes no context")),
        _ => Ok(()),
    }
}

/// The signer [`SigningKey::create_signer`] hands out for a randomized algorithm: the key,
/// borrowed, the hash state, and the salt drawn when it was made.
pub struct RsaSigner<'k, A: RsaRandomizedSignatureAlgorithm> {
    sk: &'k RsaPrivateKey<A>,
    hash: A::Hash,
    salt: [u8; MAX_HASH_LEN],
}

impl<A: RsaRandomizedSignatureAlgorithm> RsaSigner<'_, A> {
    /// Replaces the drawn salt with `salt`, the algorithm's salt length (a compile-time check),
    /// for a known-answer test: the signature is then a function of the key and the message
    /// alone.
    pub fn set_salt<const N: usize>(&mut self, salt: [u8; N]) {
        const { assert!(N == A::SALT_LEN, "the salt is the algorithm's salt length") };
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
    /// `k`. `ctx` must be `None` or empty, RSA having no context.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] for a non-empty `ctx`, before anything is drawn;
    /// [`SignatureError::RNGError`] if the RNG fails to deliver, a draw shorter than the salt
    /// included.
    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        const { assert!(A::SALT_LEN <= MAX_HASH_LEN, "the salt fits the signer's buffer") };
        refuse_context(ctx)?;
        let mut salt = [0u8; MAX_HASH_LEN];
        fill_bytes(rng, &mut salt[..A::SALT_LEN]).map_err(SignatureError::RNGError)?;
        Ok(RsaSigner { sk: self, hash: A::Hash::default(), salt })
    }
}

impl<A, const K_LEN: usize> OneShotSigningKey<A, K_LEN> for RsaPrivateKey<A>
where
    A: RsaRandomizedSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    fn sign_out(
        &self,
        rng: &mut dyn RNG,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; K_LEN],
    ) -> Result<usize, SignatureError> {
        let signer = SigningKey::<A, K_LEN>::create_signer(self, rng, ctx);
        sign_out_with_signer(signer, msg, output)
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

    /// `ctx` must be `None` or empty, RSA having no context.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] for a non-empty `ctx`.
    fn create_signer_deterministic<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        refuse_context(ctx)?;
        Ok(RsaDeterministicSigner { sk: self, hash: A::Hash::default() })
    }
}

impl<A, const K_LEN: usize> DeterministicOneShotSigningKey<A, K_LEN> for RsaPrivateKey<A>
where
    A: RsaDeterministicSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    fn sign_deterministic_out(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; K_LEN],
    ) -> Result<usize, SignatureError> {
        let signer = DeterministicSigningKey::<A, K_LEN>::create_signer_deterministic(self, ctx);
        sign_out_with_signer(signer, msg, output)
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

    /// `ctx` must be `None` or empty, RSA having no context.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] for a non-empty `ctx`.
    fn create_verifier<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        refuse_context(ctx)?;
        Ok(RsaVerifier { pk: self, hash: A::Hash::default() })
    }
}

impl<A, const K_LEN: usize> OneShotVerifyingKey<A, K_LEN> for RsaPublicKey<A>
where
    A: RsaSignatureAlgorithm,
    A::Size: RsaSize<Modulus = [u8; K_LEN]>,
{
    fn verify(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        let verifier = VerifyingKey::<A, K_LEN>::create_verifier(self, ctx)?;
        verify_with_verifier(verifier, msg, sig)
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

    fn finish_signature_into(
        &mut self,
        token: &FinishToken,
        output: &mut [u8; K_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        let h_len = A::Hash::OUTPUT_LEN;
        let mut m_hash = [0u8; MAX_HASH_LEN];
        self.hash.finish_into(token, &mut m_hash[..h_len]);
        *output = sign_from_hash_with_salt::<A, K_LEN>(
            self.sk,
            &m_hash[..h_len],
            &self.salt[..A::SALT_LEN],
        )?;
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

    fn finish_signature_into(
        &mut self,
        token: &FinishToken,
        output: &mut [u8; K_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        let h_len = A::Hash::OUTPUT_LEN;
        let mut m_hash = [0u8; MAX_HASH_LEN];
        self.hash.finish_into(token, &mut m_hash[..h_len]);
        *output = sign_from_hash_deterministic::<A, K_LEN>(self.sk, &m_hash[..h_len])?;
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

    fn finish_signature_verify(
        &mut self,
        token: &FinishToken,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        // RFC 8017 §8.1.2 / §8.2.2 step 1: a signature of the wrong length is rejected for its
        // length.
        let sig: &[u8; K_LEN] = sig.try_into().map_err(|_| {
            SignatureError::LengthError("RSA signature must be exactly the modulus length")
        })?;
        let h_len = A::Hash::OUTPUT_LEN;
        let mut m_hash = [0u8; MAX_HASH_LEN];
        self.hash.finish_into(token, &mut m_hash[..h_len]);
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
/// [`SignatureError::LengthError`] if `m_hash` is not `A::Hash::OUTPUT_LEN` bytes or `salt` is
/// not `A::SALT_LEN` bytes; [`SignatureError::ComputationFault`] if the result fails RSASP1's
/// check; [`SignatureError::DecodingError`] if the encoded message is not below `n` (RSASP1
/// step 1), which a correct encoding never is.
pub fn sign_from_hash_with_salt<A, const K_LEN: usize>(
    sk: &RsaPrivateKey<A>,
    m_hash: &[u8],
    salt: &[u8],
) -> Result<[u8; K_LEN], SignatureError>
where
    A: RsaRandomizedSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    let em = A::emsa_encode::<K_LEN>(m_hash, salt)?;
    let m = A::Size::limbs_from_be_bytes(&em);
    let s = rsasp1::<A::Size>(sk.components(), &m)?;
    Ok(A::Size::be_bytes_from_limbs(&s))
}

/// A randomized algorithm's signature of the message hash `m_hash`, the salt drawn from `rng`:
/// RFC 8017 §8.1.1.
///
/// # Errors
/// [`SignatureError::LengthError`] if `m_hash` is not `A::Hash::OUTPUT_LEN` bytes, before
/// anything is drawn; [`SignatureError::RNGError`] if the RNG fails to deliver; else as
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
    const { assert!(A::SALT_LEN <= MAX_HASH_LEN, "the salt fits the buffer") };
    if m_hash.len() != A::Hash::OUTPUT_LEN {
        return Err(HASH_LEN_ERROR);
    }
    let mut salt = [0u8; MAX_HASH_LEN];
    fill_bytes(rng, &mut salt[..A::SALT_LEN]).map_err(SignatureError::RNGError)?;
    sign_from_hash_with_salt::<A, K_LEN>(sk, m_hash, &salt[..A::SALT_LEN])
}

/// A deterministic algorithm's signature of the message hash `m_hash`: RFC 8017 §8.2.1, the
/// scheme's encoding, then RSASP1.
///
/// # Errors
/// As [`sign_from_hash_with_salt`], there being no salt.
pub fn sign_from_hash_deterministic<A, const K_LEN: usize>(
    sk: &RsaPrivateKey<A>,
    m_hash: &[u8],
) -> Result<[u8; K_LEN], SignatureError>
where
    A: RsaDeterministicSignatureAlgorithm,
    A::Size: RsaSigningSize + RsaSize<Modulus = [u8; K_LEN]>,
{
    let em = A::emsa_encode::<K_LEN>(m_hash)?;
    let m = A::Size::limbs_from_be_bytes(&em);
    let s = rsasp1::<A::Size>(sk.components(), &m)?;
    Ok(A::Size::be_bytes_from_limbs(&s))
}

/// Verification of `signature` against the message hash `m_hash` (RFC 8017 §8.1.2 / §8.2.2):
/// RSAVP1, then the scheme's verification of the recovered encoding.
///
/// # Errors
/// [`SignatureError::LengthError`] if `m_hash` is not `A::Hash::OUTPUT_LEN` bytes,
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
    if m_hash.len() != A::Hash::OUTPUT_LEN {
        return Err(HASH_LEN_ERROR);
    }
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
    impl<K: crate::size::RsaSize, H, P> Sealed for crate::rsassa_pss::RSASSA_PSS<K, H, P> {}
}
