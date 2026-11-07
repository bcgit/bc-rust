//! RSASSA-PSS (RFC 8017 §8.1): sign and verify, built on [`crate::rsa_core`]'s RSASP1/RSAVP1 and
//! [`crate::emsa_pss`]'s probabilistic encoding. Generic over the same width parameters as
//! [`crate::rsassa_pkcs1_v1_5`] plus PSS's own `S_LEN` (salt length) and `M_PRIME_LEN`
//! (`8 + H_LEN + S_LEN`); a concrete modulus size wires these to literals (RSA-2048/SHA-256 in
//! [`crate::rsa_2048`]).
//!
//! As in [`crate::rsassa_pkcs1_v1_5`], [`RSASSA_PSS`] is the algorithm marker the key role
//! traits are implemented over, on top of the `*_from_hash` functions, which take the message
//! hash rather than the message; the salt comes from the RNG handed to
//! [`SigningKey::create_signer`], and [`RsaPssSigner::set_salt`] replaces it for a known answer.

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use crate::emsa_pss::{emsa_pss_encode_from_hash, emsa_pss_verify_from_hash};
use crate::keys::{RsaPrivateKey, RsaPublicKey, modulus_strength};
use crate::rsa_core::{rsasp1, rsavp1};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{SignatureAlgorithm, SigningKey, VerifyingKey};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, HashOneShot, RNG, SignaturePrivateKey, SignaturePublicKey,
    SignatureSigner, SignatureVerifier,
};
use core::marker::PhantomData;

/// RSASSA-PSS (RFC 8017 §8.1) over `H`, with MGF1 over `H`, at a modulus of `L` limbs: the algorithm marker the key role
/// traits are implemented over, with every width fixed by the aliases in the size modules
/// (`rsa_2048::RSASSA_PSS_SHA256` and siblings).
/// `RsaPrivateKey` signs through [`SigningKey`]: a fresh `S_LEN`-byte salt from the caller's RNG
/// per signer (EMSA-PSS-ENCODE step 4), so two signatures of one message differ.
/// `RsaPublicKey` verifies through [`VerifyingKey`]. One key type serves every scheme and hash, so
/// a call names the marker: `SigningKey::<rsa_2048::RSASSA_PSS_SHA256, 256>::...(&sk, ..)`. `ctx` is
/// accepted and ignored, since RSA has no context string.
#[allow(non_camel_case_types)]
pub struct RSASSA_PSS<
    H,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    _hash: PhantomData<H>,
}

impl<
    H,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> Algorithm
    for RSASSA_PSS<
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
        SK_LEN,
        PK_LEN,
    >
{
    const ALG_NAME: &'static str = "RSASSA-PSS";
    /// From the modulus width, by SP 800-57 Part 1 Rev. 5 Table 2; see [`modulus_strength`].
    const MAX_SECURITY_STRENGTH: SecurityStrength = modulus_strength(L);
}

impl<
    H,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> SignatureAlgorithm
    for RSASSA_PSS<
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
        SK_LEN,
        PK_LEN,
    >
{
}

/// The signer the key hands out; it hashes the message and finishes with [`RSASSA_PSS`]'s encoding and
/// RSASP1. `set_salt` replaces the drawn salt, for a known-answer test; the signature then depends on the key and message alone.
pub struct RsaPssSigner<
    'k,
    H,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    sk: &'k RsaPrivateKey<L, HALF>,
    hash: H,
    salt: [u8; S_LEN],
}

impl<
    'k,
    H: HashOneShot,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
>
    RsaPssSigner<
        'k,
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
        SK_LEN,
        PK_LEN,
    >
{
    /// Replaces the salt drawn at creation with `salt`, for a known-answer test against a
    /// published salt; the signature then depends on the key and message alone.
    pub fn set_salt(&mut self, salt: [u8; S_LEN]) {
        self.salt = salt;
    }
}

/// The verifier the key hands out: hashes the message and finishes with RSAVP1 and the
/// encoding's verification.
pub struct RsaPssVerifier<
    'k,
    H,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    pk: &'k RsaPublicKey<L>,
    hash: H,
}

impl<
    H: HashOneShot,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
>
    SigningKey<
        RSASSA_PSS<
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
            SK_LEN,
            PK_LEN,
        >,
        K_LEN,
    > for RsaPrivateKey<L, HALF>
where
    // Only a private key type this crate has declared signable (a `SignaturePrivateKey` impl in
    // its size module) signs: the verify-only sizes, RSA-1024/1536, have none, so this impl does
    // not exist for them -- compile-time enforcement of the crate's `# Scope`.
    RsaPrivateKey<L, HALF>: SignaturePrivateKey<SK_LEN>,
{
    type Signer<'k>
        = RsaPssSigner<
        'k,
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
        SK_LEN,
        PK_LEN,
    >
    where
        Self: 'k;

    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        // EMSA-PSS-ENCODE step 4's salt, drawn when the signer is created, as ECDSA draws `k`.
        let mut salt = [0u8; S_LEN];
        rng.next_bytes_out(&mut salt).map_err(SignatureError::RNGError)?;
        Ok(RsaPssSigner { sk: self, hash: H::default(), salt })
    }
}

impl<
    H: HashOneShot,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
>
    VerifyingKey<
        RSASSA_PSS<
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
            SK_LEN,
            PK_LEN,
        >,
        K_LEN,
    > for RsaPublicKey<L>
where
    RsaPublicKey<L>: SignaturePublicKey<PK_LEN>,
{
    type Verifier<'k>
        = RsaPssVerifier<
        'k,
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
        SK_LEN,
        PK_LEN,
    >
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        Ok(RsaPssVerifier { pk: self, hash: H::default() })
    }
}

impl<
    H: HashOneShot,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> AlgorithmInfo
    for RsaPssSigner<
        '_,
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
        SK_LEN,
        PK_LEN,
    >
{
    fn alg_name(&self) -> &'static str {
        <RSASSA_PSS<
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
            SK_LEN,
            PK_LEN,
        > as Algorithm>::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        <RSASSA_PSS<
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
            SK_LEN,
            PK_LEN,
        > as Algorithm>::MAX_SECURITY_STRENGTH
    }
}

impl<
    H: HashOneShot,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> SignatureSigner<K_LEN>
    for RsaPssSigner<
        '_,
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
        SK_LEN,
        PK_LEN,
    >
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; K_LEN], SignatureError> {
        // The encoding's first step, `Hash(M)`, completed here over the streamed chunks.
        let mut m_hash = [0u8; H_LEN];
        self.hash.do_final_out(&mut m_hash);
        sign_from_hash_with_salt::<
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
        >(self.sk, &m_hash, &self.salt)
    }

    fn do_final_out(self, output: &mut [u8; K_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(K_LEN)
    }
}

impl<
    H: HashOneShot,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> AlgorithmInfo
    for RsaPssVerifier<
        '_,
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
        SK_LEN,
        PK_LEN,
    >
{
    fn alg_name(&self) -> &'static str {
        <RSASSA_PSS<
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
            SK_LEN,
            PK_LEN,
        > as Algorithm>::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        <RSASSA_PSS<
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
            SK_LEN,
            PK_LEN,
        > as Algorithm>::MAX_SECURITY_STRENGTH
    }
}

impl<
    H: HashOneShot,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> SignatureVerifier
    for RsaPssVerifier<
        '_,
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
        SK_LEN,
        PK_LEN,
    >
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        // RFC 8017 §8.1.2 / §8.2.2 step 1, "Length checking: If the length of the signature S is
        // not k octets, output "invalid signature" and stop", reported as the length error the
        // shared suite expects for a signature of the wrong size.
        let sig: &[u8; K_LEN] = sig.try_into().map_err(|_| {
            SignatureError::LengthError("RSA signature must be exactly the modulus length")
        })?;
        let mut m_hash = [0u8; H_LEN];
        self.hash.do_final_out(&mut m_hash);
        // Step 2.b: RSAVP1's "signature representative out of range" is "invalid signature" here;
        // one answer for every way a signature can fail.
        verify_from_hash::<H, H_LEN, SEED_LEN, S_LEN, M_PRIME_LEN, DB_LEN, L, L2, L21, K_LEN>(
            self.pk, &m_hash, sig,
        )
        .map_err(|_| SignatureError::SignatureVerificationFailed)
    }
}

/// RSASSA-PSS-SIGN (RFC 8017 §8.1.1) with the salt supplied directly rather than drawn from an
/// RNG, given the message's hash `m_hash` (`H`'s output over the message) rather than the message
/// itself -- what [`RsaPssSigner`]'s `do_final` calls once it has hashed the streamed
/// message and settled the salt. EMSA-PSS is randomized only in its choice of salt (§9.1's own
/// note 5), so a fixed salt makes this deterministic and directly testable against a known salt.
pub fn sign_from_hash_with_salt<
    H: HashOneShot,
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
    m_hash: &[u8; H_LEN],
    salt: &[u8; S_LEN],
) -> Result<[u8; K_LEN], SignatureError> {
    let em = emsa_pss_encode_from_hash::<H, H_LEN, SEED_LEN, S_LEN, M_PRIME_LEN, DB_LEN, K_LEN>(
        m_hash, salt,
    );
    let m = limbs_from_be_bytes::<L, K_LEN>(&em);
    let s = rsasp1::<L, L2, L21, HALF, HALF2, HALF21>(sk, &m)?;
    Ok(be_bytes_from_limbs::<L, K_LEN>(&s))
}

/// RSASSA-PSS-SIGN (RFC 8017 §8.1.1) given the message's hash `m_hash` instead of the message:
/// draws a fresh `S_LEN`-byte salt from `rng` (EMSA-PSS-ENCODE step 4) and hands both to
/// [`sign_from_hash_with_salt`].
pub fn sign_from_hash<
    H: HashOneShot,
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
    m_hash: &[u8; H_LEN],
    rng: &mut dyn RNG,
) -> Result<[u8; K_LEN], SignatureError> {
    let mut salt = [0u8; S_LEN];
    rng.next_bytes_out(&mut salt).map_err(SignatureError::RNGError)?;
    sign_from_hash_with_salt::<
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
    >(sk, m_hash, &salt)
}

/// RSASSA-PSS-VERIFY (RFC 8017 §8.1.2) given the message's hash `m_hash` instead of the message
/// (the counterpart of [`sign_from_hash`]): recovers `EM = I2OSP(RSAVP1((n, e), OS2IP(S)),
/// emLen)` and checks it against `m_hash` via EMSA-PSS-VERIFY, which recovers the salt from `EM`
/// itself (§9.1.2) rather than needing it supplied. RSAVP1's range error propagates as its own
/// `Err`, as in [`crate::rsassa_pkcs1_v1_5::verify_from_hash`].
pub fn verify_from_hash<
    H: HashOneShot,
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
    m_hash: &[u8; H_LEN],
    signature: &[u8; K_LEN],
) -> Result<(), SignatureError> {
    let s = limbs_from_be_bytes::<L, K_LEN>(signature);
    let m = rsavp1::<L, L2, L21>(pk, &s)?;
    let em = be_bytes_from_limbs::<L, K_LEN>(&m);

    if emsa_pss_verify_from_hash::<H, H_LEN, SEED_LEN, S_LEN, M_PRIME_LEN, DB_LEN, K_LEN>(
        m_hash, &em,
    ) {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}
