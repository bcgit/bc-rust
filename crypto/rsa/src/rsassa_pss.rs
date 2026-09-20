//! RSASSA-PSS (RFC 8017 §8.1): sign and verify, built on [`crate::rsa_core`]'s RSASP1/RSAVP1 and
//! [`crate::emsa_pss`]'s probabilistic encoding. Generic over the same width parameters as
//! [`crate::rsassa_pkcs1_v1_5`] plus PSS's own `S_LEN` (salt length) and `M_PRIME_LEN`
//! (`8 + H_LEN + S_LEN`); a concrete modulus size wires these to literals (RSA-2048/SHA-256 in
//! [`crate::rsa_2048`]).
//!
//! As in [`crate::rsassa_pkcs1_v1_5`], the free functions take a whole message (and, for
//! signing, an explicit RNG or salt) while [`RSASSA_PSS`] implements `bouncycastle_core`'s
//! [`Signer`]/[`SignatureVerifier`] traits over the same widths, streaming the message and
//! drawing its salt from the library's default RNG. Both go through the `*_from_hash` functions.

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use crate::emsa_pss::{emsa_pss_encode_from_hash, emsa_pss_verify_from_hash};
use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsa_core::{rsasp1, rsavp1};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{
    Hash, RNG, SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_rng::DefaultRNG;

/// Streaming state for RSASSA-PSS's [`Signer`] and [`SignatureVerifier`] impls, at the widths the
/// const parameters fix (the list [`sign`] takes, plus the key encoding lengths `SK_LEN`/`PK_LEN`
/// the key traits are indexed by). The same one-type-both-roles shape as
/// [`crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5`], whose docs cover the `sk`/`pk` arrangement,
/// the ignored `ctx`, the naming, and the cloned key; concrete pairings are aliases such as
/// `crate::rsa_2048::RSASSA_PSS_SHA256`.
///
/// [`Signer::sign`] has no RNG parameter, and that trait's docs define it as sourcing any
/// randomness it needs from the library's default OS-backed RNG, so `sign_final` draws the salt
/// (EMSA-PSS-ENCODE step 4) from a fresh [`DefaultRNG`] unless the caller fixed one. Two
/// `Signer::sign` calls over the same key and message therefore produce different, both valid,
/// signatures. Control over that randomness follows the workspace's other signature crates:
/// [`Self::sign_randomized`] takes a caller-supplied RNG (as `bouncycastle_ecdsa`'s and
/// `bouncycastle_sm2`'s `sign_randomized` do), and [`Self::set_signer_salt`] fixes the salt on a
/// streaming state (as `bouncycastle_mldsa`'s `set_signer_rnd` fixes its nonce), which makes the
/// signature deterministic.
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
    hash: H,
    sk: Option<RsaPrivateKey<L, HALF>>,
    pk: Option<RsaPublicKey<L>>,
    /// The salt `sign_final` will use, if [`Self::set_signer_salt`] fixed one; `None` means a
    /// fresh one from [`DefaultRNG`].
    salt: Option<[u8; S_LEN]>,
}

impl<
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
    const SK_LEN: usize,
    const PK_LEN: usize,
>
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
    >
where
    RsaPrivateKey<L, HALF>: SignaturePrivateKey<SK_LEN>,
{
    /// RSASSA-PSS-SIGN (RFC 8017 §8.1.1) with the salt drawn from the caller's `rng` rather than
    /// the library's default -- an additional capability alongside [`Signer::sign`], the same
    /// shape as `bouncycastle_ecdsa`'s `ECDSAP256::sign_randomized` and `bouncycastle_sm2`'s
    /// `SM2::sign_randomized`. `ctx` is not taken: it is ignored throughout this type.
    pub fn sign_randomized(
        sk: &RsaPrivateKey<L, HALF>,
        msg: &[u8],
        rng: &mut dyn RNG,
    ) -> Result<[u8; K_LEN], SignatureError> {
        let mut salt = [0u8; S_LEN];
        rng.next_bytes_out(&mut salt).map_err(SignatureError::RNGError)?;
        let mut signer = Self::sign_init(sk, None)?;
        signer.set_signer_salt(salt);
        signer.sign_update(msg);
        signer.sign_final()
    }

    /// Fixes the salt [`Signer::sign_final`] will use (EMSA-PSS-ENCODE step 4) instead of drawing
    /// one from the default RNG -- the counterpart of `bouncycastle_mldsa`'s `set_signer_rnd`, for
    /// a caller with its own randomness source, a device without an RNG, or a test against a known
    /// salt. With the salt fixed, signing is deterministic; PSS's security argument assumes a
    /// fresh, unpredictable salt per signature (see the crate docs' `# Security Considerations`),
    /// so a fixed salt should itself be fresh randomness the caller obtained elsewhere. Has no
    /// effect on a verify-initialised state.
    pub fn set_signer_salt(&mut self, salt: [u8; S_LEN]) {
        self.salt = Some(salt);
    }
}

impl<
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> Signer<RsaPrivateKey<L, HALF>, SK_LEN, K_LEN>
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
where
    // See `RSASSA_PKCS1_v1_5`'s `Signer` impl: no `SignaturePrivateKey`, no `Signer`.
    RsaPrivateKey<L, HALF>: SignaturePrivateKey<SK_LEN>,
{
    fn sign(
        sk: &RsaPrivateKey<L, HALF>,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; K_LEN], SignatureError> {
        let mut s = Self::sign_init(sk, ctx)?;
        s.sign_update(msg);
        s.sign_final()
    }

    fn sign_out(
        sk: &RsaPrivateKey<L, HALF>,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; K_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = Self::sign(sk, msg, ctx)?;
        Ok(K_LEN)
    }

    fn sign_init(sk: &RsaPrivateKey<L, HALF>, _ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        // ctx ignored -- see the type's docs.
        Ok(Self { hash: H::default(), sk: Some(sk.clone()), pk: None, salt: None })
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn sign_final(self) -> Result<[u8; K_LEN], SignatureError> {
        let sk = self.sk.ok_or(SignatureError::GenericError(
            "sign_final called on a verify-initialized RSASSA_PSS; call verify_final instead",
        ))?;
        // EMSA-PSS step 2, `mHash = Hash(M)`, completed here over the streamed chunks.
        let mut m_hash = [0u8; H_LEN];
        self.hash.do_final_out(&mut m_hash);
        // EMSA-PSS-ENCODE step 4's salt: the one `set_signer_salt` fixed, else fresh from the
        // library's default RNG (see the type's docs).
        let salt = match self.salt {
            Some(salt) => salt,
            None => {
                let mut salt = [0u8; S_LEN];
                DefaultRNG::default()
                    .next_bytes_out(&mut salt)
                    .map_err(SignatureError::RNGError)?;
                salt
            }
        };
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
        >(&sk, &m_hash, &salt)
    }

    fn sign_final_out(self, output: &mut [u8; K_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.sign_final()?;
        Ok(K_LEN)
    }
}

impl<
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> SignatureVerifier<RsaPublicKey<L>, PK_LEN, K_LEN>
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
where
    RsaPublicKey<L>: SignaturePublicKey<PK_LEN>,
{
    fn verify(
        pk: &RsaPublicKey<L>,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mut v = Self::verify_init(pk, ctx)?;
        v.verify_update(msg);
        v.verify_final(sig)
    }

    fn verify_init(pk: &RsaPublicKey<L>, _ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        Ok(Self { hash: H::default(), sk: None, pk: Some(pk.clone()), salt: None })
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let pk = self.pk.ok_or(SignatureError::GenericError(
            "verify_final called on a sign-initialized RSASSA_PSS; call sign_final instead",
        ))?;
        // RFC 8017 §8.1.2 step 1: "Length checking: If the length of the signature S is not k
        // octets, output "invalid signature" and stop." (See `RSASSA_PKCS1_v1_5::verify_final`.)
        let sig: &[u8; K_LEN] =
            sig.try_into().map_err(|_| SignatureError::SignatureVerificationFailed)?;
        let mut m_hash = [0u8; H_LEN];
        self.hash.do_final_out(&mut m_hash);
        // Step 2.b: RSAVP1's "signature representative out of range" is "invalid signature" here
        // (see `RSASSA_PKCS1_v1_5::verify_final`).
        verify_from_hash::<H, H_LEN, SEED_LEN, S_LEN, M_PRIME_LEN, DB_LEN, L, L2, L21, K_LEN>(
            &pk, &m_hash, sig,
        )
        .map_err(|_| SignatureError::SignatureVerificationFailed)
    }
}

/// RSASSA-PSS-SIGN (RFC 8017 §8.1.1) with the salt supplied directly rather than drawn from an
/// RNG: EMSA-PSS is randomized only in its choice of salt (§9.1's own note 5), so fixing it makes
/// this deterministic and directly testable against a known salt. [`sign`] is the RNG-backed
/// entry point real callers want.
///
/// Hashes `message` (EMSA-PSS step 2) and hands `mHash` to [`sign_from_hash_with_salt`].
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
    let mut m_hash = [0u8; H_LEN];
    H::default().hash_out(message, &mut m_hash);
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
    >(sk, &m_hash, salt)
}

/// [`sign_with_salt`] given the message's hash `m_hash` (`H`'s output over the message) instead of
/// the message itself -- for a caller that hashed the message incrementally, such as a streaming
/// `Signer`.
pub fn sign_from_hash_with_salt<
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

/// RSASSA-PSS-SIGN (RFC 8017 §8.1.1), drawing a fresh `S_LEN`-byte salt from `rng` for each
/// signature (step 4 of EMSA-PSS-ENCODE). Hashes `message` and hands `mHash` to
/// [`sign_from_hash`].
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
    let mut m_hash = [0u8; H_LEN];
    H::default().hash_out(message, &mut m_hash);
    sign_from_hash::<
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
    >(sk, &m_hash, rng)
}

/// [`sign`] given the message's hash `m_hash` instead of the message: draws the salt from `rng`
/// (EMSA-PSS-ENCODE step 4) and hands both to [`sign_from_hash_with_salt`].
pub fn sign_from_hash<
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

/// RSASSA-PSS-VERIFY (RFC 8017 §8.1.2): recovers `EM = I2OSP(RSAVP1((n, e), OS2IP(S)), emLen)`
/// and checks it against `message` via EMSA-PSS-VERIFY, which recovers the salt from `EM` itself
/// (EMSA-PSS's own verification operation, §9.1.2) rather than needing it supplied. Hashes
/// `message` and hands `mHash` to [`verify_from_hash`].
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
    let mut m_hash = [0u8; H_LEN];
    H::default().hash_out(message, &mut m_hash);
    verify_from_hash::<H, H_LEN, SEED_LEN, S_LEN, M_PRIME_LEN, DB_LEN, L, L2, L21, K_LEN>(
        pk, &m_hash, signature,
    )
}

/// [`verify`] given the message's hash `m_hash` instead of the message -- the counterpart of
/// [`sign_from_hash`], for a streaming `SignatureVerifier`.
pub fn verify_from_hash<
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
