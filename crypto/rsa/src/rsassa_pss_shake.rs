//! RSASSA-PSS with SHAKE128 or SHAKE256 as both the hash and the (native, non-MGF1) mask
//! generation function -- `id-RSASSA-PSS-SHAKE128`/`id-RSASSA-PSS-SHAKE256` (RFC 8702 §3.2.1).
//! Otherwise identical to [`crate::rsassa_pss`] (RFC 8017 §8.1): same RSASP1/RSAVP1 orchestration,
//! same fresh-salt-per-signature approach, just built on [`crate::emsa_pss_shake`] in place of
//! [`crate::emsa_pss`] -- and the same free-function/[`RSASSA_PSS_SHAKE`]-trait-type split,
//! with `X: XOF` in place of `H: Hash` and no `SEED_LEN` (there is no MGF1 counter to size).

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use crate::emsa_pss_shake::{emsa_pss_encode_shake_from_hash, emsa_pss_verify_shake_from_hash};
use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsa_core::{rsasp1, rsavp1};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{
    RNG, SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer, XOF,
};
use bouncycastle_rng::DefaultRNG;

/// Streaming state for RSASSA-PSS-SHAKE's [`Signer`] and [`SignatureVerifier`] impls: exactly
/// [`crate::rsassa_pss::RSASSA_PSS`] (whose docs cover the shared behaviour, including where the
/// salt comes from and the [`Self::sign_randomized`]/[`Self::set_signer_salt`] ways to control
/// it) built on the SHAKE-native encoding instead. `X`'s `Hash` methods (a `XOF` is a `Hash`)
/// absorb the streamed message; its `H_LEN`-byte output is `mHash`, as in the free functions.
/// Concrete pairings are aliases such as `crate::rsa_2048::RSASSA_PSS_SHAKE128`.
#[allow(non_camel_case_types)]
pub struct RSASSA_PSS_SHAKE<
    X,
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    hash: X,
    sk: Option<RsaPrivateKey<L, HALF>>,
    pk: Option<RsaPublicKey<L>>,
    /// See `RSASSA_PSS`'s field of the same name.
    salt: Option<[u8; S_LEN]>,
}

impl<
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
    const SK_LEN: usize,
    const PK_LEN: usize,
>
    RSASSA_PSS_SHAKE<
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
        SK_LEN,
        PK_LEN,
    >
where
    RsaPrivateKey<L, HALF>: SignaturePrivateKey<SK_LEN>,
{
    /// As [`crate::rsassa_pss::RSASSA_PSS::sign_randomized`]: the salt from the caller's `rng`.
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

    /// As [`crate::rsassa_pss::RSASSA_PSS::set_signer_salt`]: fixes the salt `sign_final` uses.
    pub fn set_signer_salt(&mut self, salt: [u8; S_LEN]) {
        self.salt = Some(salt);
    }
}

impl<
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> Signer<RsaPrivateKey<L, HALF>, SK_LEN, K_LEN>
    for RSASSA_PSS_SHAKE<
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
        // ctx ignored -- see `RSASSA_PKCS1_v1_5`'s docs.
        Ok(Self { hash: X::default(), sk: Some(sk.clone()), pk: None, salt: None })
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn sign_final(self) -> Result<[u8; K_LEN], SignatureError> {
        let sk = self.sk.ok_or(SignatureError::GenericError(
            "sign_final called on a verify-initialized RSASSA_PSS_SHAKE; call verify_final instead",
        ))?;
        // EMSA-PSS step 2, `mHash = Hash(M)`, completed here over the streamed chunks.
        let mut m_hash = [0u8; H_LEN];
        self.hash.do_final_out(&mut m_hash);
        // EMSA-PSS-ENCODE step 4's salt: fixed by `set_signer_salt`, else fresh from the default
        // RNG (see `RSASSA_PSS`).
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
        >(&sk, &m_hash, &salt)
    }

    fn sign_final_out(self, output: &mut [u8; K_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.sign_final()?;
        Ok(K_LEN)
    }
}

impl<
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
    const SK_LEN: usize,
    const PK_LEN: usize,
> SignatureVerifier<RsaPublicKey<L>, PK_LEN, K_LEN>
    for RSASSA_PSS_SHAKE<
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
        Ok(Self { hash: X::default(), sk: None, pk: Some(pk.clone()), salt: None })
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let pk = self.pk.ok_or(SignatureError::GenericError(
            "verify_final called on a sign-initialized RSASSA_PSS_SHAKE; call sign_final instead",
        ))?;
        // RFC 8017 §8.1.2 step 1: "Length checking: If the length of the signature S is not k
        // octets, output "invalid signature" and stop." (See `RSASSA_PKCS1_v1_5::verify_final`.)
        let sig: &[u8; K_LEN] =
            sig.try_into().map_err(|_| SignatureError::SignatureVerificationFailed)?;
        let mut m_hash = [0u8; H_LEN];
        self.hash.do_final_out(&mut m_hash);
        // Step 2.b: RSAVP1's "signature representative out of range" is "invalid signature" here
        // (see `RSASSA_PKCS1_v1_5::verify_final`).
        verify_from_hash::<X, H_LEN, S_LEN, M_PRIME_LEN, DB_LEN, L, L2, L21, K_LEN>(
            &pk, &m_hash, sig,
        )
        .map_err(|_| SignatureError::SignatureVerificationFailed)
    }
}

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
