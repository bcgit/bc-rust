//! RSASSA-PKCS1-v1_5 (RFC 8017 §8.2): sign and verify, built on [`crate::rsa_core`]'s
//! RSASP1/RSAVP1 and [`crate::emsa_pkcs1_v1_5`]'s deterministic encoding. Generic over every
//! width this crate's arithmetic needs (`L`/`L2`/`L21` for the modulus, `HALF`/`HALF2`/`HALF21`
//! for each CRT prime, `K_LEN = 8 * L` for the encoded message/signature byte length) and over
//! the hash function `H` (`H_LEN`/`T_LEN` sized to it) -- a concrete modulus size wires these to
//! literals (e.g. RSA-2048/SHA-256 in [`crate::rsa_2048`]) rather than a caller choosing them.
//!
//! [`RSASSA_PKCS1_v1_5`] is the algorithm marker the key role traits ([`DeterministicSigningKey`],
//! [`VerifyingKey`]) are implemented over at those widths -- one-shot and streaming, with a
//! `&[u8]`-typed signature on the verify side -- on top of [`sign_from_hash`]/[`verify_from_hash`],
//! which take the message hash rather than the message and are the pre-hash entry points for a
//! caller that has already computed it.

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use crate::emsa_pkcs1_v1_5::{emsa_pkcs1_v1_5_encode_from_hash, emsa_pkcs1_v1_5_verify_from_hash};
use crate::keys::{RsaPrivateKey, RsaPublicKey, modulus_strength};
use crate::rsa_core::{rsasp1, rsavp1};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{DeterministicSigningKey, SignatureAlgorithm, VerifyingKey};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, AlgorithmOID, HashAlgParams, HashOneShot, SignaturePrivateKey,
    SignaturePublicKey, SignatureSigner, SignatureVerifier,
};
use core::marker::PhantomData;

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) over `H`, at a modulus of `L` limbs: the algorithm marker the key role
/// traits are implemented over, with every width fixed by the aliases in the size modules
/// (`rsa_2048::RSASSA_PKCS1_v1_5_SHA256` and siblings).
/// `RsaPrivateKey` signs through [`DeterministicSigningKey`]: PKCS#1 v1.5 draws nothing, so the
/// same key and message always give the same signature.
/// `RsaPublicKey` verifies through [`VerifyingKey`]. One key type serves every scheme and hash, so
/// a call names the marker: `DeterministicSigningKey::<rsa_2048::RSASSA_PKCS1_v1_5_SHA256, 256>::...(&sk, ..)`. `ctx` is
/// accepted and ignored, since RSA has no context string.
#[allow(non_camel_case_types)]
pub struct RSASSA_PKCS1_v1_5<
    H,
    const H_LEN: usize,
    const T_LEN: usize,
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
    const T_LEN: usize,
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
    for RSASSA_PKCS1_v1_5<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN, SK_LEN, PK_LEN>
{
    const ALG_NAME: &'static str = "RSASSA-PKCS1-v1_5";
    /// From the modulus width, by SP 800-57 Part 1 Rev. 5 Table 2; see [`modulus_strength`].
    const MAX_SECURITY_STRENGTH: SecurityStrength = modulus_strength(L);
}

impl<
    H,
    const H_LEN: usize,
    const T_LEN: usize,
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
    for RSASSA_PKCS1_v1_5<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN, SK_LEN, PK_LEN>
{
}

/// The signer the key hands out; it hashes the message and finishes with [`RSASSA_PKCS1_v1_5`]'s encoding and
/// RSASP1.
pub struct RsaPkcs1v15Signer<
    'k,
    H,
    const H_LEN: usize,
    const T_LEN: usize,
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
}

/// The verifier the key hands out: hashes the message and finishes with RSAVP1 and the
/// encoding's verification.
pub struct RsaPkcs1v15Verifier<
    'k,
    H,
    const H_LEN: usize,
    const T_LEN: usize,
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
    H: HashOneShot + HashAlgParams + AlgorithmOID,
    const H_LEN: usize,
    const T_LEN: usize,
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
    DeterministicSigningKey<
        RSASSA_PKCS1_v1_5<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN, SK_LEN, PK_LEN>,
        K_LEN,
    > for RsaPrivateKey<L, HALF>
where
    // Only a private key type this crate has declared signable (a `SignaturePrivateKey` impl in
    // its size module) signs: the verify-only sizes, RSA-1024/1536, have none, so this impl does
    // not exist for them -- compile-time enforcement of the crate's `# Scope`.
    RsaPrivateKey<L, HALF>: SignaturePrivateKey<SK_LEN>,
{
    type Signer<'k>
        = RsaPkcs1v15Signer<
        'k,
        H,
        H_LEN,
        T_LEN,
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

    fn create_signer_deterministic<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        Ok(RsaPkcs1v15Signer { sk: self, hash: H::default() })
    }
}

impl<
    H: HashOneShot + HashAlgParams + AlgorithmOID,
    const H_LEN: usize,
    const T_LEN: usize,
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
        RSASSA_PKCS1_v1_5<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN, SK_LEN, PK_LEN>,
        K_LEN,
    > for RsaPublicKey<L>
where
    RsaPublicKey<L>: SignaturePublicKey<PK_LEN>,
{
    type Verifier<'k>
        = RsaPkcs1v15Verifier<
        'k,
        H,
        H_LEN,
        T_LEN,
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
        Ok(RsaPkcs1v15Verifier { pk: self, hash: H::default() })
    }
}

impl<
    H: HashOneShot + HashAlgParams + AlgorithmOID,
    const H_LEN: usize,
    const T_LEN: usize,
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
    for RsaPkcs1v15Signer<
        '_,
        H,
        H_LEN,
        T_LEN,
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
        <RSASSA_PKCS1_v1_5<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN, SK_LEN, PK_LEN> as Algorithm>::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        <RSASSA_PKCS1_v1_5<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN, SK_LEN, PK_LEN> as Algorithm>::MAX_SECURITY_STRENGTH
    }
}

impl<
    H: HashOneShot + HashAlgParams + AlgorithmOID,
    const H_LEN: usize,
    const T_LEN: usize,
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
    for RsaPkcs1v15Signer<
        '_,
        H,
        H_LEN,
        T_LEN,
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
        sign_from_hash::<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN>(self.sk, &m_hash)
    }

    fn do_final_out(self, output: &mut [u8; K_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(K_LEN)
    }
}

impl<
    H: HashOneShot + HashAlgParams + AlgorithmOID,
    const H_LEN: usize,
    const T_LEN: usize,
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
    for RsaPkcs1v15Verifier<
        '_,
        H,
        H_LEN,
        T_LEN,
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
        <RSASSA_PKCS1_v1_5<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN, SK_LEN, PK_LEN> as Algorithm>::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        <RSASSA_PKCS1_v1_5<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN, SK_LEN, PK_LEN> as Algorithm>::MAX_SECURITY_STRENGTH
    }
}

impl<
    H: HashOneShot + HashAlgParams + AlgorithmOID,
    const H_LEN: usize,
    const T_LEN: usize,
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
    for RsaPkcs1v15Verifier<
        '_,
        H,
        H_LEN,
        T_LEN,
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
        verify_from_hash::<H, H_LEN, L, L2, L21, K_LEN>(self.pk, &m_hash, sig)
            .map_err(|_| SignatureError::SignatureVerificationFailed)
    }
}

/// RSASSA-PKCS1-V1_5-SIGN (RFC 8017 §8.2.1), `S = I2OSP(RSASP1(K, OS2IP(EM)), k)` with
/// `EM = EMSA-PKCS1-V1_5-ENCODE(M, k)`, given the message's hash `digest` (`H`'s output over `M`)
/// rather than `M` itself: the entry point for a caller that hashed the message incrementally
/// (the [`DeterministicSigningKey`] impl) or already holds the digest. Step 1's two errors ("message too long" --
/// unreachable, since the encoding's length is fixed at compile time by `K_LEN` -- and "RSA
/// modulus too short") are folded into [`emsa_pkcs1_v1_5_encode_from_hash`]'s `debug_assert`, not
/// raised here as a runtime error, for the reason given there. The `H` bound is only what [`emsa_pkcs1_v1_5_encode_from_hash`] needs to build the
/// `DigestInfo`; no hashing happens here.
pub fn sign_from_hash<
    H: HashAlgParams + AlgorithmOID,
    const H_LEN: usize,
    const T_LEN: usize,
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
    const K_LEN: usize,
>(
    sk: &RsaPrivateKey<L, HALF>,
    digest: &[u8; H_LEN],
) -> Result<[u8; K_LEN], SignatureError> {
    let em = emsa_pkcs1_v1_5_encode_from_hash::<H, H_LEN, T_LEN, K_LEN>(digest);
    let m = limbs_from_be_bytes::<L, K_LEN>(&em);
    let s = rsasp1::<L, L2, L21, HALF, HALF2, HALF21>(sk, &m)?;
    Ok(be_bytes_from_limbs::<L, K_LEN>(&s))
}

/// RSASSA-PKCS1-V1_5-VERIFY (RFC 8017 §8.2.2), given the message's hash `digest` rather than the
/// message (the counterpart of [`sign_from_hash`]): recovers `EM' = I2OSP(RSAVP1((n, e),
/// OS2IP(S)), k)` and checks it against `digest` via [`emsa_pkcs1_v1_5_verify_from_hash`] -- a
/// decode, not RFC 8017's own step 4 (re-encode and compare bytes to `EM'`), because a byte
/// comparison against this crate's own (always-`NULL`-including) encoding would reject an
/// otherwise-valid signature whose `DigestInfo` omits the `AlgorithmIdentifier`'s `NULL`
/// parameters -- a real-world leniency that function's docs explain. Step 1's length check (`S`
/// must be exactly `k` octets) doesn't apply here: `signature` is a fixed `K_LEN`-byte array, so a
/// wrong length is a type error at the call site; the [`VerifyingKey`] impl, which takes a
/// `&[u8]`, performs it. Step 2's "signature representative out of range" surfaces as
/// [`rsavp1`]'s own `Err`, propagated directly rather than folded into "invalid signature": a
/// caller working through CAVP/wycheproof-style vectors needs to tell "malformed input" apart from
/// "well-formed but wrong", the same distinction RFC 8017 itself draws by giving the range check
/// its own error text (the trait impl folds it, per step 2.b).
pub fn verify_from_hash<
    H: AlgorithmOID,
    const H_LEN: usize,
    const L: usize,
    const L2: usize,
    const L21: usize,
    const K_LEN: usize,
>(
    pk: &RsaPublicKey<L>,
    digest: &[u8; H_LEN],
    signature: &[u8; K_LEN],
) -> Result<(), SignatureError> {
    let s = limbs_from_be_bytes::<L, K_LEN>(signature);
    let m = rsavp1::<L, L2, L21>(pk, &s)?;
    let em_prime = be_bytes_from_limbs::<L, K_LEN>(&m);

    if emsa_pkcs1_v1_5_verify_from_hash::<H, H_LEN, K_LEN>(digest, &em_prime) {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}
