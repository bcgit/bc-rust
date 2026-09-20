//! RSASSA-PKCS1-v1_5 (RFC 8017 §8.2): sign and verify, built on [`crate::rsa_core`]'s
//! RSASP1/RSAVP1 and [`crate::emsa_pkcs1_v1_5`]'s deterministic encoding. Generic over every
//! width this crate's arithmetic needs (`L`/`L2`/`L21` for the modulus, `HALF`/`HALF2`/`HALF21`
//! for each CRT prime, `K_LEN = 8 * L` for the encoded message/signature byte length) and over
//! the hash function `H` (`H_LEN`/`T_LEN` sized to it) -- a concrete modulus size wires these to
//! literals (e.g. RSA-2048/SHA-256 in [`crate::rsa_2048`]) rather than a caller choosing them.
//!
//! Two shapes of the same operation: the free functions [`sign`]/[`verify`] take a whole message,
//! and [`RSASSA_PKCS1_v1_5`] implements `bouncycastle_core`'s [`Signer`]/[`SignatureVerifier`]
//! traits over the same widths, adding the streaming (`sign_init`/`sign_update`/`sign_final`)
//! form and a `&[u8]`-typed signature on the verify side. Both go through [`sign_from_hash`]/
//! [`verify_from_hash`], so there is exactly one encoding path to test.

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use crate::emsa_pkcs1_v1_5::{emsa_pkcs1_v1_5_encode_from_hash, emsa_pkcs1_v1_5_verify_from_hash};
use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsa_core::{rsasp1, rsavp1};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{
    AlgorithmOID, Hash, HashAlgParams, SignaturePrivateKey, SignaturePublicKey, SignatureVerifier,
    Signer,
};

/// Streaming state for RSASSA-PKCS1-v1_5's [`Signer`] and [`SignatureVerifier`] impls, at the
/// widths the const parameters fix (the same list [`sign`] takes, plus the key encoding lengths
/// `SK_LEN`/`PK_LEN` the key traits are indexed by). One type serves both roles, mirroring
/// `bouncycastle_ecdsa::ecdsa_p256::ECDSAP256`: exactly one of `sk`/`pk` is `Some`, chosen by
/// which trait's `_init` constructed this value, and calling the other trait's `_final` on it is
/// reported as [`SignatureError::GenericError`] rather than silently doing the wrong operation.
///
/// Concrete (hash, modulus size) pairings are type aliases in the per-size modules --
/// `crate::rsa_2048::RSASSA_PKCS1_v1_5_SHA256` and siblings -- so a caller never spells out the
/// width list. The spec's own spelling `RSASSA-PKCS1-v1_5` is kept (hyphens as underscores), per
/// this repo's naming convention for identifiers a specification names.
///
/// `ctx` is accepted but ignored by every method: RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) has no
/// context-string input, the same position `bouncycastle_ecdsa` takes for ECDSA.
///
/// The key is cloned into this state by `sign_init`/`verify_init` (the traits leave no room for a
/// borrow), so a signing state for the largest modulus size holds a copy of its
/// `RsaPrivateKey`'s `Secret` fields for as long as the state lives -- see the crate docs'
/// `# Memory Usage`.
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
    hash: H,
    sk: Option<RsaPrivateKey<L, HALF>>,
    pk: Option<RsaPublicKey<L>>,
}

impl<
    H: Hash + HashAlgParams + AlgorithmOID + Default,
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
> Signer<RsaPrivateKey<L, HALF>, SK_LEN, K_LEN>
    for RSASSA_PKCS1_v1_5<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN, SK_LEN, PK_LEN>
where
    // Only a private key type this crate has declared signable (a `SignaturePrivateKey` impl in
    // its size module) gets a `Signer`: the verify-only sizes, RSA-1024/1536, have none, so this
    // impl does not exist for them and there is nothing to call -- compile-time enforcement of the
    // crate's `# Scope`, not a runtime check.
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
        Ok(Self { hash: H::default(), sk: Some(sk.clone()), pk: None })
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn sign_final(self) -> Result<[u8; K_LEN], SignatureError> {
        let sk = self.sk.ok_or(SignatureError::GenericError(
            "sign_final called on a verify-initialized RSASSA_PKCS1_v1_5; call verify_final instead",
        ))?;
        // EMSA-PKCS1-v1_5 step 1, `H = Hash(M)`, completed here over the streamed chunks.
        let mut digest = [0u8; H_LEN];
        self.hash.do_final_out(&mut digest);
        sign_from_hash::<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN>(&sk, &digest)
    }

    fn sign_final_out(self, output: &mut [u8; K_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.sign_final()?;
        Ok(K_LEN)
    }
}

impl<
    H: Hash + HashAlgParams + AlgorithmOID + Default,
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
> SignatureVerifier<RsaPublicKey<L>, PK_LEN, K_LEN>
    for RSASSA_PKCS1_v1_5<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN, SK_LEN, PK_LEN>
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
        Ok(Self { hash: H::default(), sk: None, pk: Some(pk.clone()) })
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let pk = self.pk.ok_or(SignatureError::GenericError(
            "verify_final called on a sign-initialized RSASSA_PKCS1_v1_5; call sign_final instead",
        ))?;
        // RFC 8017 §8.2.2 step 1: "Length checking: If the length of the signature S is not k
        // octets, output "invalid signature" and stop." -- the one place in this crate that step
        // is a runtime check, since the trait hands over a `&[u8]` rather than the `[u8; K_LEN]`
        // the free functions take.
        let sig: &[u8; K_LEN] =
            sig.try_into().map_err(|_| SignatureError::SignatureVerificationFailed)?;
        let mut digest = [0u8; H_LEN];
        self.hash.do_final_out(&mut digest);
        // Step 2.b: "If RSAVP1 outputs "signature representative out of range", output "invalid
        // signature" and stop." The free function [`verify`] deliberately lets RSAVP1's own error
        // through instead (see its docs); the trait's contract is the RFC's -- one "invalid
        // signature" answer for every way a signature can fail -- so it is folded in here.
        verify_from_hash::<H, H_LEN, L, L2, L21, K_LEN>(&pk, &digest, sig)
            .map_err(|_| SignatureError::SignatureVerificationFailed)
    }
}

/// RSASSA-PKCS1-V1_5-SIGN (RFC 8017 §8.2.1): `S = I2OSP(RSASP1(K, OS2IP(EM)), k)`, where
/// `EM = EMSA-PKCS1-V1_5-ENCODE(M, k)`. Step 1's two errors ("message too long" -- unreachable
/// here, since the encoding's own length is fixed at compile time by `K_LEN`, never computed from
/// `message`'s length -- and "RSA modulus too short") are folded into
/// [`emsa_pkcs1_v1_5_encode_from_hash`]'s `debug_assert`, not raised here as a runtime error, for
/// the same reason given there.
///
/// Hashes `message` (EMSA-PKCS1-v1_5 step 1) and hands the digest to [`sign_from_hash`].
pub fn sign<
    H: Hash + HashAlgParams + AlgorithmOID + Default,
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
    message: &[u8],
) -> Result<[u8; K_LEN], SignatureError> {
    let mut digest = [0u8; H_LEN];
    H::default().hash_out(message, &mut digest);
    sign_from_hash::<H, H_LEN, T_LEN, L, L2, L21, HALF, HALF2, HALF21, K_LEN>(sk, &digest)
}

/// [`sign`] given the message's hash `digest` (`H`'s output over the message) instead of the
/// message itself -- for a caller that hashed the message incrementally, such as a streaming
/// `Signer`. The `H` bound is only what [`emsa_pkcs1_v1_5_encode_from_hash`] needs to build the
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

/// RSASSA-PKCS1-V1_5-VERIFY (RFC 8017 §8.2.2): recovers `EM' = I2OSP(RSAVP1((n, e), OS2IP(S)),
/// k)` and checks it against `message` via [`emsa_pkcs1_v1_5_verify_from_hash`] -- a decode, not
/// RFC 8017's own step 4 (re-encode `message` and compare bytes to `EM'`), because a byte
/// comparison against this crate's own (always-`NULL`-including) encoding would reject an
/// otherwise-valid signature whose `DigestInfo` omits the `AlgorithmIdentifier`'s `NULL`
/// parameters -- a real-world leniency [`emsa_pkcs1_v1_5_verify_from_hash`]'s docs explain. Step
/// 1's length check (`S` must be exactly
/// `k` octets) doesn't apply: `signature` is already a fixed `K_LEN`-byte array, not an
/// arbitrary-length octet string, so a wrong length is a compile-time type error at the call site
/// instead. Step 2's "signature representative out of range" surfaces as [`rsavp1`]'s own `Err`,
/// propagated directly rather than folded into "invalid signature": a caller working through
/// CAVP/wycheproof-style vectors needs to tell "malformed input" apart from "well-formed but
/// wrong", the same distinction RFC 8017 itself draws by giving the range check its own error
/// text.
///
/// Hashes `message` and hands the digest to [`verify_from_hash`].
pub fn verify<
    H: Hash + HashAlgParams + AlgorithmOID + Default,
    const H_LEN: usize,
    const L: usize,
    const L2: usize,
    const L21: usize,
    const K_LEN: usize,
>(
    pk: &RsaPublicKey<L>,
    message: &[u8],
    signature: &[u8; K_LEN],
) -> Result<(), SignatureError> {
    let mut digest = [0u8; H_LEN];
    H::default().hash_out(message, &mut digest);
    verify_from_hash::<H, H_LEN, L, L2, L21, K_LEN>(pk, &digest, signature)
}

/// [`verify`] given the message's hash `digest` instead of the message -- the counterpart of
/// [`sign_from_hash`], for a streaming `SignatureVerifier`.
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
