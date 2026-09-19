//! RSASSA-PKCS1-v1_5 (RFC 8017 §8.2): sign and verify, built on [`crate::rsa_core`]'s
//! RSASP1/RSAVP1 and [`crate::emsa_pkcs1_v1_5`]'s deterministic encoding. Generic over every
//! width this crate's arithmetic needs (`L`/`L2`/`L21` for the modulus, `HALF`/`HALF2`/`HALF21`
//! for each CRT prime, `K_LEN = 8 * L` for the encoded message/signature byte length) and over
//! the hash function `H` (`H_LEN`/`T_LEN` sized to it) -- a concrete modulus size wires these to
//! literals (e.g. RSA-2048/SHA-256 in [`crate::rsa_2048`]) rather than a caller choosing them.

use crate::codec::{be_bytes_from_limbs, limbs_from_be_bytes};
use crate::emsa_pkcs1_v1_5::{emsa_pkcs1_v1_5_encode, emsa_pkcs1_v1_5_verify};
use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsa_core::{rsasp1, rsavp1};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{AlgorithmOID, Hash, HashAlgParams};

/// RSASSA-PKCS1-V1_5-SIGN (RFC 8017 §8.2.1): `S = I2OSP(RSASP1(K, OS2IP(EM)), k)`, where
/// `EM = EMSA-PKCS1-V1_5-ENCODE(M, k)`. Step 1's two errors ("message too long" -- unreachable
/// here, since [`emsa_pkcs1_v1_5_encode`]'s own length is fixed at compile time by `K_LEN`, never
/// computed from `message`'s length -- and "RSA modulus too short") are folded into
/// [`emsa_pkcs1_v1_5_encode`]'s `debug_assert`, not raised here as a runtime error, for the same
/// reason given there.
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
    let em = emsa_pkcs1_v1_5_encode::<H, H_LEN, T_LEN, K_LEN>(message);
    let m = limbs_from_be_bytes::<L, K_LEN>(&em);
    let s = rsasp1::<L, L2, L21, HALF, HALF2, HALF21>(sk, &m)?;
    Ok(be_bytes_from_limbs::<L, K_LEN>(&s))
}

/// RSASSA-PKCS1-V1_5-VERIFY (RFC 8017 §8.2.2): recovers `EM' = I2OSP(RSAVP1((n, e), OS2IP(S)),
/// k)` and checks it against `message` via [`emsa_pkcs1_v1_5_verify`] -- a decode, not RFC 8017's
/// own step 4 (re-encode `message` and compare bytes to `EM'`), because a byte comparison against
/// this crate's own (always-`NULL`-including) encoding would reject an otherwise-valid signature
/// whose `DigestInfo` omits the `AlgorithmIdentifier`'s `NULL` parameters -- a real-world
/// leniency [`emsa_pkcs1_v1_5_verify`]'s docs explain. Step 1's length check (`S` must be exactly
/// `k` octets) doesn't apply: `signature` is already a fixed `K_LEN`-byte array, not an
/// arbitrary-length octet string, so a wrong length is a compile-time type error at the call site
/// instead. Step 2's "signature representative out of range" surfaces as [`rsavp1`]'s own `Err`,
/// propagated directly rather than folded into "invalid signature": a caller working through
/// CAVP/wycheproof-style vectors needs to tell "malformed input" apart from "well-formed but
/// wrong", the same distinction RFC 8017 itself draws by giving the range check its own error
/// text.
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
    let s = limbs_from_be_bytes::<L, K_LEN>(signature);
    let m = rsavp1::<L, L2, L21>(pk, &s)?;
    let em_prime = be_bytes_from_limbs::<L, K_LEN>(&m);

    if emsa_pkcs1_v1_5_verify::<H, H_LEN, K_LEN>(message, &em_prime) {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}
