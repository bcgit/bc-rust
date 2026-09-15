//! RFC 6979 §3.2 / FIPS 186-5 Appendix A.3.3: the deterministic per-message secret `k` for
//! secp256k1, fixed to SHA-256 (the conventional pairing for this curve -- e.g. Bitcoin's own
//! usage, and wycheproof's `ecdsa_secp256k1_sha256_*` vector files). Identical in shape to
//! [`crate::rfc6979`] (P-256) -- see that module's docs for the full reasoning -- since
//! secp256k1's `n` is, like P-256's, 256 bits: `HLEN` (SHA-256's output) and `qlen` are equal, so
//! the same `int2octets`/`bits2octets`/single-HMAC-round shortcuts apply.
//!
//! RFC 6979 has no official Appendix A.2.x-style test vectors for secp256k1 (its appendix only
//! covers the NIST curves P-192 through P-521); `rfc6979_p256k1_vectors_tests.rs` cross-checks this
//! implementation against an independent Python implementation of the same RFC instead.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::MAC;
use bouncycastle_ec::nat;
use bouncycastle_ec::p256k1_scalar::{N_LIMBS, P256K1Scalar};
use bouncycastle_ec::p256k1_sec1;
use bouncycastle_hmac::HMAC;
use bouncycastle_sha2::SHA256;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

const HLEN: usize = 32;

const _: () =
    assert!(HLEN * 8 == 256, "int2octets/bits2octets shortcuts assume hlen == qlen == 256");

/// `HMAC_K(data)` (§3.1.1). See [`crate::rfc6979::hmac_k`]'s docs.
fn hmac_k(key: &[u8; HLEN], data: &[&[u8]]) -> [u8; HLEN] {
    let key_material = KeyMaterial::<HLEN>::from_bytes_as_type(key, KeyType::MACKey)
        .expect("HLEN-byte key always fits");
    let mut hmac =
        HMAC::<SHA256>::new_allow_weak_key(&key_material).expect("weak key always allowed");
    for piece in data {
        hmac.do_update(piece);
    }
    let mut out = [0u8; HLEN];
    hmac.do_final_out(&mut out).expect("HLEN-byte output buffer always fits HMAC-SHA256's output");
    out
}

/// RFC 6979 §2.3.4 `bits2octets(h1)`. See [`crate::rfc6979::bits2octets`]'s docs -- the same
/// single-subtraction argument applies here since secp256k1's `n` is likewise close enough to
/// `2^256` for a 256-bit input to always be `< 2n`.
fn bits2octets(h1: &[u8; HLEN]) -> [u8; HLEN] {
    let limbs = p256k1_sec1::limbs_from_be_bytes(h1);
    let (diff, borrow) = nat::sub(&limbs, &N_LIMBS);
    let mut reduced = [0u64; 4];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
    p256k1_sec1::be_bytes_from_limbs(&reduced)
}

/// `true` iff the raw (unreduced) candidate bytes, read as a big-endian integer, are in `[1,
/// n-1]` -- RFC 6979 step h.3's comparison against `q`.
fn candidate_in_range(candidate: &[u8; HLEN]) -> bool {
    let limbs = p256k1_sec1::limbs_from_be_bytes(candidate);
    if limbs == [0, 0, 0, 0] {
        return false;
    }
    let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
    borrow == 1
}

/// RFC 6979 §3.2 steps a-h: the deterministic per-message secret `k` for private key `d` and
/// message hash `h1 = H(m)`. See [`crate::rfc6979::generate_k`]'s docs for the rejection-loop
/// constant-time argument, which applies unchanged here.
pub fn generate_k(d: &P256K1Scalar, h1: &[u8; HLEN]) -> P256K1Scalar {
    let int2octets_d = d.to_be_bytes(); // §2.3.3, d already in [1, n-1]
    let bits2octets_h1 = bits2octets(h1);

    // step c
    let mut key = [0u8; HLEN];
    // step b
    let mut v = [0x01u8; HLEN];

    // step d
    key = hmac_k(&key, &[&v, &[0x00], &int2octets_d, &bits2octets_h1]);
    // step e
    v = hmac_k(&key, &[&v]);
    // step f
    key = hmac_k(&key, &[&v, &[0x01], &int2octets_d, &bits2octets_h1]);
    // step g
    v = hmac_k(&key, &[&v]);

    // step h
    loop {
        // step h.1-h.2: T = HMAC_K(V) suffices in one round since tlen == qlen == HLEN*8 (see
        // module docs)
        v = hmac_k(&key, &[&v]);
        if candidate_in_range(&v) {
            // in [1, n-1] already: from_limbs's reduction is a no-op safety net, not a real reduce
            return P256K1Scalar::from_limbs(p256k1_sec1::limbs_from_be_bytes(&v));
        }
        key = hmac_k(&key, &[&v, &[0x00]]);
        v = hmac_k(&key, &[&v]);
    }
}

// `candidate_in_range` is private and, through `generate_k`'s rejection loop, only ever reached on
// candidates that -- for any real message/key input -- are essentially always in range, so no
// realistic integration test exercises its reject path; the QUALITY_AND_STYLE.md private-function
// exception applies. Known answers: `0` and `n` are the immediate out-of-range neighbours of the
// valid interval `[1, n-1]`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_in_range_boundary_cases() {
        assert!(!candidate_in_range(&[0u8; HLEN]));

        let mut one = [0u8; HLEN];
        one[HLEN - 1] = 1;
        assert!(candidate_in_range(&one));

        let n_bytes = p256k1_sec1::be_bytes_from_limbs(&N_LIMBS);
        assert!(!candidate_in_range(&n_bytes));

        let mut n_minus_1_bytes = n_bytes;
        *n_minus_1_bytes.last_mut().unwrap() -= 1; // N_LIMBS[0] is odd, so this never borrows
        assert!(candidate_in_range(&n_minus_1_bytes));

        assert!(!candidate_in_range(&[0xffu8; HLEN]));
    }
}
