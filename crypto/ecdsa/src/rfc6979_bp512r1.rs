//! RFC 6979 §3.2 / FIPS 186-5 Appendix A.3.3: the deterministic per-message secret `k` for
//! brainpoolP512r1, fixed to SHA-512 (the pairing wycheproof's `ecdsa_brainpoolP512r1_sha512_*`
//! vector files use). Identical in shape to [`crate::rfc6979_p384`] -- see that module's docs for
//! the full derivation -- with `HLEN = 64` (SHA-512's output) and brainpoolP512r1's types
//! substituted. `qlen == hlen == 512` here (this curve's `n` is 512 bits, unlike P-521's own
//! 521-bit `n` paired with the same hash), so the same shortcuts collapse the same way.
//! `bits2octets`'s single-conditional-subtraction reduction is valid for the same reason as the
//! other brainpool curves' own case: brainpoolP512r1's `n` has its top bit set (`n > 2^511`), so
//! `2n > 2^512` and any 512-bit input is already `< 2n`, despite `n` not being close to `2^512`.
//!
//! RFC 6979 has no official Appendix A.2.x-style test vectors for brainpool curves;
//! `rfc6979_bp512r1_vectors_tests.rs` cross-checks this implementation against an independent
//! Python implementation of the same RFC instead.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::MAC;
use bouncycastle_ec::bp512r1_scalar::{Bp512r1Scalar, N_LIMBS};
use bouncycastle_ec::bp512r1_sec1;
use bouncycastle_ec::nat;
use bouncycastle_hmac::HMAC;
use bouncycastle_sha2::SHA512;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

const HLEN: usize = 64;

const _: () =
    assert!(HLEN * 8 == 512, "int2octets/bits2octets shortcuts assume hlen == qlen == 512");

/// `HMAC_K(data)` (§3.1.1). See [`crate::rfc6979::hmac_k`]'s docs.
/// As [`crate::rfc6979::hmac_k`], including why this returns a [`Secret`] rather than a bare
/// array: see that function's docs and [`generate_k`]'s "What is scrubbed" section.
fn hmac_k(key: &[u8; HLEN], data: &[&[u8]]) -> Secret<[u8; HLEN]> {
    let key_material = KeyMaterial::<HLEN>::from_bytes_as_type(key, KeyType::MACKey)
        .expect("HLEN-byte key always fits");
    let mut hmac =
        HMAC::<SHA512>::new_allow_weak_key(&key_material).expect("weak key always allowed");
    for piece in data {
        hmac.do_update(piece);
    }
    let mut out = Secret::<[u8; HLEN]>::new();
    hmac.do_final_out(&mut *out).expect("HLEN-byte output buffer always fits HMAC-SHA512's output");
    out
}

/// RFC 6979 §2.3.4 `bits2octets(h1)`. See [`crate::rfc6979::bits2octets`]'s docs -- the same
/// single-subtraction argument applies here (see this module's own docs for why it holds despite
/// brainpoolP512r1's `n` not being close to `2^512`).
fn bits2octets(h1: &[u8; HLEN]) -> [u8; HLEN] {
    let limbs = bp512r1_sec1::limbs_from_be_bytes(h1);
    let (diff, borrow) = nat::sub(&limbs, &N_LIMBS);
    let mut reduced = [0u64; 8];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
    bp512r1_sec1::be_bytes_from_limbs(&reduced)
}

/// `true` iff the raw (unreduced) candidate bytes, read as a big-endian integer, are in `[1,
/// n-1]` -- RFC 6979 step h.3's comparison against `q`.
fn candidate_in_range(candidate: &[u8; HLEN]) -> bool {
    let limbs = bp512r1_sec1::limbs_from_be_bytes(candidate);
    if limbs == [0, 0, 0, 0, 0, 0, 0, 0] {
        return false;
    }
    let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
    borrow == 1
}

/// RFC 6979 §3.2 steps a-h: the deterministic per-message secret `k` for private key `d` and
/// message hash `h1 = H(m)`. See [`crate::rfc6979::generate_k`]'s docs for the rejection-loop
/// constant-time argument, which applies unchanged here.
pub fn generate_k(d: &Bp512r1Scalar, h1: &[u8; HLEN]) -> Bp512r1Scalar {
    let mut int2octets_d = Secret::<[u8; HLEN]>::new();
    *int2octets_d = d.to_be_bytes(); // §2.3.3, d already in [1, n-1]
    let bits2octets_h1 = bits2octets(h1);

    // step c
    let mut key = Secret::<[u8; HLEN]>::new();
    // step b
    let mut v = Secret::<[u8; HLEN]>::new();
    *v = [0x01u8; HLEN];

    // step d
    key = hmac_k(&key, &[&*v, &[0x00], &*int2octets_d, &bits2octets_h1]);
    // step e
    v = hmac_k(&key, &[&*v]);
    // step f
    key = hmac_k(&key, &[&*v, &[0x01], &*int2octets_d, &bits2octets_h1]);
    // step g
    v = hmac_k(&key, &[&*v]);

    // step h
    loop {
        // step h.1-h.2: T = HMAC_K(V) suffices in one round since tlen == qlen == HLEN*8 (see
        // module docs)
        v = hmac_k(&key, &[&*v]);
        if candidate_in_range(&v) {
            // in [1, n-1] already: from_limbs's reduction is a no-op safety net, not a real reduce
            return Bp512r1Scalar::from_limbs(bp512r1_sec1::limbs_from_be_bytes(&v));
        }
        key = hmac_k(&key, &[&*v, &[0x00]]);
        v = hmac_k(&key, &[&*v]);
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

        let n_bytes = bp512r1_sec1::be_bytes_from_limbs(&N_LIMBS);
        assert!(!candidate_in_range(&n_bytes));

        let mut n_minus_1_bytes = n_bytes;
        *n_minus_1_bytes.last_mut().unwrap() -= 1; // N_LIMBS[0] is odd, so this never borrows
        assert!(candidate_in_range(&n_minus_1_bytes));

        assert!(!candidate_in_range(&[0xffu8; HLEN]));
    }
}
