//! RFC 6979 §3.2 / FIPS 186-5 Appendix A.3.3: the deterministic per-message secret `k` for P-384,
//! fixed to SHA-384. Identical in shape to [`crate::rfc6979`] -- see that module's docs for the
//! full derivation -- with `HLEN = 48` (SHA-384's output) and P-384's types substituted. `qlen ==
//! hlen == 384` here too, so the same shortcuts collapse the same way, guarded by the same kind of
//! compile-time assertion.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::MAC;
use bouncycastle_ec::nat;
use bouncycastle_ec::p384_scalar::{N_LIMBS, P384Scalar};
use bouncycastle_ec::p384_sec1;
use bouncycastle_hmac::HMAC;
use bouncycastle_sha2::SHA384;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

const HLEN: usize = 48;

const _: () =
    assert!(HLEN * 8 == 384, "int2octets/bits2octets shortcuts assume hlen == qlen == 384");

fn hmac_k(key: &[u8; HLEN], data: &[&[u8]]) -> [u8; HLEN] {
    let key_material = KeyMaterial::<HLEN>::from_bytes_as_type(key, KeyType::MACKey)
        .expect("HLEN-byte key always fits");
    let mut hmac =
        HMAC::<SHA384>::new_allow_weak_key(&key_material).expect("weak key always allowed");
    for piece in data {
        hmac.do_update(piece);
    }
    let mut out = [0u8; HLEN];
    hmac.do_final_out(&mut out).expect("HLEN-byte output buffer always fits HMAC-SHA384's output");
    out
}

/// RFC 6979 §2.3.4 `bits2octets(h1)`. See [`crate::rfc6979::bits2octets`]'s docs.
fn bits2octets(h1: &[u8; HLEN]) -> [u8; HLEN] {
    let limbs = p384_sec1::limbs_from_be_bytes(h1);
    let (diff, borrow) = nat::sub(&limbs, &N_LIMBS);
    let mut reduced = [0u64; 6];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
    p384_sec1::be_bytes_from_limbs(&reduced)
}

/// `true` iff the raw (unreduced) candidate bytes, read as a big-endian integer, are in `[1,
/// n-1]`. See [`crate::rfc6979::candidate_in_range`]'s docs.
fn candidate_in_range(candidate: &[u8; HLEN]) -> bool {
    let limbs = p384_sec1::limbs_from_be_bytes(candidate);
    if limbs == [0, 0, 0, 0, 0, 0] {
        return false;
    }
    let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
    borrow == 1
}

/// RFC 6979 §3.2 steps a-h: the deterministic per-message secret `k` for private key `d` and
/// message hash `h1 = H(m)`. See [`crate::rfc6979::generate_k`]'s docs.
pub fn generate_k(d: &P384Scalar, h1: &[u8; HLEN]) -> P384Scalar {
    let int2octets_d = d.to_be_bytes();
    let bits2octets_h1 = bits2octets(h1);

    let mut key = [0u8; HLEN];
    let mut v = [0x01u8; HLEN];

    key = hmac_k(&key, &[&v, &[0x00], &int2octets_d, &bits2octets_h1]);
    v = hmac_k(&key, &[&v]);
    key = hmac_k(&key, &[&v, &[0x01], &int2octets_d, &bits2octets_h1]);
    v = hmac_k(&key, &[&v]);

    loop {
        v = hmac_k(&key, &[&v]);
        if candidate_in_range(&v) {
            return P384Scalar::from_limbs(p384_sec1::limbs_from_be_bytes(&v));
        }
        key = hmac_k(&key, &[&v, &[0x00]]);
        v = hmac_k(&key, &[&v]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_in_range_boundary_cases() {
        assert!(!candidate_in_range(&[0u8; HLEN]));

        let mut one = [0u8; HLEN];
        one[HLEN - 1] = 1;
        assert!(candidate_in_range(&one));

        let n_bytes = p384_sec1::be_bytes_from_limbs(&N_LIMBS);
        assert!(!candidate_in_range(&n_bytes));

        let mut n_minus_1_bytes = n_bytes;
        *n_minus_1_bytes.last_mut().unwrap() -= 1;
        assert!(candidate_in_range(&n_minus_1_bytes));

        assert!(!candidate_in_range(&[0xffu8; HLEN]));
    }
}
