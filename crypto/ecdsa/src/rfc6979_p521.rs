//! RFC 6979 §3.2 / FIPS 186-5 Appendix A.3.3: the deterministic per-message secret `k` for P-521,
//! fixed to SHA-512. Unlike [`crate::rfc6979`] (P-256/SHA-256) and [`crate::rfc6979_p384`]
//! (P-384/SHA-384), `qlen` (521, P-521's order's bit length) and `hlen` (512, SHA-512's output)
//! are **not equal** here, so the shortcuts those modules document (`bits2octets`/`int2octets`
//! needing no truncation, step h.2's loop always running exactly once) do not apply, and this
//! module implements RFC 6979 §3.2 in its general form:
//!
//! - `int2octets(d)`/`bits2octets(H)` still produce `rlen = 8*ceil(qlen/8) = 528` bits (66 bytes,
//!   [`RLEN`]) -- one byte wider than `HLEN`'s 64, with the extra byte's low 7 bits always `0`
//!   ([`P521Scalar::to_be_bytes`](bouncycastle_ec::p521_scalar::P521Scalar::to_be_bytes) and
//!   [`bits2octets`] both produce values already `< n < 2^521`, so their 66-byte big-endian form
//!   never sets those bits).
//! - Step h.2's "while `tlen < qlen`" loop runs **twice**: one `HMAC_K(V)` gives only 512 bits,
//!   short of the 521 needed, so a second round is required, giving `T` of length 1024 bits.
//! - Step h.3's `bits2int(T)` then keeps the **leftmost 521 bits** of that 1024-bit `T` (RFC 6979
//!   §2.3.2): the first 66 bytes, with the last byte's low 7 bits cleared (bit 520 is the only bit
//!   of that byte inside the leftmost-521-bit window) -- see [`bits2int_521`].

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::MAC;
use bouncycastle_ec::nat;
use bouncycastle_ec::p521_scalar::{N_LIMBS, P521Scalar};
use bouncycastle_ec::p521_sec1;
use bouncycastle_hmac::HMAC;
use bouncycastle_sha2::SHA512;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// SHA-512's output length in bytes.
const HLEN: usize = 64;

/// `rlen = 8*ceil(qlen/8)` for P-521's `qlen = 521`: the width `int2octets`/`bits2octets` produce.
const RLEN: usize = 66;

fn hmac_k(key: &[u8; HLEN], data: &[&[u8]]) -> [u8; HLEN] {
    let key_material = KeyMaterial::<HLEN>::from_bytes_as_type(key, KeyType::MACKey)
        .expect("HLEN-byte key always fits");
    let mut hmac =
        HMAC::<SHA512>::new_allow_weak_key(&key_material).expect("weak key always allowed");
    for piece in data {
        hmac.do_update(piece);
    }
    let mut out = [0u8; HLEN];
    hmac.do_final_out(&mut out).expect("HLEN-byte output buffer always fits HMAC-SHA512's output");
    out
}

/// RFC 6979 §2.3.4 `bits2octets(h1)`: `bits2int(h1)` (`h1` is exactly `HLEN` bytes = 512 bits,
/// `< qlen = 521` bits, so no truncation -- it is simply read as a big-endian integer), reduced
/// mod `n` (a single conditional subtraction: the value is `< 2^512 < n`, so this is a no-op in
/// practice, but kept for fidelity to the spec step), then `int2octets` to `RLEN` bytes.
fn bits2octets(h1: &[u8; HLEN]) -> [u8; RLEN] {
    let mut padded = [0u8; RLEN];
    padded[RLEN - HLEN..].copy_from_slice(h1);
    let limbs = p521_sec1::limbs_from_be_bytes(&padded);
    let (diff, borrow) = nat::sub(&limbs, &N_LIMBS);
    let mut reduced = [0u64; 9];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
    p521_sec1::be_bytes_from_limbs(&reduced)
}

/// RFC 6979 §2.3.2 `bits2int`, specialised to a 1024-bit input (two concatenated `HLEN`-byte `V`
/// values) and `qlen = 521`: keeps the leftmost 521 bits and discards the rest, per the module
/// docs. Returns the result directly as [`RLEN`] big-endian bytes (an integer `< 2^521`, so
/// [`p521_sec1::limbs_from_be_bytes`] on it is exactly `bits2int`'s value, matching
/// [`crate::rfc6979::candidate_in_range`]'s "compared to `n`, not reduced" step h.3 semantics).
///
/// Keeping "the leftmost 521 bits" as a *value* is not simply truncating the input to its first
/// 66 bytes and masking the last one -- that keeps each surviving bit in its *original* position,
/// which is `2^7` too large (`RLEN*8 - 521 = 7` unused low bits remain). The 66-byte prefix (`v1`
/// followed by `v2`'s first two bytes) must actually be shifted right by those 7 bits, carrying
/// bits across the byte boundary, to land the result in `[0, 2^521)` the way every other `<
/// 2^521` value in this crate is represented.
fn bits2int_521(v1: &[u8; HLEN], v2: &[u8; HLEN]) -> [u8; RLEN] {
    let mut prefix = [0u8; RLEN];
    prefix[..HLEN].copy_from_slice(v1);
    prefix[HLEN] = v2[0];
    prefix[HLEN + 1] = v2[1];

    let mut shifted = [0u8; RLEN];
    shifted[0] = prefix[0] >> 7;
    for i in 1..RLEN {
        // `prefix[i] >> 7` occupies only bit 0; `prefix[i - 1] << 1` occupies bits 1-7 (its own
        // top bit is shifted out) -- disjoint, so `|` and `^` agree here.
        shifted[i] = (prefix[i] >> 7) | (prefix[i - 1] << 1);
    }
    shifted
}

/// `true` iff the raw (unreduced) candidate bytes, read as a big-endian integer, are in `[1,
/// n-1]`. See [`crate::rfc6979::candidate_in_range`]'s docs.
fn candidate_in_range(candidate: &[u8; RLEN]) -> bool {
    let limbs = p521_sec1::limbs_from_be_bytes(candidate);
    if limbs == [0; 9] {
        return false;
    }
    let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
    borrow == 1
}

/// RFC 6979 §3.2 steps a-h: the deterministic per-message secret `k` for private key `d` and
/// message hash `h1 = H(m)`. See [`crate::rfc6979::generate_k`]'s docs; step h differs as
/// described in the module docs (two `HMAC_K(V)` rounds per candidate, then a 521-bit truncation).
pub fn generate_k(d: &P521Scalar, h1: &[u8; HLEN]) -> P521Scalar {
    let int2octets_d = d.to_be_bytes();
    let bits2octets_h1 = bits2octets(h1);

    let mut key = [0u8; HLEN];
    let mut v = [0x01u8; HLEN];

    key = hmac_k(&key, &[&v, &[0x00], &int2octets_d, &bits2octets_h1]);
    v = hmac_k(&key, &[&v]);
    key = hmac_k(&key, &[&v, &[0x01], &int2octets_d, &bits2octets_h1]);
    v = hmac_k(&key, &[&v]);

    loop {
        let v1 = hmac_k(&key, &[&v]);
        let v2 = hmac_k(&key, &[&v1]);
        v = v2;
        let candidate = bits2int_521(&v1, &v2);
        if candidate_in_range(&candidate) {
            return P521Scalar::from_limbs(p521_sec1::limbs_from_be_bytes(&candidate));
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
        assert!(!candidate_in_range(&[0u8; RLEN]));

        let mut one = [0u8; RLEN];
        one[RLEN - 1] = 1;
        assert!(candidate_in_range(&one));

        let n_bytes = p521_sec1::be_bytes_from_limbs(&N_LIMBS);
        assert!(!candidate_in_range(&n_bytes));

        let mut n_minus_1_bytes = n_bytes;
        *n_minus_1_bytes.last_mut().unwrap() -= 1;
        assert!(candidate_in_range(&n_minus_1_bytes));

        assert!(!candidate_in_range(&[0xffu8; RLEN]));
    }

    #[test]
    fn bits2int_521_all_ones_gives_2_pow_521_minus_1() {
        // The leftmost 521 bits of an all-ones 1024-bit string are 521 ones, i.e. 2^521 - 1: as a
        // right-aligned 66-byte value, a single set bit in the top byte (0b00000001) followed by
        // 65 bytes of 0xff (520 more one-bits).
        let v1 = [0xffu8; HLEN];
        let v2 = [0xffu8; HLEN];
        let result = bits2int_521(&v1, &v2);
        assert_eq!(result[0], 0x01);
        assert_eq!(result[1..], [0xffu8; RLEN - 1]);
    }

    #[test]
    fn bits2int_521_drops_bit_521_and_beyond() {
        // v2's low 7 bits (the last 7 bits of the 1024-bit input, positions 521-527 of the
        // leftmost-521-bit window's complement) must never survive into the result: setting only
        // v2's very last bit must produce the same output as an all-zero v2.
        let v1 = [0u8; HLEN];
        let mut v2 = [0u8; HLEN];
        v2[HLEN - 1] = 0x01; // the least significant bit of the whole 1024-bit input
        let result = bits2int_521(&v1, &v2);
        assert_eq!(result, [0u8; RLEN]);
    }
}
