//! RFC 6979 §3.2 / FIPS 186-5 Appendix A.3.3: the deterministic per-message secret `k`, fixed to
//! SHA-256 (this crate's only supported hash so far -- see [`crate`]'s module docs). Quotes below
//! are RFC 6979 §3.2's own lettered steps; FIPS 186-5 A.3.3 restates the same process in
//! HMAC_DRBG terms (steps 1.1-1.9, 2-5), cited alongside where the two differ in presentation.
//!
//! `HLEN` (SHA-256's output) and `qlen` (`n`'s bit length, 256 for P-256) are equal here, which
//! collapses two of RFC 6979's general steps: `int2octets`/`bits2octets` (§2.3.3/§2.3.4) need no
//! truncation-or-padding step because a 32-byte value already has exactly `rlen = 256` bits, and
//! step h.2's "while tlen < qlen" loop always runs its body exactly once, since one `HMAC_K(V)`
//! already produces `qlen` bits of `T`. Neither shortcut is taken silently: the `const` assertion
//! below fails to compile if this crate ever gains a curve/hash pairing where they don't hold.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::MAC;
use bouncycastle_ec::nat;
use bouncycastle_ec::p256_scalar::{N_LIMBS, P256Scalar};
use bouncycastle_ec::p256_sec1;
use bouncycastle_hmac::HMAC;
use bouncycastle_sha2::SHA256;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

const HLEN: usize = 32;

const _: () =
    assert!(HLEN * 8 == 256, "int2octets/bits2octets shortcuts assume hlen == qlen == 256");

/// `HMAC_K(data)` (§3.1.1), `data` passed as multiple pieces so callers don't need to concatenate
/// into one buffer first.
///
/// Returns a [`Secret`], not a bare array: every value this produces is HMAC_DRBG state derived
/// from the private key, and the last one produced *is* `k`. Returning `Secret` means each is
/// scrubbed when it is dropped -- including the previous `key`/`v` that [`generate_k`]'s next step
/// overwrites -- without disturbing that function's one-line-per-RFC-step shape.
/// `new_allow_weak_key`: every `K` used here is 32 synthetic bytes from this same construction
/// (starting from `0x00...00` in step c), not an application key, so there is no real "security
/// strength" for [`KeyMaterial::from_bytes`] to have under- or over-estimated.
fn hmac_k(key: &[u8; HLEN], data: &[&[u8]]) -> Secret<[u8; HLEN]> {
    let key_material = KeyMaterial::<HLEN>::from_bytes_as_type(key, KeyType::MACKey)
        .expect("HLEN-byte key always fits");
    let mut hmac =
        HMAC::<SHA256>::new_allow_weak_key(&key_material).expect("weak key always allowed");
    for piece in data {
        hmac.do_update(piece);
    }
    let mut out = Secret::<[u8; HLEN]>::new();
    hmac.do_final_out(&mut *out).expect("HLEN-byte output buffer always fits HMAC-SHA256's output");
    out
}

/// RFC 6979 §2.3.4 `bits2octets(h1)`: reduce the message hash `h1` mod `n`, then §2.3.3
/// `int2octets`. `h1` is `bits2int`'d as-is (no truncation: `blen == qlen`), so this is one
/// conditional subtraction -- the same single-subtraction argument
/// [`P256Scalar::from_limbs`](bouncycastle_ec::p256_scalar::P256Scalar::from_limbs) documents for
/// any 256-bit input against a modulus this close to `2^256`. `h1` is a public message hash, not a
/// secret, so there is no constant-time obligation here; the branch-free form is used anyway to
/// match this crate's house style.
fn bits2octets(h1: &[u8; HLEN]) -> [u8; HLEN] {
    let limbs = p256_sec1::limbs_from_be_bytes(h1);
    let (diff, borrow) = nat::sub(&limbs, &N_LIMBS);
    let mut reduced = [0u64; 4];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
    p256_sec1::be_bytes_from_limbs(&reduced)
}

/// `true` iff the raw (unreduced) candidate bytes, read as a big-endian integer, are in `[1,
/// n-1]` -- RFC 6979 step h.3's comparison against `q`, "not reduced modulo q" (§3.2, footnote to
/// step h).
fn candidate_in_range(candidate: &[u8; HLEN]) -> bool {
    let limbs = p256_sec1::limbs_from_be_bytes(candidate);
    if limbs == [0, 0, 0, 0] {
        return false;
    }
    let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
    borrow == 1
}

/// RFC 6979 §3.2 steps a-h: the deterministic per-message secret `k` for private key `d` and
/// message hash `h1 = H(m)`.
///
/// # What is scrubbed
///
/// `int2octets(d)`, `key` and `v` are all derived from the private key (and `v` ends up holding
/// `k` itself), so all three live in [`Secret`] and are erased when this function returns rather
/// than left on the stack for whatever runs next -- matching how `bouncycastle_mlkem` and
/// `bouncycastle_mldsa` treat their own secret stack intermediates. `bits2octets(h1)` is not
/// wrapped: it derives from the public message hash, not from `d`.
///
/// One copy is outside this function's reach: `d.to_be_bytes()` hands back a plain array by
/// design (see [`P256Scalar::to_be_bytes`](bouncycastle_ec::p256_scalar::P256Scalar::to_be_bytes),
/// whose own docs note it "momentarily holds the plain value ... the caller asked for the bytes"),
/// so that transient is copied into the `Secret` above but the transient itself is not erased.
///
/// The rejection loop (step h.3, "otherwise ... loop") is the one place this crate's own
/// constant-time rules permit branching on a value derived from a secret. The position, which
/// applies equally to FIPS 186-5 Appendix A.3.2's and A.4.2's identical loops: a rejection loop is
/// acceptable when a rejected candidate is discarded entirely and nothing derived from it is ever
/// used, because the only thing its iteration count can reveal is how many candidates were
/// rejected -- and that is independent of the `k` finally returned. What must be constant time is
/// everything subsequently done *with* the accepted `k`, which is the rest of this crate's
/// concern. For P-256 the question is close to moot anyway: `n` is within `2^-32` of `2^256`, so a
/// candidate is rejected with negligible probability.
pub fn generate_k(d: &P256Scalar, h1: &[u8; HLEN]) -> P256Scalar {
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
            return P256Scalar::from_limbs(p256_sec1::limbs_from_be_bytes(&v));
        }
        key = hmac_k(&key, &[&*v, &[0x00]]);
        v = hmac_k(&key, &[&*v]);
    }
}

// `candidate_in_range` is private and, through `generate_k`'s rejection loop, only ever reached on
// candidates that -- for any real message/key input -- are essentially always in range (RFC 6979
// §3.4: rejection is "utterly improbable"), so no realistic integration test exercises its reject
// path; the QUALITY_AND_STYLE.md private-function exception applies. Known answers: `0` and `n`
// are the immediate out-of-range neighbours of the valid interval `[1, n-1]`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_in_range_boundary_cases() {
        assert!(!candidate_in_range(&[0u8; HLEN]));

        let mut one = [0u8; HLEN];
        one[HLEN - 1] = 1;
        assert!(candidate_in_range(&one));

        let n_bytes = p256_sec1::be_bytes_from_limbs(&N_LIMBS);
        assert!(!candidate_in_range(&n_bytes));

        let mut n_minus_1_bytes = n_bytes;
        *n_minus_1_bytes.last_mut().unwrap() -= 1; // N_LIMBS[0] is odd, so this never borrows
        assert!(candidate_in_range(&n_minus_1_bytes));

        assert!(!candidate_in_range(&[0xffu8; HLEN]));
    }
}
