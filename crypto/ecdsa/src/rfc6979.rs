//! RFC 6979 Section 3.2 / FIPS 186-5 Appendix A.3.3: the deterministic per-message secret `k`,
//! once over the curve and the hash, in the RFC's general form. Quotes below are RFC 6979
//! Section 3.2's own lettered steps; FIPS 186-5 A.3.3 restates the same process in HMAC_DRBG
//! terms. `qlen` is the order's bit length (`C::ORDER_BITS`), `hlen` the hash output's
//! (`8 * H::OUTPUT_LEN`), `rlen = 8 * ceil(qlen / 8)` (`8 * C::SCALAR_LEN`); where `hlen == qlen`
//! the general steps collapse to the shortcuts a per-curve implementation would take (one
//! `HMAC_K(V)` round in step h.2, no truncation in `bits2int`), and where they differ (P-521 under
//! any hash here, any curve under a longer or shorter hash) the loop and the truncation do what the
//! RFC says. The buffers are sized for the largest hash and the most rounds any pairing here
//! needs, and held in `Secret`s.

use crate::ecdsa::{MAX_HASH_LEN, check_hash_fits, hash_to_limbs};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::FromAnyKeyMaterial;
use bouncycastle_core::traits::HashAlgParams;
use bouncycastle_ec::curve::{Curve, ScalarFieldElement, SecretScalar};
use bouncycastle_hmac::{HMACParams, HmacKey, hazmat as hmac_hazmat};
use bouncycastle_utils::secret::Secret;

/// The most `HMAC_K(V)` outputs step h.2 concatenates: `ceil(qlen / hlen)`, which is 3 for
/// P-521 under SHA-224.
pub(crate) const MAX_ROUNDS: usize = 3;

/// `HMAC_K(data)` (Section 3.1.1) over `H`, `data` in pieces, into `out`, `H::OUTPUT_LEN` bytes.
/// `K` is `hlen` bytes of HMAC_DRBG state derived from the private key (from `0x00..00` in step
/// c), not an application key, so it is taken at any strength; the output is the next state, or
/// `k` itself, so it goes into the caller's `Secret` rather than being returned.
fn hmac_k<H: HMACParams>(key: &[u8], data: &[&[u8]], out: &mut [u8]) {
    let key_material = KeyMaterial::<MAX_HASH_LEN>::from_bytes_as_type(key, KeyType::MACKey)
        .expect("the key is a hash output, at most MAX_HASH_LEN bytes");
    let hmac_key =
        HmacKey::<H>::from_key_material_allow_weak(&key_material).expect("weak key always allowed");
    let mut inner = hmac_hazmat::inner_state(&hmac_key);
    for piece in data {
        inner.do_update(piece);
    }
    hmac_hazmat::finish_out(&hmac_key, inner, out);
}

/// RFC 6979 Section 2.3.4 `bits2octets(h1)`: `bits2int(h1)` (Section 2.3.2: the leftmost
/// `qlen` bits when the hash is longer, zero-extended on the left when shorter), reduced mod `n`
/// (the value is below `2^qlen < 2n`, so one conditional subtraction, which the scalar field's
/// load performs), then `int2octets` to `rlen` bytes. `h1` is the public message hash, so there is
/// no constant-time obligation here; the branch-free form is the house style.
fn bits2octets<C: Curve, H: HashAlgParams>(h1: &[u8]) -> C::ScalarBytes {
    let reduced = C::ScalarField::from_limbs(hash_to_limbs::<C, H>(h1)).to_limbs();
    C::be_bytes_from_limbs(&reduced)
}

/// RFC 6979 Section 2.3.2 `bits2int(T)` for step h.3: `T` is `rounds * hlen` bits, at least
/// `qlen`, and the leftmost `qlen` are kept, as the value `T >> (tlen - qlen)`. Byte-wise: the
/// first `rlen / 8` bytes shifted right by `rlen - qlen` bits (7 for P-521, 0 where `qlen` is a
/// multiple of 8), carrying across the byte boundaries; keeping the bytes and masking the last
/// one would leave every bit `2^(rlen - qlen)` too high.
fn bits2int_leftmost<C: Curve>(t: &[u8], out: &mut C::ScalarBytes) {
    let rlen_bytes = C::SCALAR_LEN;
    let shift = 8 * rlen_bytes - C::ORDER_BITS;
    let prefix = &t[..rlen_bytes];
    let out = out.as_mut();
    if shift == 0 {
        out.copy_from_slice(prefix);
        return;
    }
    out[0] = prefix[0] >> shift;
    for i in 1..rlen_bytes {
        // `prefix[i] >> shift` occupies the low 8 - shift bits and `prefix[i - 1] << (8 - shift)`
        // the high shift bits: disjoint, so `|` and `^` agree here. (The only non-zero shift
        // among this crate's curves is P-521's 7, where 8 - 7 and 8 / 7 are both 1, so that
        // mutant is equivalent too.)
        out[i] = (prefix[i] >> shift) | (prefix[i - 1] << (8 - shift));
    }
}

/// RFC 6979 Section 3.2 steps a-h: the deterministic per-message secret `k` for private key `d`
/// and message hash `h1 = H(m)`.
///
/// # What is scrubbed
///
/// `int2octets(d)`, `K`, `V`, `T` and the candidate are derived from the private key (and the
/// accepted candidate is `k` itself), so they live in [`Secret`]s and are erased when this
/// function returns rather than left on the stack. `bits2octets(h1)` is not wrapped: it derives
/// from the public message hash. One copy is outside this function's reach: `d.to_be_bytes()`
/// hands back a plain array by design, copied into the `Secret` and not itself erased.
///
/// # The rejection loop
///
/// Step h.3's "otherwise ... loop" is the one place this crate's constant-time rules permit
/// branching on a value derived from a secret; the crate docs list it as an exception. The
/// iteration count is a function of the HMAC_DRBG output stream, PRF outputs under a key derived
/// from `(d, h1)`, so under the PRF assumption it is independent of the accepted `k`, which,
/// conditioned on the count, is uniform on `[1, n-1]`, and reveals nothing about `d`. The
/// argument does not rely on a rejected candidate being discarded, which the chaining never
/// satisfies; what must be constant time is everything subsequently done with the accepted `k`.
/// What differs by curve is the rate: on the NIST curves and secp256k1, whose `n` is within
/// `2^-32` of `2^qlen`, the loop is close to dead; on the brainpool curves, whose `n` is not near
/// a power of two, a candidate is rejected with probability `1 - n / 2^qlen`, about 0.34 on
/// brainpoolP256r1, 0.45 on brainpoolP384r1 and 0.41 on brainpoolP512r1, so a third to a half of
/// signatures run the branch at least once, each extra iteration three more HMAC calls, which a
/// remote observer can time. The count is deterministic per `(d, msg)`, so the timing pattern
/// over chosen messages is a fingerprint worth one to two bits per message: useless for
/// recovering `d`, usable for confirming a candidate `d` an attacker already holds.
///
/// The loop rejects only out-of-range candidates. RFC 6979 Section 3.4 would also loop on a `k`
/// giving `r = 0`; this crate follows FIPS 186-5 Section 6.4.1 step 11 instead, under which
/// deterministic signing outputs failure there (see the crate docs' Security Considerations).
pub(crate) fn generate_k<C: Curve, H: HMACParams>(d: &C::Scalar, h1: &[u8]) -> C::Scalar {
    const { check_hash_fits::<C, H>() };
    let hlen = H::OUTPUT_LEN;
    let rounds = C::ORDER_BITS.div_ceil(8 * hlen);

    let mut int2octets_d = Secret::<C::ScalarBytes>::new();
    *int2octets_d = d.to_be_bytes(); // Section 2.3.3, d already in [1, n-1]
    let bits2octets_h1 = bits2octets::<C, H>(h1);

    // step c: K = 0x00 0x00 ... (hlen bytes), as the Secret is born
    let mut key = Secret::<[u8; MAX_HASH_LEN]>::new();
    // step b: V = 0x01 0x01 ... (hlen bytes)
    let mut v = Secret::<[u8; MAX_HASH_LEN]>::new();
    v[..hlen].fill(0x01);
    // each HMAC lands here and is copied over K or V, since the key is borrowed while it runs
    let mut next = Secret::<[u8; MAX_HASH_LEN]>::new();

    // step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    hmac_k::<H>(
        &key[..hlen],
        &[&v[..hlen], &[0x00], (*int2octets_d).as_ref(), bits2octets_h1.as_ref()],
        &mut next[..hlen],
    );
    key.copy_from_slice(&*next);
    // step e: V = HMAC_K(V)
    hmac_k::<H>(&key[..hlen], &[&v[..hlen]], &mut next[..hlen]);
    v.copy_from_slice(&*next);
    // step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    hmac_k::<H>(
        &key[..hlen],
        &[&v[..hlen], &[0x01], (*int2octets_d).as_ref(), bits2octets_h1.as_ref()],
        &mut next[..hlen],
    );
    key.copy_from_slice(&*next);
    // step g: V = HMAC_K(V)
    hmac_k::<H>(&key[..hlen], &[&v[..hlen]], &mut next[..hlen]);
    v.copy_from_slice(&*next);

    // step h
    let mut t = Secret::<[u8; MAX_ROUNDS * MAX_HASH_LEN]>::new();
    let mut candidate = Secret::<C::ScalarBytes>::new();
    let mut limbs = Secret::<C::Limbs>::new();
    loop {
        // h.1-h.2: T = V_1 || V_2 || ... until tlen >= qlen, each V = HMAC_K(V)
        for round in 0..rounds {
            hmac_k::<H>(&key[..hlen], &[&v[..hlen]], &mut next[..hlen]);
            v.copy_from_slice(&*next);
            t[round * hlen..(round + 1) * hlen].copy_from_slice(&v[..hlen]);
        }
        // h.3: k = bits2int(T), "compared to q, not reduced modulo q"
        bits2int_leftmost::<C>(&t[..rounds * hlen], &mut candidate);
        C::limbs_from_be_bytes_into(&candidate, &mut limbs);
        if C::scalar_in_range(&limbs).to_bool() {
            // in [1, n-1] already: the load's reduction is a no-op
            return C::Scalar::from_borrowed_limbs(&limbs);
        }
        // otherwise: K = HMAC_K(V || 0x00), V = HMAC_K(V), and loop
        hmac_k::<H>(&key[..hlen], &[&v[..hlen], &[0x00]], &mut next[..hlen]);
        key.copy_from_slice(&*next);
        hmac_k::<H>(&key[..hlen], &[&v[..hlen]], &mut next[..hlen]);
        v.copy_from_slice(&*next);
    }
}
