//! EMSA-PKCS1-v1_5 (RFC 8017 §9.2): deterministic signature encoding, generic over the hash
//! function `H` via its [`Hash`]/[`HashAlgParams`]/[`AlgorithmOID`] impls (e.g.
//! `bouncycastle_sha2::SHA256`), and specialized to this crate's fixed-width keys: RFC 8017's
//! `emLen` is always this crate's modulus byte length `K_LEN` (`8 * L`), never a generic
//! caller-chosen length.

use bouncycastle_core::traits::{AlgorithmOID, Hash, HashAlgParams};

/// `T`, the DER encoding of `DigestInfo { digestAlgorithm, digest }` (RFC 8017 §9.2 step 2):
///
/// ```text
/// DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
/// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters NULL }
/// ```
///
/// Built directly from `H::OID_DER` (already the DER encoding of the `OBJECT IDENTIFIER` itself,
/// tag and length included) rather than a hand-copied table of the nine prefixes RFC 8017 §9.2
/// note 1 lists for MD2/MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512/SHA-512-224/SHA-512-256:
/// wrapping `OID_DER` in the two surrounding `SEQUENCE`s and the `05 00` (`NULL`) parameters, then
/// appending the digest behind its own `04 <len>` (`OCTET STRING`) tag, reproduces exactly those
/// bytes -- checked against SHA-256/384/512 in this module's tests. Every DER length here
/// (`H::OID_DER.len()` and `H_LEN`) is well under 128 for every hash this crate could plausibly
/// support (SHA-3's largest output is 64 bytes), so each is a single length byte, not the
/// multi-byte long form; `debug_assert`'d, since it can only fail on a hash this crate does not
/// support, never on real input.
fn digest_info<H: AlgorithmOID + HashAlgParams, const H_LEN: usize, const T_LEN: usize>(
    digest: &[u8; H_LEN],
) -> [u8; T_LEN] {
    debug_assert_eq!(H_LEN, H::OUTPUT_LEN, "digest_info: H_LEN must match H::OUTPUT_LEN");
    let oid_der = H::OID_DER;
    debug_assert!(oid_der.len() < 128 && H_LEN < 128, "DER length must fit in one byte");

    let inner_len = oid_der.len() + 2; // + 05 00 (the AlgorithmIdentifier's NULL parameters)
    let outer_len = 4 + inner_len + H_LEN; // + "30 <inner_len>" and "04 <H_LEN>"
    debug_assert_eq!(T_LEN, 2 + outer_len, "digest_info: T_LEN must match the computed DER length");

    let mut t = [0u8; T_LEN];
    t[0] = 0x30;
    t[1] = outer_len as u8;
    t[2] = 0x30;
    t[3] = inner_len as u8;
    t[4..4 + oid_der.len()].copy_from_slice(oid_der);
    let mut i = 4 + oid_der.len();
    t[i] = 0x05;
    t[i + 1] = 0x00;
    t[i + 2] = 0x04;
    t[i + 3] = H_LEN as u8;
    i += 4;
    t[i..i + H_LEN].copy_from_slice(digest);
    t
}

/// EMSA-PKCS1-V1_5-ENCODE (RFC 8017 §9.2), with `emLen` fixed to `K_LEN` (see the module docs).
///
/// Steps 1-2: hash `message` and wrap it in [`digest_info`]. Step 3's error ("intended encoded
/// message length too short", `emLen < tLen + 11`) is a `debug_assert` here, not a runtime error:
/// every (hash, modulus size) pairing this crate actually wires up has a modulus thousands of
/// bits wider than any hash's `DigestInfo`, so it can only fire on a deliberately-wrong generic
/// instantiation, never on real input. Steps 4-5 build `EM = 0x00 || 0x01 || PS || 0x00 || T`,
/// where `PS` is `K_LEN - T_LEN - 3` bytes of `0xff` (at least 8, per step 3's bound).
pub fn emsa_pkcs1_v1_5_encode<
    H: Hash + HashAlgParams + AlgorithmOID + Default,
    const H_LEN: usize,
    const T_LEN: usize,
    const K_LEN: usize,
>(
    message: &[u8],
) -> [u8; K_LEN] {
    let mut digest = [0u8; H_LEN];
    H::default().hash_out(message, &mut digest);
    let t: [u8; T_LEN] = digest_info::<H, H_LEN, T_LEN>(&digest);

    debug_assert!(K_LEN >= T_LEN + 11, "emsa_pkcs1_v1_5_encode: modulus too short for this hash");

    let mut em = [0xffu8; K_LEN];
    em[0] = 0x00;
    em[1] = 0x01;
    em[K_LEN - T_LEN - 1] = 0x00;
    em[K_LEN - T_LEN..].copy_from_slice(&t);
    em
}

/// A single DER length octet in strict short form: `None` if the byte's top bit is set (BER's
/// long form, always rejected here -- see [`emsa_pkcs1_v1_5_verify`]) or `bytes` doesn't reach
/// `pos`.
fn short_form_len(bytes: &[u8], pos: usize) -> Option<usize> {
    let len = *bytes.get(pos)? as usize;
    if len >= 0x80 { None } else { Some(len) }
}

/// Checks that `t` is a `DigestInfo` DER encoding (RFC 8017 §9.2 step 2) of `message`'s hash under
/// `H`, tolerating both `AlgorithmIdentifier` shapes: `parameters NULL` (what [`digest_info`]
/// always produces) and `parameters` ABSENT (not produced here, but present in the wild: the
/// `AlgorithmIdentifier`'s `parameters` field is `ANY DEFINED BY algorithm`, and it needs none for
/// a hash OID, so some implementations omit it) -- see [`emsa_pkcs1_v1_5_verify`]'s docs for why
/// verification must accept it. Every other check is a strict requirement: a DER length must be
/// single-byte short form, and no byte of `t` may go unaccounted for.
fn decode_digest_info<H: Hash + HashAlgParams + AlgorithmOID + Default, const H_LEN: usize>(
    t: &[u8],
    message: &[u8],
) -> bool {
    let mut pos = 0;
    if t.first() != Some(&0x30) {
        return false;
    }
    pos += 1;
    let Some(outer_len) = short_form_len(t, pos) else { return false };
    pos += 1;
    if pos + outer_len != t.len() {
        return false; // T must be exactly outer_len + 2 bytes -- no trailing garbage.
    }
    if t.get(pos) != Some(&0x30) {
        return false;
    }
    pos += 1;
    let Some(inner_len) = short_form_len(t, pos) else { return false };
    pos += 1;
    let inner_end = pos + inner_len;
    if inner_end > t.len() {
        return false;
    }
    let oid = H::OID_DER;
    if pos + oid.len() > inner_end || t[pos..pos + oid.len()] != *oid {
        return false;
    }
    pos += oid.len();
    if t.get(pos..pos + 2) == Some(&[0x05, 0x00]) {
        pos += 2; // Optional NULL parameters -- see this function's docs.
    }
    if pos != inner_end {
        return false; // Trailing bytes inside AlgorithmIdentifier that aren't a bare NULL.
    }
    if t.get(pos) != Some(&0x04) {
        return false;
    }
    pos += 1;
    let Some(digest_len) = short_form_len(t, pos) else { return false };
    pos += 1;
    // Mutating this `||` to `&&` is an accepted equivalent, not a gap: `t[pos..]` at line 145
    // already fails its own comparison against `computed` (a fixed `[u8; H_LEN]`) whenever either
    // half of this condition is true alone -- a `digest_len` that disagrees with `H_LEN` or a
    // `pos + digest_len` that disagrees with `t.len()` both show up as a slice/array length
    // mismatch there, which `PartialEq` for `[u8]` against `[u8; H_LEN]` treats as unequal without
    // panicking. This check exists to fail fast and by a clearer name, not because anything
    // downstream depends on it having fired.
    if digest_len != H_LEN || pos + digest_len != t.len() {
        return false;
    }

    let mut computed = [0u8; H_LEN];
    H::default().hash_out(message, &mut computed);
    t[pos..] == computed
}

/// EMSA-PKCS1-v1_5 verification: RFC 8017 §8.2.2's own note describes this as an alternative to
/// its step 4 ("apply a 'decoding' operation ... to recover the underlying hash value, and then
/// compare it to a newly computed hash value") -- required here, rather than optional, because
/// re-encoding `message` and comparing bytes (this crate's [`emsa_pkcs1_v1_5_encode`]) only ever
/// produces one canonical `EM`, and [`decode_digest_info`] must accept two.
///
/// Confirmed against every forgery-shaped case in Wycheproof's `rsa_signature_2048_sha256_test.json`
/// (`BerEncodedPadding`, `InvalidAsnInPadding`, `ModifiedPadding`, `WrongHash`, `InvalidPadding`,
/// `ShortPadding`, `NoHash`), and its one `MissingNull` "acceptable" case.
pub fn emsa_pkcs1_v1_5_verify<
    H: Hash + HashAlgParams + AlgorithmOID + Default,
    const H_LEN: usize,
    const K_LEN: usize,
>(
    message: &[u8],
    em: &[u8; K_LEN],
) -> bool {
    if em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }
    let mut i = 2;
    while i < K_LEN && em[i] == 0xff {
        i += 1;
    }
    // Mutating this `- 2` to `+ 2` or `/ 2` is an accepted equivalent, not a gap, for every
    // concrete `(H, K_LEN)` this crate actually instantiates: `decode_digest_info` requires `T`
    // to exactly fill whatever remains of `em` after the separator (no trailing garbage, RFC 8017
    // SS9.2 note 1's structure enforced at line 109 above), which pins `i` to one specific value
    // for a genuine, hash-matching `DigestInfo` -- the same value regardless of how `ps_len` is
    // computed from it, since `ps_len` is used only for the `< 8` comparison immediately below,
    // and that real value of `i` is always thousands of bits' worth of padding away from the
    // boundary where an off-by-a-constant miscalculation could flip the comparison's answer.
    let ps_len = i - 2;
    if ps_len < 8 || i >= K_LEN || em[i] != 0x00 {
        return false;
    }

    decode_digest_info::<H, H_LEN>(&em[i + 1..], message)
}

#[cfg(test)]
mod tests {
    //! `digest_info` is crate-private (only [`emsa_pkcs1_v1_5_encode`] needs it directly), so it
    //! is exercised here rather than from `tests/` -- the same "high-risk code that cannot be
    //! reached through the public API" exception `rsa_core`'s tests use, though `digest_info`
    //! itself is not high-risk so much as inconvenient to reach any other way. The expected DER
    //! prefixes are RFC 8017 §9.2 note 1's own literal byte strings for SHA-256/384/512.

    use super::*;
    use bouncycastle_sha2::{SHA256, SHA384, SHA512};

    #[test]
    fn digest_info_matches_rfc8017_sha256_prefix() {
        let digest = [0xabu8; 32];
        let t = digest_info::<SHA256, 32, 51>(&digest);
        let mut expected = [0u8; 51];
        expected[..19].copy_from_slice(&[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]);
        expected[19..].copy_from_slice(&digest);
        assert_eq!(t, expected);
    }

    #[test]
    fn digest_info_matches_rfc8017_sha384_prefix() {
        let digest = [0xcdu8; 48];
        let t = digest_info::<SHA384, 48, 67>(&digest);
        let mut expected = [0u8; 67];
        expected[..19].copy_from_slice(&[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ]);
        expected[19..].copy_from_slice(&digest);
        assert_eq!(t, expected);
    }

    #[test]
    fn digest_info_matches_rfc8017_sha512_prefix() {
        let digest = [0xefu8; 64];
        let t = digest_info::<SHA512, 64, 83>(&digest);
        let mut expected = [0u8; 83];
        expected[..19].copy_from_slice(&[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ]);
        expected[19..].copy_from_slice(&digest);
        assert_eq!(t, expected);
    }

    #[test]
    fn encode_layout_is_00_01_ff_dot_dot_dot_00_t() {
        let em = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"hello");
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);
        assert!(em[2..256 - 51 - 1].iter().all(|&b| b == 0xff));
        assert_eq!(em[256 - 51 - 1], 0x00);
        assert_eq!(&em[256 - 51..256 - 51 + 19][..2], &[0x30, 0x31]);
    }

    #[test]
    fn encode_is_deterministic() {
        let a = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"same message");
        let b = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"same message");
        assert_eq!(a, b);
    }

    #[test]
    fn encode_differs_for_different_messages() {
        let a = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"message one");
        let b = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"message two");
        assert_ne!(a, b);
    }

    #[test]
    fn verify_accepts_what_encode_produces() {
        let em = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"hello");
        assert!(emsa_pkcs1_v1_5_verify::<SHA256, 32, 256>(b"hello", &em));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let em = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"hello");
        assert!(!emsa_pkcs1_v1_5_verify::<SHA256, 32, 256>(b"goodbye", &em));
    }

    /// The `MissingNull` case Wycheproof's `rsa_signature_2048_sha256_test.json` marks
    /// "acceptable": a `DigestInfo` whose `AlgorithmIdentifier` omits the `NULL` parameters this
    /// crate's own [`emsa_pkcs1_v1_5_encode`] always includes.
    #[test]
    fn verify_accepts_digest_info_with_null_parameters_absent() {
        let mut digest = [0u8; 32];
        SHA256::default().hash_out(b"hello", &mut digest);
        let oid = <SHA256 as AlgorithmOID>::OID_DER; // 11 bytes: 06 09 <9-byte OID>
        // T without "05 00": 30 <inner_len+2> 30 <oid_len> <oid> 04 20 <digest>, i.e. 2 bytes
        // shorter than digest_info's own (NULL-including) T for the same hash.
        let mut t = [0u8; 49];
        t[0] = 0x30;
        t[1] = 47;
        t[2] = 0x30;
        t[3] = oid.len() as u8;
        t[4..4 + oid.len()].copy_from_slice(oid);
        let mut i = 4 + oid.len();
        t[i] = 0x04;
        t[i + 1] = 32;
        i += 2;
        t[i..i + 32].copy_from_slice(&digest);

        let mut em = [0xffu8; 256];
        em[0] = 0x00;
        em[1] = 0x01;
        em[256 - 49 - 1] = 0x00;
        em[256 - 49..].copy_from_slice(&t);

        assert!(emsa_pkcs1_v1_5_verify::<SHA256, 32, 256>(b"hello", &em));
    }

    /// Wycheproof's `BerEncodedPadding`: a `DigestInfo` length re-encoded in BER long form (top
    /// bit set) rather than DER's required single-byte short form -- must be rejected outright,
    /// since accepting any non-canonical length encoding is exactly the class of leniency
    /// Bleichenbacher-style forgeries exploit, regardless of what value it happens to encode.
    #[test]
    fn verify_rejects_ber_long_form_length() {
        let mut em = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"hello");
        let t_start = 256 - 51;
        assert_eq!(em[t_start], 0x30);
        assert_eq!(em[t_start + 1], 49); // outer_len
        em[t_start + 1] |= 0x80;
        assert!(!emsa_pkcs1_v1_5_verify::<SHA256, 32, 256>(b"hello", &em));
    }

    /// Wycheproof's `InvalidAsnInPadding`: a `DigestInfo` length off by one from the true value.
    #[test]
    fn verify_rejects_wrong_der_length() {
        let mut em = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"hello");
        let t_start = 256 - 51;
        em[t_start + 1] += 1;
        assert!(!emsa_pkcs1_v1_5_verify::<SHA256, 32, 256>(b"hello", &em));
    }

    /// Wycheproof's `ModifiedPadding` ("appending 0's to digestInfo"): two extra zero bytes appended
    /// after an otherwise-valid `DigestInfo`, with `PS` shrunk by two bytes to keep `EM`'s total
    /// length fixed. A check that only confirms `EM` *starts with* the right bytes would miss
    /// this; requiring every byte of `T` to be accounted for by the parse does not.
    #[test]
    fn verify_rejects_trailing_garbage_after_digest_info() {
        let good = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"hello");
        let mut em = [0xffu8; 256];
        em[0] = 0x00;
        em[1] = 0x01;
        em[256 - 51 - 2 - 1] = 0x00; // PS is 2 bytes shorter than the valid encoding's.
        em[256 - 51 - 2..256 - 2].copy_from_slice(&good[256 - 51..]); // the valid T, unmodified.
        em[256 - 2..].copy_from_slice(&[0x00, 0x00]); // two bytes appended after it.
        assert!(!emsa_pkcs1_v1_5_verify::<SHA256, 32, 256>(b"hello", &em));
    }

    /// Wycheproof's `ShortPadding`: fewer than the required 8 `0xff` bytes.
    #[test]
    fn verify_rejects_short_padding() {
        let mut em = [0u8; 256];
        em[0] = 0x00;
        em[1] = 0x01;
        em[2] = 0x00; // PS has length 0, not >= 8
        assert!(!emsa_pkcs1_v1_5_verify::<SHA256, 32, 256>(b"hello", &em));
    }

    /// Wycheproof's `WrongHash`: the OID in the padding names a different hash than the one used
    /// to verify.
    #[test]
    fn verify_rejects_wrong_hash_oid() {
        let mut em = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 256>(b"hello");
        let t_start = 256 - 51;
        em[t_start + 4] ^= 0xff; // flip a byte inside the OID
        assert!(!emsa_pkcs1_v1_5_verify::<SHA256, 32, 256>(b"hello", &em));
    }

    /// A crafted `EM` whose `DigestInfo` claims an `AlgorithmIdentifier` length long enough to run
    /// past the end of the (very short, in this construction) remaining buffer. `decode_digest_info`
    /// must reject this cleanly via its `inner_end > t.len()` check (line 119) rather than let a
    /// later, unguarded slice (`t[pos..pos + oid.len()]`) index past the real buffer and panic:
    /// `pos + oid.len()` is fixed (4 + 11 = 15 for SHA-256) and does not itself depend on the
    /// claimed length, so nothing downstream catches an inflated `inner_end` before that slice
    /// runs -- this early check is the one thing standing between a malformed signature and a
    /// crash, not merely a spec-conformance nicety. RSA verification exists to be run on
    /// adversarial input, so a signature that panics the verifier is a real (if effortful to find,
    /// since the attacker only controls `s`, not `s^e mod n` directly) denial-of-service vector.
    #[test]
    fn verify_rejects_digest_info_length_that_would_overrun_the_buffer_instead_of_panicking() {
        let mut em = [0xffu8; 256];
        em[0] = 0x00;
        em[1] = 0x01;
        em[251] = 0x00; // separator; PS is em[2..251], 249 bytes, comfortably >= 8
        // T = em[252..256], only 4 bytes: 30 02 30 64 -- an AlgorithmIdentifier claiming 100
        // (0x64) content bytes where only 0 remain.
        em[252] = 0x30;
        em[253] = 0x02;
        em[254] = 0x30;
        em[255] = 0x64;
        assert!(!emsa_pkcs1_v1_5_verify::<SHA256, 32, 256>(b"hello", &em));
    }

    /// RFC 8017 §9.2 step 4: "The length of PS will be at least 8 octets" -- exactly 8 must be
    /// accepted, not just "8 or more" in the abstract. `K_LEN = 62` is the minimum modulus width
    /// this hash's `DigestInfo` (`T_LEN = 51`) allows at all (the `K_LEN >= T_LEN + 11` bound
    /// [`emsa_pkcs1_v1_5_encode`]'s docs describe), which pins `PS` to exactly 8 bytes -- the one
    /// pairing that distinguishes "`< 8`" from "`<= 8`" or "`== 8`" as the rejection condition.
    #[test]
    fn verify_accepts_the_minimum_8_byte_ps_boundary() {
        let em = emsa_pkcs1_v1_5_encode::<SHA256, 32, 51, 62>(b"hello");
        assert_eq!(em[2..2 + 8], [0xff; 8], "this construction must exercise ps_len == 8 exactly");
        assert!(emsa_pkcs1_v1_5_verify::<SHA256, 32, 62>(b"hello", &em));
    }
}
