//! Minimal DER encode/decode for `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 3279
//! §2.2.3), as an alternative to this crate's native raw `r || s` signature encoding (see e.g.
//! [`crate::ecdsa_p256::SIG_LEN`]'s docs on why raw was chosen as the default). This handles
//! exactly two ASN.1 types -- `INTEGER` (universal tag `0x02`) and constructed `SEQUENCE`
//! (universal tag `0x30`) -- which is all `Ecdsa-Sig-Value` ever needs, so there is no general
//! ASN.1/BER/DER crate here, just this.
//!
//! Every rule enforced below is from ITU-T Rec. X.690 (02/2021), "ASN.1 encoding rules:
//! Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished
//! Encoding Rules (DER)":
//!
//! - **Length octets** (§8.1.3): short form (a single octet, bit 8 clear, encoding 0-127 directly)
//!   or long form (an initial octet with bit 8 set and bits 7-1 giving the count of subsequent
//!   octets, which then big-endian-encode the length). [`max_len`]'s bound (66-byte `r`/`s`, the
//!   widest this crate supports, for P-521) never needs more than one subsequent length octet, so
//!   [`parse_length`]/[`write_length`] don't implement the general long form, only that one case.
//! - **DER's length restriction** (§10.1): "the minimum number of octets" -- so a long-form length
//!   encoding a value `< 128` (which should have used the short form) is rejected, and the
//!   indefinite form (§8.1.3.6, a single `0x80` octet) is not a definite length at all and is
//!   rejected outright.
//! - **INTEGER content** (§8.3.2/§8.3.3): a two's-complement binary number, minimally encoded --
//!   §8.3.2 forbids a leading octet (plus bit 8 of the next) that is "all ones" or "all zero",
//!   since either means a redundant leading byte. `r` and `s` are always non-negative (RFC 3279's
//!   `Ecdsa-Sig-Value` uses `INTEGER` for values that are never negative in practice), so
//!   [`parse_integer`] rejects the "all ones" (negative) case unconditionally rather than checking
//!   it for redundancy, and rejects a redundant leading `0x00` per §8.3.2's "all zero" case.
//!
//! [`decode`] additionally checks that parsing the `SEQUENCE`'s two `INTEGER`s consumes it exactly
//! (no gap, no overlap) and that the `SEQUENCE`'s own declared length accounts for every byte
//! passed in (no trailing garbage after it) -- both are ordinary structural well-formedness checks
//! for a length-prefixed format, not DER-specific, but easy to get wrong, so they're covered by
//! this module's own tests (`der_tests.rs`) as well as this crate's wycheproof suites, several of
//! which include DER-encoding-error test vectors.

/// Upper bound on the DER encoding of a `SEQUENCE { r, s }` where `r` and `s` are each `n` bytes
/// wide (the curve's scalar width): each `INTEGER`'s content is at most `n + 1` bytes (the `+1` for
/// a sign-avoiding `0x00` pad, per this module's docs), so each `INTEGER` TLV is at most `n + 3`
/// bytes (tag + one length octet -- `n + 1 <= 67` for every curve this crate supports, always
/// under the 128 that would force a long-form length), the `SEQUENCE`'s content is at most
/// `2*(n + 3)`, and its own header is 2 bytes (short-form length) unless that content is `>= 128`,
/// in which case it needs 3 (long-form, one subsequent length octet -- true for P-521's `n = 66`,
/// where content is `138`).
pub const fn max_len(n: usize) -> usize {
    let content_len = 2 * (n + 3);
    let header_len = if content_len < 0x80 { 2 } else { 3 };
    header_len + content_len
}

/// Writes `content_len`'s DER length octets (short or one-octet long form; see the module docs) to
/// `out[pos..]`, returning the number of octets written.
fn write_length(content_len: usize, out: &mut [u8], pos: usize) -> usize {
    if content_len < 0x80 {
        out[pos] = content_len as u8;
        1
    } else {
        out[pos] = 0x81;
        out[pos + 1] = content_len as u8;
        2
    }
}

/// The DER content-octet length of `v`'s `INTEGER` encoding: `v` with its redundant leading zero
/// bytes stripped, plus one more if the remaining leading byte's high bit is set (to keep the
/// two's-complement value non-negative).
fn integer_content_len(v: &[u8]) -> usize {
    let mut i = 0;
    while i < v.len() - 1 && v[i] == 0 {
        i += 1;
    }
    (v.len() - i) + if v[i] & 0x80 != 0 { 1 } else { 0 }
}

/// Writes `v`'s DER `INTEGER` TLV to `out[pos..]`, returning the number of octets written.
fn write_integer(v: &[u8], out: &mut [u8], pos: usize) -> usize {
    let mut i = 0;
    while i < v.len() - 1 && v[i] == 0 {
        i += 1;
    }
    let needs_pad = v[i] & 0x80 != 0;
    let content_len = (v.len() - i) + if needs_pad { 1 } else { 0 };

    out[pos] = 0x02;
    let mut p = pos + 1 + write_length(content_len, out, pos + 1);
    if needs_pad {
        out[p] = 0;
        p += 1;
    }
    out[p..p + (v.len() - i)].copy_from_slice(&v[i..]);
    p + (v.len() - i)
}

/// Encodes `r`/`s` (equal-length big-endian magnitudes) as a DER `SEQUENCE { r INTEGER, s INTEGER
/// }` into `out`, returning the number of bytes written. `out` must be at least
/// `max_len(r.len())` bytes and `r.len() == s.len()`; every call site in this crate sizes its own
/// buffer via [`max_len`] and passes equal-width `r`/`s` (both encode the same curve's scalars), so
/// this is an internal-crate contract, not a public API needing its own error path.
pub fn encode(r: &[u8], s: &[u8], out: &mut [u8]) -> usize {
    debug_assert_eq!(r.len(), s.len(), "r and s must be the same width");
    let content_len = 2 + integer_content_len(r) + 2 + integer_content_len(s);
    out[0] = 0x30;
    let mut pos = 1 + write_length(content_len, out, 1);
    pos = write_integer(r, out, pos);
    write_integer(s, out, pos)
}

/// Parses DER length octets at `bytes[pos..]` (short form, or the one-octet long form -- see the
/// module docs), returning `(length, octets_consumed)`, or `None` for the indefinite form, an
/// unsupported longer long-form, or a non-minimal long-form encoding (DER forbids both).
fn parse_length(bytes: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *bytes.get(pos)?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x81 {
        let len = *bytes.get(pos + 1)? as usize;
        if len < 0x80 {
            return None; // non-minimal: this length should have used the short form
        }
        Some((len, 2))
    } else {
        None // indefinite (0x80) or a length-of-length this crate never needs (>= 0x82)
    }
}

/// Parses a DER `INTEGER` TLV at `bytes[pos..]`, writing its big-endian magnitude right-aligned
/// (zero-padded on the left) into `out`, and returns the number of bytes consumed -- or `None` if
/// malformed, negative, non-canonically padded (§8.3.2), or too wide for `out`.
fn parse_integer(bytes: &[u8], pos: usize, out: &mut [u8]) -> Option<usize> {
    if *bytes.get(pos)? != 0x02 {
        return None;
    }
    let (content_len, len_octets) = parse_length(bytes, pos + 1)?;
    let content_start = pos + 1 + len_octets;
    let content = bytes.get(content_start..content_start + content_len)?;

    let (first, rest) = content.split_first()?; // §8.3.1: content is never empty
    if first & 0x80 != 0 {
        return None; // negative: r, s are never negative (see the module docs)
    }
    if *first == 0 && rest.first().is_some_and(|b| b & 0x80 == 0) {
        return None; // §8.3.2: redundant leading zero byte
    }
    // A leading 0x00 here (content.len() > 1, since a lone 0x00 is the encoding of zero) is only
    // ever the sign-avoidance pad byte just validated above, not part of the magnitude, so it must
    // not count against out's width. (The `content.len() > 1` guard is mutation-equivalent for
    // this function's actual output: dropping it would make `magnitude` an empty slice for the
    // `content == [0x00]` case, but `out` is already zero-filled below, so the written result is
    // the same all-zero encoding of `0` either way.)
    let magnitude = if *first == 0 && content.len() > 1 { rest } else { content };
    if magnitude.len() > out.len() {
        return None; // magnitude too wide for this curve's scalar width
    }

    out.fill(0);
    let split = out.len() - magnitude.len();
    out[split..].copy_from_slice(magnitude);
    Some(1 + len_octets + content_len)
}

/// Decodes a DER `SEQUENCE { r, s }`, writing `r`/`s` right-aligned (zero-padded) into `r_out`/
/// `s_out` (which must be the same length: the curve's scalar width), or `None` if malformed, if
/// either integer doesn't fit, or if `bytes` has trailing data beyond the `SEQUENCE` -- see the
/// module docs for exactly which checks this performs and why.
pub fn decode(bytes: &[u8], r_out: &mut [u8], s_out: &mut [u8]) -> Option<()> {
    if r_out.len() != s_out.len() {
        return None;
    }
    if *bytes.first()? != 0x30 {
        return None;
    }
    let (seq_content_len, len_octets) = parse_length(bytes, 1)?;
    let content_start = 1 + len_octets;
    if content_start.checked_add(seq_content_len)? != bytes.len() {
        return None; // trailing bytes after the SEQUENCE, or a declared length past the end
    }

    let r_len = parse_integer(bytes, content_start, r_out)?;
    let s_len = parse_integer(bytes, content_start + r_len, s_out)?;
    if r_len + s_len != seq_content_len {
        return None; // the two INTEGERs must exactly fill the declared SEQUENCE content
    }
    Some(())
}
