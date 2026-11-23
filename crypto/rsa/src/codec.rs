//! Big-endian byte-string <-> little-endian limb-array conversion: RFC 8017 §4's OS2IP/I2OSP,
//! specialized to this crate's fixed-width keys (every modulus size this crate offers is a whole
//! number of 64-bit limbs, so the byte length is always exactly `8 * L`) rather than OS2IP's
//! arbitrary-length octet string. `BYTES = 8 * L` is a separate const parameter rather than a
//! computed one for the same reason [`bouncycastle_ec::montgomery`]'s `L2 = 2 * L` is: stable
//! Rust cannot express one const generic as a function of another.
//!
//! Fixed arrays throughout, not slices with a runtime length check: every caller in this crate
//! knows `BYTES` at compile time (it is the modulus's own byte length), so there is nothing to
//! validate at a boundary here -- both directions are infallible.

/// OS2IP (RFC 8017 §4.2): a big-endian byte string into little-endian limbs.
pub fn limbs_from_be_bytes<const L: usize, const BYTES: usize>(bytes: &[u8; BYTES]) -> [u64; L] {
    debug_assert_eq!(BYTES, 8 * L, "limbs_from_be_bytes needs BYTES == 8 * L");
    let mut limbs = [0u64; L];
    for i in 0..L {
        let start = BYTES - (i + 1) * 8;
        limbs[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().expect("8-byte slice"));
    }
    limbs
}

/// I2OSP (RFC 8017 §4.1): little-endian limbs into a big-endian byte string. I2OSP's "integer too
/// large" error cannot occur here: an `[u64; L]` is always `< 256^BYTES`.
pub fn be_bytes_from_limbs<const L: usize, const BYTES: usize>(limbs: &[u64; L]) -> [u8; BYTES] {
    debug_assert_eq!(BYTES, 8 * L, "be_bytes_from_limbs needs BYTES == 8 * L");
    let mut bytes = [0u8; BYTES];
    for i in 0..L {
        let start = BYTES - (i + 1) * 8;
        bytes[start..start + 8].copy_from_slice(&limbs[i].to_be_bytes());
    }
    bytes
}
