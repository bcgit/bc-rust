//! BLAKE2b-512 and BLAKE2s-256 (RFC 7693, "The BLAKE2 Cryptographic Hash and Message
//! Authentication Code (MAC)"), unkeyed and in BLAKE2's built-in keyed mode.
//!
//! | Type                | RFC 7693 parameters           | Use                                  |
//! |---------------------|-------------------------------|--------------------------------------|
//! | [`BLAKE2b_512`]     | BLAKE2b, nn = 64, kk = 0      | [`Hash`]                             |
//! | [`BLAKE2s_256`]     | BLAKE2s, nn = 32, kk = 0      | [`Hash`]                             |
//! | [`BLAKE2b_512_MACKey`] | BLAKE2b, nn = 64, kk = 1..=64 | MAC key; worker [`BLAKE2b_512_MAC`] |
//! | [`BLAKE2s_256_MACKey`] | BLAKE2s, nn = 32, kk = 1..=32 | MAC key; worker [`BLAKE2s_256_MAC`] |
//!
//! Other digest lengths, salt and personalisation, and the tree / parallel / XOF variants are not
//! implemented.
//!
//! # Usage Examples
//! ```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_blake2::{BLAKE2b_512, BLAKE2s_256};
//!
//! // RFC 7693 Appendix A and B.
//! assert_eq!(BLAKE2b_512::new().hash(b"abc")[..4], [0xBA, 0x80, 0xA5, 0x3F]);
//!
//! let mut blake2s = BLAKE2s_256::new();
//! blake2s.do_update(b"a");
//! blake2s.do_update(b"bc");
//! assert_eq!(blake2s.do_final()[..4], [0x50, 0x8C, 0x5E, 0x8C]);
//! ```
//!
//! A MAC is reached through its key object, built from [`KeyMaterial`] tagged
//! [`KeyType::MACKey`]:
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::FromAnyKeyMaterial;
//! use bouncycastle_core::symmetric_key::{MacGenerationKey, MacVerificationKey};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_blake2::BLAKE2s_256_MACKey;
//!
//! let material = KeyMaterial256::from_bytes_as_type(&[0x0Bu8; 32], KeyType::MACKey).unwrap();
//! let key = BLAKE2s_256_MACKey::from_key_material(&material).unwrap();
//!
//! let tag: Vec<u8> = key.mac(b"message");
//! assert!(key.verify(b"message", &tag));
//!
//! let mut mac = key.create_verifier();
//! mac.do_update(b"mess");
//! mac.do_update(b"age");
//! assert!(mac.do_verify_final(&tag));
//! ```
//!
//! # Memory Usage
//!
//! No heap memory is used by the algorithm itself. Sizes from `core::mem::size_of` on x86_64:
//!
//! | Object                                                  | Size (bytes) |
//! |---------------------------------------------------------|--------------|
//! | [`BLAKE2b_512`], [`BLAKE2b_512_MAC`], [`BLAKE2b_512_MACKey`] | 224     |
//! | [`BLAKE2s_256`], [`BLAKE2s_256_MAC`], [`BLAKE2s_256_MACKey`] | 112     |
//! | BLAKE2b-512 suspended state (hash and MAC)              | 212          |
//! | BLAKE2s-256 suspended state (hash and MAC)              | 108          |
//!
//! The compression function also uses 256 bytes (BLAKE2b) or 128 bytes (BLAKE2s) of stack.
//!
//! # 🚨 Security Considerations 🚨
//!
//! * BLAKE2b-512 offers 256 bits and BLAKE2s-256 128 bits of collision resistance (RFC 7693 s. 4).
//! * Use the MAC keys for keyed hashing: BLAKE2 "has a built-in keying mechanism" (RFC 7693 s. 1)
//!   and its final-block flag (s. 3.2) rules out length extension. A MAC key should be uniformly
//!   random.
//! * A truncated output is the full digest cut short, not BLAKE2 with a smaller `nn`, which is a
//!   different function. MAC tags are not truncated below [`MIN_MAC_OUTPUT_LEN`] bytes.
//! * Verify tags with `verify` / [`MAC::do_verify_final`], which compare in constant time.
//! * BLAKE2 is byte-oriented: [`Hash::do_final_partial_bits`] refuses 1 to 7 partial bits.
//! * State and buffered input, including the key block, are zeroized on drop; the compression
//!   function's stack locals are not. There are no data-dependent branches or table lookups.
//! * A suspended MAC state holds no key bytes, but once input has been absorbed it can finish the
//!   MAC of any extension of that input without the key. Protect it like the key.
//!
//! # Suspending and resuming execution
//!
//! The hash types impl [`Suspendable`], and the MAC workers impl [`SuspendableKeyed`], which takes
//! the key object again to resume:
//!
//! ```rust
//! use bouncycastle_blake2::BLAKE2b_512;
//! use bouncycastle_core::traits::{Hash, Suspendable};
//!
//! let mut blake2b = BLAKE2b_512::new();
//! blake2b.do_update(b"The quick brown fox");
//! let serialized_state = blake2b.suspend();
//!
//! // ... later, possibly on another host.
//! let mut resumed = BLAKE2b_512::from_suspended(serialized_state).unwrap();
//! resumed.do_update(b" jumps over the lazy dog");
//! let h: Vec<u8> = resumed.do_final();
//! ```

// todo #![no_std]
//      waiting for the no_std refactor that removes the `-> Vec<u8>` from core::traits::Hash

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod blake2b;
mod blake2s;

pub use self::blake2b::{
    BLAKE2b_512, BLAKE2b_512_MAC, BLAKE2b_512_MACKey, SUSPENDED_BLAKE2B_512_MAC_STATE_LEN,
    SUSPENDED_BLAKE2B_512_STATE_LEN,
};
pub use self::blake2s::{
    BLAKE2s_256, BLAKE2s_256_MAC, BLAKE2s_256_MACKey, SUSPENDED_BLAKE2S_256_MAC_STATE_LEN,
    SUSPENDED_BLAKE2S_256_STATE_LEN,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
#[allow(unused_imports)]
use bouncycastle_core::traits::{Hash, MAC, Suspendable, SuspendableKeyed};

/// Algorithm name string for BLAKE2b-512, as used by the factories and CLI.
pub const BLAKE2B_512_NAME: &str = "BLAKE2b-512";
/// Algorithm name string for BLAKE2s-256, as used by the factories and CLI.
pub const BLAKE2S_256_NAME: &str = "BLAKE2s-256";
/// Algorithm name string for keyed BLAKE2b-512, as used by the factories and CLI.
pub const BLAKE2B_512_MAC_NAME: &str = "BLAKE2b-512-MAC";
/// Algorithm name string for keyed BLAKE2s-256, as used by the factories and CLI.
pub const BLAKE2S_256_MAC_NAME: &str = "BLAKE2s-256-MAC";

/// Smallest output buffer the MAC workers will truncate a tag into: 4 bytes.
///
/// RFC 7693 sets no floor; this follows HMAC's `MIN_FIPS_DIGEST_LEN` (32 bits).
pub const MIN_MAC_OUTPUT_LEN: usize = 4;

/// RFC 7693 s. 4: id-blake2b512 has "Collision Security 2**256".
impl Algorithm for BLAKE2b_512 {
    const ALG_NAME: &'static str = BLAKE2B_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// RFC 7693 s. 4: id-blake2s256 has "Collision Security 2**128".
impl Algorithm for BLAKE2s_256 {
    const ALG_NAME: &'static str = BLAKE2S_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// Keyed BLAKE2b-512: the same strength as the hash.
impl Algorithm for BLAKE2b_512_MAC {
    const ALG_NAME: &'static str = BLAKE2B_512_MAC_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// Keyed BLAKE2s-256: the same strength as the hash.
impl Algorithm for BLAKE2s_256_MAC {
    const ALG_NAME: &'static str = BLAKE2S_256_MAC_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// RFC 7693 s. 2.1: nn = 64 output bytes, bb = 128 block bytes.
impl HashAlgParams for BLAKE2b_512 {
    const OUTPUT_LEN: usize = 64;
    const BLOCK_LEN: usize = 128;
}

/// RFC 7693 s. 2.1: nn = 32 output bytes, bb = 64 block bytes.
impl HashAlgParams for BLAKE2s_256 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
}

/// RFC 7693 s. 4: id-blake2b512 OBJECT IDENTIFIER ::= { blake2b 16 }, under
/// hashAlgs = 1.3.6.1.4.1.1722.12.2 and blake2b = { hashAlgs 1 }.
impl AlgorithmOID for BLAKE2b_512 {
    const OID: &'static [u32] = &[1, 3, 6, 1, 4, 1, 1722, 12, 2, 1, 16];
    const OID_DER: &'static [u8] =
        &[0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x8D, 0x3A, 0x0C, 0x02, 0x01, 0x10];
}

/// RFC 7693 s. 4: id-blake2s256 OBJECT IDENTIFIER ::= { blake2s 8 }, under
/// hashAlgs = 1.3.6.1.4.1.1722.12.2 and blake2s = { hashAlgs 2 }.
impl AlgorithmOID for BLAKE2s_256 {
    const OID: &'static [u32] = &[1, 3, 6, 1, 4, 1, 1722, 12, 2, 2, 8];
    const OID_DER: &'static [u8] =
        &[0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x8D, 0x3A, 0x0C, 0x02, 0x02, 0x08];
}

/// RFC 7693 s. 4: "The same OID can be used for both keyed and unkeyed hashing since in the latter
/// case the key simply has zero length." So keyed BLAKE2b-512 shares id-blake2b512.
impl AlgorithmOID for BLAKE2b_512_MAC {
    const OID: &'static [u32] = BLAKE2b_512::OID;
    const OID_DER: &'static [u8] = BLAKE2b_512::OID_DER;
}

/// RFC 7693 s. 4, as for [`BLAKE2b_512_MAC`]: keyed BLAKE2s-256 shares id-blake2s256.
impl AlgorithmOID for BLAKE2s_256_MAC {
    const OID: &'static [u32] = BLAKE2s_256::OID;
    const OID_DER: &'static [u8] = BLAKE2s_256::OID_DER;
}
