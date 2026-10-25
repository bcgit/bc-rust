//! Implements the BLAKE3 cryptographic hash function -- the `hash`, `keyed_hash` and `derive_key`
//! modes, with extendable output -- as per the BLAKE3 specification (J. O'Connor, J.-P. Aumasson,
//! S. Neves, Z. Wilcox-O'Hearn, "BLAKE3: one function, fast everywhere", version 20211102173700).
//!
//! * [`BLAKE3`]: the `hash` mode ([`BLAKE3::new`]) and the `derive_key` mode
//!   ([`BLAKE3::new_derive_key`]), as a [`Hash`] and a [`XOF`].
//! * [`BLAKE3KeyedHashKey`]: the `keyed_hash` key, which hands out [`BLAKE3KeyedHash`] workers, a
//!   [`MAC`] with extended keyed output via [`BLAKE3KeyedHash::into_squeezer`].
//!
//! # Usage Examples
//! ```
//! use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
//! use bouncycastle_blake3::BLAKE3;
//!
//! // One-shot: the official test vector for the empty input begins af1349b9.
//! assert_eq!(BLAKE3::new().hash(b"")[..4], [0xaf, 0x13, 0x49, 0xb9]);
//!
//! // Streaming, then reading any amount of output; the first 32 bytes are the hash.
//! let mut blake3 = BLAKE3::new();
//! blake3.do_update(b"ab");
//! blake3.do_update(b"c");
//! let mut squeezer = blake3.into_squeezer();
//! let long = [squeezer.do_output(40), squeezer.do_output(60)].concat();
//! assert_eq!(long, BLAKE3::new().xof(b"abc", 100));
//! assert_eq!(long[..32], BLAKE3::new().hash(b"abc"));
//!
//! // derive_key: a hardcoded context string, then the key material as input.
//! const CONTEXT: &[u8] = b"example.com 2019-12-25 16:18:03 session tokens v1";
//! let derived: Vec<u8> = BLAKE3::new_derive_key(CONTEXT).xof(&[0x0bu8; 32], 64);
//! ```
//!
//! The `keyed_hash` mode takes a 32-byte key tagged [`KeyType::MACKey`]:
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{
//!     FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey,
//! };
//! use bouncycastle_core::traits::{MAC, XOFSqueezer};
//! use bouncycastle_blake3::BLAKE3KeyedHashKey;
//!
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42u8; 32], KeyType::MACKey).unwrap();
//! let key = BLAKE3KeyedHashKey::from_key_material(&material).unwrap();
//!
//! let tag: Vec<u8> = key.mac(b"message");
//! assert!(key.verify(b"message", &tag)); // constant-time comparison
//!
//! // Streaming, then extended keyed output: its first 32 bytes are the tag.
//! let mut mac = key.create_generator();
//! mac.do_update(b"mess");
//! mac.do_update(b"age");
//! assert_eq!(mac.into_squeezer().do_output(64)[..32], tag);
//! ```
//!
//! # Memory Usage
//!
//! No heap memory is used except by the `Vec`-returning convenience methods.
//!
//! | Object                                    | Size (bytes) |
//! |-------------------------------------------|--------------|
//! | [`BLAKE3`]                                | 1880         |
//! | [`BLAKE3KeyedHashKey`]                    | 32           |
//! | [`BLAKE3KeyedHash`]                       | 1880         |
//! | [`BLAKE3Squeezer`]                        | 192          |
//! | [`BLAKE3KeyedSqueezer`]                   | 192          |
//! | [`SUSPENDED_BLAKE3_STATE_LEN`]            | 1874         |
//! | [`SUSPENDED_BLAKE3_KEYED_HASH_STATE_LEN`] | 1838         |
//! | [`SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN`]   | 180          |
//!
//! 1728 bytes of a hasher are the chaining-value stack, sized for the full 2^64-byte input range
//! (spec s. 5.4).
//!
//! # 🚨 Security Considerations 🚨
//!
//! * BLAKE3 targets 128-bit security for all its goals (s. 4.1), so every type here reports
//!   [`SecurityStrength::_128bit`]; the 256-bit key and longer outputs do not raise it.
//! * Shorter outputs are prefixes of longer ones (s. 2.6): the output length is not bound into the
//!   result.
//! * `keyed_hash` is a MAC and PRF by design (s. 6.1); its key must be 32 uniformly random bytes.
//!   The [`MAC`] trait will not truncate a tag below [`MIN_MAC_OUTPUT_LEN`] bytes;
//!   [`BLAKE3KeyedHash::into_squeezer`] has no floor.
//! * The `derive_key` context string must be hardcoded, globally unique and application-specific,
//!   never variable data (s. 6.2); see [`BLAKE3::new_derive_key`].
//! * BLAKE3 is byte-oriented: a partial final byte is refused.
//! * State and buffers are zeroized on drop; there are no data-dependent branches or table
//!   lookups.
//! * Suspended states are sensitive: a `derive_key` state holds up to 64 bytes of key material
//!   verbatim, and a `keyed_hash` state can finish some messages without the key (see
//!   [`BLAKE3KeyedHash`]'s [`SuspendableKeyed`] impl). Protect either like the key.
//!
//! # Suspending and resuming execution
//!
//! [`BLAKE3`] and [`BLAKE3Squeezer`] implement [`Suspendable`]; [`BLAKE3KeyedHash`] implements
//! [`SuspendableKeyed`], which never writes the key into the state and takes the key object on
//! resume. [`BLAKE3KeyedSqueezer`] cannot be suspended, because its state can contain the key
//! words.
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
//! use bouncycastle_core::traits::{Hash, MAC, Suspendable, SuspendableKeyed};
//! use bouncycastle_blake3::{BLAKE3, BLAKE3KeyedHash, BLAKE3KeyedHashKey};
//!
//! let mut blake3 = BLAKE3::new();
//! blake3.do_update(b"part one, ");
//! let mut resumed = BLAKE3::from_suspended(blake3.suspend()).unwrap();
//! resumed.do_update(b"part two");
//! assert_eq!(resumed.do_final(), BLAKE3::new().hash(b"part one, part two"));
//!
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42u8; 32], KeyType::MACKey).unwrap();
//! let key = BLAKE3KeyedHashKey::from_key_material(&material).unwrap();
//! let mut mac = key.create_generator();
//! mac.do_update(b"part one, ");
//! let mut resumed = BLAKE3KeyedHash::from_suspended(mac.suspend(), &key).unwrap();
//! resumed.do_update(b"part two");
//! assert_eq!(resumed.do_final(), key.mac(b"part one, part two"));
//! ```

// todo #![no_std]
//      waiting for the no_std refactor that removes the `-> Vec<u8>` from core::traits::Hash

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod blake3;
mod compress;

pub use self::blake3::{
    BLAKE3, BLAKE3KeyedHash, BLAKE3KeyedHashKey, BLAKE3KeyedSqueezer, BLAKE3Squeezer,
    MIN_MAC_OUTPUT_LEN, SUSPENDED_BLAKE3_KEYED_HASH_STATE_LEN, SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN,
    SUSPENDED_BLAKE3_STATE_LEN,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashAlgParams};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyType;
#[allow(unused_imports)]
use bouncycastle_core::traits::{Hash, MAC, Suspendable, SuspendableKeyed, XOF};

/// Algorithm name string for BLAKE3 (`hash` and `derive_key` modes), as used by the factories and
/// CLI.
pub const BLAKE3_NAME: &str = "BLAKE3";

/// Algorithm name string for BLAKE3 in `keyed_hash` mode, as used by the factories and CLI.
pub const BLAKE3_KEYED_HASH_NAME: &str = "BLAKE3-KeyedHash";

/// BLAKE3 spec s. 4.1: "BLAKE3 targets 128-bit security for all of its security goals."
impl Algorithm for BLAKE3 {
    const ALG_NAME: &'static str = BLAKE3_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// BLAKE3 spec s. 4.1: "BLAKE3 targets 128-bit security for all of its security goals." The
/// 256-bit key is "an extra defense layer", not a higher target.
impl Algorithm for BLAKE3KeyedHash {
    const ALG_NAME: &'static str = BLAKE3_KEYED_HASH_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// BLAKE3 spec s. 2.1: the default output is 32 bytes ("The chaining value of the root node,
/// encoded as 32 bytes ... is the default-length BLAKE3 hash"); s. 2.2: 64-byte message blocks.
/// BLAKE3 has no assigned OID.
impl HashAlgParams for BLAKE3 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
}
