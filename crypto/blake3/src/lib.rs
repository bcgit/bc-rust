//! Implements the BLAKE3 cryptographic hash function -- the `hash`, `keyed_hash` and `derive_key`
//! modes, with extendable output -- as per the BLAKE3 specification (J. O'Connor, J.-P. Aumasson,
//! S. Neves, Z. Wilcox-O'Hearn, "BLAKE3: one function, fast everywhere", version 20211102173700).
//!
//! * [`BLAKE3`]: the `hash` mode, as a [`Hash`] and a [`XOF`].
//! * [`BLAKE3DeriveKey`]: the `derive_key` mode, as a [`Hash`] and a [`XOF`].
//! * [`BLAKE3KeyedHashKey`]: the `keyed_hash` key, which hands out [`BLAKE3KeyedHash`] workers, a
//!   MAC with extended keyed output via [`BLAKE3KeyedHash::into_squeezer`].
//!
//! # Usage Examples
//! ```
//! use bouncycastle_core::traits::{Hash, HashOneShot, XOF, XOFSqueezer};
//! use bouncycastle_blake3::{BLAKE3, BLAKE3DeriveKey};
//!
//! // One-shot: the official test vector for the empty input begins af1349b9.
//! assert_eq!(BLAKE3::hash(b"")[..4], [0xaf, 0x13, 0x49, 0xb9]);
//!
//! // Streaming, then reading any amount of output; the first 32 bytes are the hash.
//! let mut blake3 = BLAKE3::new();
//! blake3.do_update(b"ab");
//! blake3.do_update(b"c");
//! let mut squeezer = blake3.into_squeezer();
//! let long = [squeezer.do_output(40), squeezer.do_output(60)].concat();
//! assert_eq!(long, BLAKE3::new().xof(b"abc", 100));
//! assert_eq!(long[..32], BLAKE3::hash(b"abc"));
//!
//! // derive_key: a hardcoded context string, then the key material as input.
//! const CONTEXT: &[u8] = b"example.com 2019-12-25 16:18:03 session tokens v1";
//! let derived: Vec<u8> = BLAKE3DeriveKey::new(CONTEXT).xof(&[0x0bu8; 32], 64);
//! ```
//!
//! The `keyed_hash` mode takes a 32-byte key tagged [`KeyType::MACKey`]:
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{
//!     FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey,
//! };
//! use bouncycastle_core::traits::{MACGenerator, XOFSqueezer};
//! use bouncycastle_blake3::BLAKE3KeyedHashKey;
//!
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42u8; 32], KeyType::MACKey).unwrap();
//! let key = BLAKE3KeyedHashKey::from_key_material(&material).unwrap();
//!
//! let tag: [u8; 32] = key.mac(b"message");
//! assert!(key.verify(b"message", &tag).is_ok()); // constant-time comparison
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
//! | [`BLAKE3`], [`BLAKE3DeriveKey`]           | 1880         |
//! | [`BLAKE3KeyedHashKey`]                    | 32           |
//! | [`BLAKE3KeyedHash`]                       | 1856         |
//! | [`BLAKE3Squeezer`]                        | 192          |
//! | [`BLAKE3KeyedSqueezer`], [`BLAKE3DeriveKeySqueezer`] | 192 |
//! | [`SUSPENDED_BLAKE3_STATE_LEN`]            | 1874         |
//! | [`SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN`]   | 116          |
//!
//! 1728 bytes of a hasher are the chaining-value stack, sized for the full 2^64-byte input range
//! (spec s. 5.4).
//!
//! Peak stack per call, measured by painting the stack below a non-inlined call into the operation
//! (the object and the output buffer included, the 4 KiB input static; release build with thin
//! LTO, x86_64, rustc 1.97.0-nightly):
//!
//! | Operation                                              | Stack   |
//! |--------------------------------------------------------|---------|
//! | [`BLAKE3`] hash, one-shot or streaming                 | 6864 B  |
//! | [`BLAKE3`] XOF, 512 bytes of output                    | 5552 B  |
//! | [`BLAKE3`] `suspend`, `from_suspended`, finish         | 11696 B |
//! | [`BLAKE3Squeezer`] `suspend`, `from_suspended`, output | 5648 B  |
//! | [`BLAKE3KeyedHashKey`] from key material               | 104 B   |
//! | [`BLAKE3KeyedHashKey`] `mac_out`                       | 5080 B  |
//! | [`BLAKE3KeyedHash`] `into_squeezer`, 512 bytes         | 5576 B  |
//! | [`BLAKE3DeriveKey`] `new`, `hash_out`                  | 10592 B |
//!
//! # 🚨 Security Considerations 🚨
//!
//! * Every type here reports [`SecurityStrength::_128bit`] (see the [`Algorithm`] impls); the
//!   256-bit key and longer outputs do not raise it.
//! * Shorter outputs are prefixes of longer ones (s. 2.6): the output length is not bound into the
//!   result.
//! * `keyed_hash` is a MAC and PRF by design (s. 6.1); its key must be 32 uniformly random bytes.
//!   [`BLAKE3KeyedHash::into_squeezer`] has no output-length floor.
//! * The `derive_key` context string must be hardcoded, globally unique and application-specific,
//!   never variable data (s. 6.2); see [`BLAKE3DeriveKey`].
//! * BLAKE3 is byte-oriented: a partial final byte is refused.
//! * State and buffers are zeroized on drop; there are no data-dependent branches or table
//!   lookups.
//! * The `keyed_hash` and `derive_key` workers are not suspendable: their states hold key
//!   material.
//!
//! # Suspending and resuming execution
//!
//! [`BLAKE3`] and [`BLAKE3Squeezer`] implement [`Suspendable`]. [`BLAKE3KeyedHash`],
//! [`BLAKE3KeyedSqueezer`], [`BLAKE3DeriveKey`] and [`BLAKE3DeriveKeySqueezer`] cannot be
//! suspended, because their states contain key material; a message in progress is paused by
//! holding the worker.
//! ```
//! use bouncycastle_core::traits::{Hash, HashOneShot, Suspendable};
//! use bouncycastle_blake3::BLAKE3;
//!
//! let mut blake3 = BLAKE3::new();
//! blake3.do_update(b"part one, ");
//! let mut resumed = BLAKE3::from_suspended(blake3.suspend()).unwrap();
//! resumed.do_update(b"part two");
//! assert_eq!(resumed.do_final(), BLAKE3::hash(b"part one, part two"));
//! ```

// todo #![no_std]
//      waiting for the no_std refactor that removes the `-> Vec<u8>` from core::traits::Hash

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod blake3;
mod compress;

pub use self::blake3::{
    BLAKE3, BLAKE3DeriveKey, BLAKE3DeriveKeySqueezer, BLAKE3KeyedHash, BLAKE3KeyedHashKey,
    BLAKE3KeyedSqueezer, BLAKE3Squeezer, SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN,
    SUSPENDED_BLAKE3_STATE_LEN,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashAlgParams};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyType;
#[allow(unused_imports)]
use bouncycastle_core::traits::{Hash, MACGenerator, Suspendable, XOF};

/// Algorithm name string for BLAKE3 (`hash` mode), as used by the factories and CLI.
pub const BLAKE3_NAME: &str = "BLAKE3";

/// Algorithm name string for BLAKE3 in `derive_key` mode.
pub const BLAKE3_DERIVE_KEY_NAME: &str = "BLAKE3-DeriveKey";

/// Algorithm name string for BLAKE3 in `keyed_hash` mode, as used by the factories and CLI.
pub const BLAKE3_KEYED_HASH_NAME: &str = "BLAKE3-KeyedHash";

/// BLAKE3 spec s. 4.1: "BLAKE3 targets 128-bit security for all of its security goals."
impl Algorithm for BLAKE3 {
    const ALG_NAME: &'static str = BLAKE3_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// As for [`BLAKE3`]: the 256-bit key is "an extra defense layer" (s. 4.1), not a higher target.
impl<Dir> Algorithm for BLAKE3KeyedHash<'_, Dir> {
    const ALG_NAME: &'static str = BLAKE3_KEYED_HASH_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// As for [`BLAKE3`].
impl Algorithm for BLAKE3DeriveKey {
    const ALG_NAME: &'static str = BLAKE3_DERIVE_KEY_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// BLAKE3 spec s. 2.1: the default output is 32 bytes ("The chaining value of the root node,
/// encoded as 32 bytes ... is the default-length BLAKE3 hash"); s. 2.2: 64-byte message blocks.
/// BLAKE3 has no assigned OID.
impl HashAlgParams for BLAKE3 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
}
