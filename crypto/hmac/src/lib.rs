//! This crate contains an implementation of the Hash-Based Message Authentication Code (HMAC)
//! as specified in RFC2104, taking into account NIST Implementation Guidance in FIPS 140-2 IG A.8
//! and NIST SP 800-107-r1.
//!
//! # Usage
//!
//! The HMAC object (and the [MAC] trait in general) is designed in three phases:
//!
//! * The initialization phase where you specify the underlying hash function and the key material.
//! * The update phase where you feed in the content being MAC'd, either in one-shot or in chunks.
//! * The finalization phase where you either obtain the MAC value or verify an existing MAC value.
//!
//! The initialization phase is primarily performed via the [MAC::new] function which performs
//! checks on the provided key to ensure that it is of the correct type [KeyType::MACKey] and tagged
//! at the correct security level for the chosen hash function. In cases where you need to use HMAC
//! with an intentially week key (such as an all-zero salt), the alternative constructor
//! [MAC::new_allow_weak_key] can be used.
//!
//! The update phase supports streaming of the content via the repeated calls to the [MAC::do_update] function.
//! One-shot APIs are provided that combine the update and finalization phases into a single function call.
//!
//!
//! # Examples
//!
//! Instantation of an HMAC object is straightforward:
//!
//! ```
//! use bouncycastle_hmac::HMAC_SHA256;
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_core::key_material::{KeyMaterial256};
//!
//! let key: KeyMaterial256 = HMAC_SHA256::keygen().expect("Will only fail if the system RNG can't start up.");
//!
//! let hmac = HMAC_SHA256::new(&key).expect(
//!         "Should succeed because key is long enough and tagged KeyType::MACKey");
//! ```
//!
//! Alternatively, if you have key material from somewhere else, you can create the key manually, like so:
//! ```
//! use bouncycastle_hmac::HMAC_SHA256;
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//! let hmac = HMAC_SHA256::new(&key).expect(
//!         "Should succeed because key is long enough and tagged KeyType::MACKey");
//! ```
//!
//! ## Computing a MAC
//! MAC functionality is accessed via the [MAC] trait.
//!
//! The simplest usage is via the one-shot functions.
//! ```
//! use bouncycastle_hmac::HMAC_SHA256;
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//!
//! let key: KeyMaterial256 = HMAC_SHA256::keygen().expect("Will only fail if the system RNG can't start up.");
//!
//! let data: &[u8] = b"Hello, world!";
//! let hmac = HMAC_SHA256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
//! let output: Vec<u8> = hmac.mac(data);
//! ```
//!
//! More advanced usage will require creating an HMAC object to hold state between successive calls,
//! for example if input is received in chunks and not all available at the same time:
//!
//! ```
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_hmac::HMAC_SHA256;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//!
//! let key: KeyMaterial256 = HMAC_SHA256::keygen().expect("Will only fail if the system RNG can't start up.");
//!
//! let mut hmac = HMAC_SHA256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
//! hmac.do_update(b"Hello,");
//! hmac.do_update(b" world!");
//! let output: Vec<u8> = hmac.do_final();
//! ```
//!
//! ## Verifying a MAC
//! MAC functionality is accessed via the [MAC] trait which provides functions for MAC verification.
//! The built-in verification functions use constant-time comparisons and so are *strongly recommended*
//! rather than re-computing the MAC value and comparing it yourself.
//!
//! The simplest usage is via the one-shot functions.
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::MAC;
//!
//! // For this example to work, we are hard-coding both the key and the MAC value that it generates
//! // for this data.
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! // .verify() returns a bool: true if the MAC is valid, false otherwise.
//! if bouncycastle_hmac::HMAC_SHA256::new(&key).unwrap()
//!                 .verify(data,
//!                         b"\xa2\xd1\x2e\xcf\xfc\x41\xba\xf1\x23\xd6\x3e\x44\xfc\x27\x88\x90
//!                            \x47\xcd\x08\xe7\x05\xd7\x0f\xa3\xb8\xaa\x8a\x5c\x18\x7c\x6c\xa9"
//!                         )
//! {
//!     println!("MAC is valid!");
//! } else {
//!     println!("MAC is invalid!");
//! }
//! ```
//!
//! Similarly, a streaming version is available, which is identical to the streaming interface for
//! computing a mac value, but calls [MAC::do_verify_final] instead of [MAC::do_final].
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_hmac::HMAC_SHA256;
//!
//! // For this example to work, we are hard-coding both the key and the MAC value that it generates
//! // for this data.
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//! let mut hmac = HMAC_SHA256::new(&key).unwrap();
//! hmac.do_update(b"Hello,");
//! hmac.do_update(b" world!");
//! if hmac.do_verify_final(b"\xa2\xd1\x2e\xcf\xfc\x41\xba\xf1\x23\xd6\x3e\x44\xfc\x27\x88\x90\x47\xcd\x08\xe7\x05\xd7\x0f\xa3\xb8\xaa\x8a\x5c\x18\x7c\x6c\xa9"
//!                     )
//! {
//!     println!("MAC is valid!");
//! } else {
//!     println!("MAC is invalid!");
//! }
//! ```
//!
//! # Suspending and resuming execution
//!
//! When MAC'ing a large message, it can be advantageous to be able to suspend the operation
//! to a cache and resume it later; for example if waiting for the message to stream over a slow network
//! connection. For this reason, all HMAC algorithms impl [SuspendableKeyed].
//!
//! Note that since HMAC is a keyed
//! algorithm and we do not want to serialize the private key into the state, the trait structure forces you to
//! re-provide the same key when you resume the operation. Securely storing this key in the interim
//! is the responsibility of the caller. Note also that if you resume the HMAC with the wrong key,
//! `from_serialized_state` has no way to detect this, so the end result will be a broken MAC value
//! computed with different keys in the inner and outer pad. So make sure you resume with the same key!
//!
//!```rust
//! use bouncycastle_hmac::HMAC_SHA256;
//! use bouncycastle_core::key_material::KeyMaterial256;
//! use bouncycastle_core::traits::{MAC, SuspendableKeyed};
//! use bouncycastle_core::key_material::KeyType;
//!
//! let msg_part1 = b"The quick brown fox";
//! let msg_part2 = b" jumped over the lazy dog";
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//! let mut hmac = HMAC_SHA256::new(&key).unwrap();
//! hmac.do_update(msg_part1);
//!
//! // suspend the in-progress mac (the key is NOT included in the serialized state)
//! let serialized_state = hmac.suspend();
//!
//! // ...
//! // do other things in the meantime
//! // ...
//!
//! // ... later, possibly on another host: resume from the serialized state by re-supplying
//! // the same salt (make sure you store it securely!).
//! let mut hmac_resumed = HMAC_SHA256::from_suspended(serialized_state, &key).unwrap();
//! hmac_resumed.do_update(msg_part2);
//! let h: Vec<u8> = hmac_resumed.do_final();
//! ```

#![forbid(unsafe_code)]
#![allow(incomplete_features)] // because at time of writing, generic_const_exprs is not a stable feature
#![feature(generic_const_exprs)]

use bouncycastle_core::errors::{KeyMaterialError, MACError, RNGError, SuspendableError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    Algorithm, Hash, MAC, RNG, Secret, SecurityStrength, Suspendable, SuspendableKeyed,
};
use bouncycastle_rng::{HashDRBG_SHA256, HashDRBG_SHA512};
use bouncycastle_sha2::{
    SHA224, SHA256, SHA384, SHA512, SUSPENDED_SHA256_STATE_LEN, SUSPENDED_SHA512_STATE_LEN,
};
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SUSPENDED_SHA3_STATE_LEN};
use bouncycastle_utils::ct;
use core::fmt::{Debug, Display, Formatter};

/*** String constants ***/
///
pub const HMAC_SHA224_NAME: &str = "HMAC-SHA224";
///
pub const HMAC_SHA256_NAME: &str = "HMAC-SHA256";
///
pub const HMAC_SHA384_NAME: &str = "HMAC-SHA384";
///
pub const HMAC_SHA512_NAME: &str = "HMAC-SHA512";
///
pub const HMAC_SHA3_224_NAME: &str = "HMAC-SHA3-224";
///
pub const HMAC_SHA3_256_NAME: &str = "HMAC-SHA3-256";
///
pub const HMAC_SHA3_384_NAME: &str = "HMAC-SHA3-384";
///
pub const HMAC_SHA3_512_NAME: &str = "HMAC-SHA3-512";

/*** Type aliases ***/
#[allow(non_camel_case_types)]
pub type HMAC_SHA224 = HMAC<SHA224, 64>;
impl Algorithm for HMAC_SHA224 {
    const ALG_NAME: &'static str = HMAC_SHA224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA256 = HMAC<SHA256, 64>;
impl Algorithm for HMAC_SHA256 {
    const ALG_NAME: &'static str = HMAC_SHA256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA384 = HMAC<SHA384, 128>;
impl Algorithm for HMAC_SHA384 {
    const ALG_NAME: &'static str = HMAC_SHA384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA512 = HMAC<SHA512, 128>;
impl Algorithm for HMAC_SHA512 {
    const ALG_NAME: &'static str = HMAC_SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_224 = HMAC<SHA3_224, 144>;
impl Algorithm for HMAC_SHA3_224 {
    const ALG_NAME: &'static str = HMAC_SHA3_224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_256 = HMAC<SHA3_256, 136>;
impl Algorithm for HMAC_SHA3_256 {
    const ALG_NAME: &'static str = HMAC_SHA3_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_384 = HMAC<SHA3_384, 104>;
impl Algorithm for HMAC_SHA3_384 {
    const ALG_NAME: &'static str = HMAC_SHA3_384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_512 = HMAC<SHA3_512, 72>;
impl Algorithm for HMAC_SHA3_512 {
    const ALG_NAME: &'static str = HMAC_SHA3_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

// The internal key buffer must be able to hold a key up to the *block length* of the underlying hash:
// per RFC 2104, a key no longer than the block is used verbatim (only longer keys are pre-hashed down
// to the output length). So the buffer size is a const parameter of the struct, set per hash to its
// block length by the type aliases below. Block lengths (bytes): SHA-224/256 = 64, SHA-384/512 = 128,
// SHA3-224 = 144, SHA3-256 = 136, SHA3-384 = 104, SHA3-512 = 72.
//
// The default is used only when `HMAC<HASH>` is written without an explicit buffer size; it is the
// largest block length across all supported hashes, so it is always large enough.
const LARGEST_HASHER_BLOCK_LEN: usize = 144;

// HMAC implements RFC 2104.
#[derive(Clone)]
pub struct HMAC<HASH: Hash + Default, const KEY_BUF_LEN: usize = LARGEST_HASHER_BLOCK_LEN> {
    hasher: HASH,
    // todo: once rust stable merges generic_const_exprs, we can remove this hack and delete the KEY_BUF_LEN param.
    // key: [u8; HASH::OUTPUT_LEN];
    key: [u8; KEY_BUF_LEN],
    key_len: usize, // Doing it this way to avoid needing a vec, so that this can be made no_std friendly.
}

// Because the HMAC struct contains a copy of the long-term key
impl<HASH: Hash + Default, const KEY_BUF_LEN: usize> Secret for HMAC<HASH, KEY_BUF_LEN> {}

impl<HASH: Hash + Default, const KEY_BUF_LEN: usize> Drop for HMAC<HASH, KEY_BUF_LEN> {
    fn drop(&mut self) {
        self.key.fill(0);
        self.key_len = 0;
    }
}

impl<HASH: Hash + Default, const KEY_BUF_LEN: usize> Debug for HMAC<HASH, KEY_BUF_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HMAC-{} instance", HASH::ALG_NAME,)
    }
}

impl<HASH: Hash + Default, const KEY_BUF_LEN: usize> Display for HMAC<HASH, KEY_BUF_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HMAC-{} instance", HASH::ALG_NAME,)
    }
}

// See definitions in RFC 2104 Section 2.
const IPAD_BYTE: u8 = 0x36;
const OPAD_BYTE: u8 = 0x5C;

// Per FIPS 140-2 IG A.8 Use of a truncated HMAC (matching NIST SP 800-107-r1
// Section 5.3.3. Truncation of HMAC), says that the minimum truncation of a
// HMAC for tagging should be 32 bits; this exceeds the lower bound set by
// IETF RFC 2104 Section 5 Truncated output, which sets the lower bound to be
// half of the hash's length and no fewer than 80 bits.
//
// However, as we feel there should be a minimum limit (and have an author
// work around this via explicit truncation manually afterwards), but not
// be too strict about it,
pub const MIN_FIPS_DIGEST_LEN: usize = 4; // 32 / 8;

impl<HASH: Hash + Default, const KEY_BUF_LEN: usize> HMAC<HASH, KEY_BUF_LEN> {
    fn pad_key_into_hasher(&mut self, padding: u8) {
        // TODO: it would be nice to be able to statically extract the length of HASH and not need a Vec or over-sized array here.
        // TODO: make this no_std-friendly
        let mut padded = vec![0u8; self.hasher.block_bitlen() / 8];

        padded[..self.key_len].copy_from_slice(&self.key[..self.key_len]);

        // XXX: easier way to xor over Vec?
        for entry in &mut padded {
            *entry ^= padding;
        }

        // Per RFC 2104 Section 2, write the padded key into the stream prior
        // to any other data.
        self.hasher.do_update(&padded)
    }

    /// Per RFC 2104 Section 2, if the application key exceeds the block
    /// length of the underlying hashes algorithm, we apply a hash invocation
    /// over the key first.
    /// This does NOT absorb the key into the hasher; that is done separately via [HMAC::pad_key_into_hasher].
    fn load_key_material(&mut self, key_bytes: &[u8]) {
        if key_bytes.len() > self.hasher.block_bitlen() / 8 {
            // then we have to pre-hash it -- use a new instance of the hasher rather than the internal one
            HASH::default().hash_out(key_bytes, &mut self.key[..self.hasher.output_len()]);
            self.key_len = self.hasher.output_len();
        } else {
            self.key[..key_bytes.len()].copy_from_slice(key_bytes);
            self.key_len = key_bytes.len();
        }

        // Just as a sanity-check.
        assert!(
            self.key_len <= KEY_BUF_LEN,
            "Fatal error: Key length exceeds HMAC internal buffer length"
        );
    }

    /// Private init so that users are forced to go through one of the public new methods and thus we
    /// don't need to track state errors.
    fn init(&mut self, key: &impl KeyMaterialTrait, allow_weak_keys: bool) -> Result<(), MACError> {
        // check that the key is of type KeyMaterial::MACKey
        // Make an exception for all-zero keys, which is allowed (which can be zero-length or non-zero-length,
        // because it's just a nuisance to force users to set KeyType::MACKey for an all-zero key.
        if !(key.key_type() == KeyType::Zeroized || key.key_type() == KeyType::MACKey) {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "Key type must be a MAC key.",
            )));
        }

        // import the key material as bytes.
        // Per RFC 2104 Section 2, if the application key exceeds the block
        // length of the underlying hashes algorithm, we apply a hash invocation
        // over the key first.

        self.load_key_material(key.ref_to_bytes());

        self.pad_key_into_hasher(IPAD_BYTE);

        // check that the key had enough security level
        if !allow_weak_keys && key.security_strength() < HASH::default().max_security_strength() {
            Err(KeyMaterialError::SecurityStrength(
                "HMAC::init(): provided key has a lower security strength than the instantiated HMAC",
            ))?
        } else {
            Ok(())
        }
    }

    /// the out buffer can be oversized, but not less than the MIN_FIPS_DIGEST_LENGTH
    /// Returns the number of bytes written.
    fn do_final_internal_out(mut self, out: &mut [u8]) -> Result<usize, MACError> {
        if out.len() < MIN_FIPS_DIGEST_LEN {
            return Err(MACError::InvalidLength(
                "HMAC truncation too short for FIPS 140-2 guidelines",
            ));
        }

        out.fill(0);

        // Per RFC 2104 Section 2, save our inner digest to calculate our
        // outer digest. Note that we can't (necessarily) reuse out as a
        // scratch pad here: if we're truncating the output but not
        // truncating the underlying hashes, we'd lose bytes and compute an
        // invalid outer hashes.
        // TODO: rework this to be no_std friendly (ie no vec!)
        let mut ihash = vec![0u8; self.hasher.output_len()];
        // `HMAC` implements `Drop` (required by `Secret`), so we cannot move `self.hasher` out
        // directly. Swap in a fresh default and consume the taken-out hasher instead.
        core::mem::take(&mut self.hasher).do_final_out(&mut ihash);

        // ohash
        self.hasher = HASH::default();
        self.pad_key_into_hasher(OPAD_BYTE);
        self.hasher.do_update(&ihash);
        Ok(core::mem::take(&mut self.hasher).do_final_out(out))
    }
}

// TODO: potential feature: add an interface that pre-computes the intermediate values (K XOR ipad) and (K XOR opad)
// TODO for a given key as described in RFC2104 section 4.
// TODO: This is essentially a "batch mode" where you want to perform many MACs or Verifications with the same key
// TODO: against different data.

impl<HASH: Hash + Default, const KEY_BUF_LEN: usize> MAC for HMAC<HASH, KEY_BUF_LEN> {
    fn new(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        let mut hmac = Self { hasher: HASH::default(), key: [0u8; KEY_BUF_LEN], key_len: 0 };
        hmac.init(key, false)?;
        Ok(hmac)
    }

    fn new_allow_weak_key(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        let mut hmac = Self { hasher: HASH::default(), key: [0u8; KEY_BUF_LEN], key_len: 0 };
        hmac.init(key, true)?;
        Ok(hmac)
    }

    fn output_len(&self) -> usize {
        self.hasher.output_len()
    }

    fn mac(self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0_u8; self.hasher.output_len()];
        let bytes_written = self.mac_out(data, &mut out).expect("HMAC::mac(): should not have failed because we gave it a sufficiently large output buffer to meet FIPS rules.");
        out[..bytes_written].to_vec()
    }

    fn mac_out(mut self, data: &[u8], mut out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);

        self.do_update(data);
        self.do_final_out(&mut out)
    }

    fn verify(mut self, data: &[u8], mac: &[u8]) -> bool {
        self.do_update(data);
        self.do_verify_final(mac)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.hasher.do_update(data)
    }

    fn do_final(self) -> Vec<u8> {
        let mut out = vec![0_u8; self.hasher.output_len()];
        self.do_final_internal_out(&mut out).expect("HMAC::do_final(): should not have failed because we gave it a sufficiently large output buffer to meet FIPS rules.");
        out
    }

    fn do_final_out(self, mut out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);

        self.do_final_internal_out(&mut out)
    }

    fn do_verify_final(self, mac: &[u8]) -> bool {
        let mut out = vec![0_u8; HASH::default().output_len()];
        let output_len = self.do_final_internal_out(&mut out).expect("HMAC::do_final(): should not have failed because we gave it a sufficiently large output buffer to meet FIPS rules.");
        if mac.len() != output_len {
            return false;
        }
        ct::ct_eq_bytes(mac, &out[..output_len])
    }

    fn max_security_strength(&self) -> SecurityStrength {
        HASH::default().max_security_strength()
    }
}

/* SerializedState */

/*** Serialized-state length constants ***/
/// Length in bytes of the serialized state of [HMAC_SHA224].
pub const SUSPENDED_HMAC_SHA224_STATE_LEN: usize = SUSPENDED_SHA256_STATE_LEN;
/// Length in bytes of the serialized state of [HMAC_SHA256].
pub const SUSPENDED_HMAC_SHA256_STATE_LEN: usize = SUSPENDED_SHA256_STATE_LEN;
/// Length in bytes of the serialized state of [HMAC_SHA384].
pub const SUSPENDED_HMAC_SHA384_STATE_LEN: usize = SUSPENDED_SHA512_STATE_LEN;
/// Length in bytes of the serialized state of [HMAC_SHA512].
pub const SUSPENDED_HMAC_SHA512_STATE_LEN: usize = SUSPENDED_SHA512_STATE_LEN;
/// Length in bytes of the serialized state of [HMAC_SHA3_224].
pub const SUSPENDED_HMAC_SHA3_224_STATE_LEN: usize = SUSPENDED_SHA3_STATE_LEN;
/// Length in bytes of the serialized state of [HMAC_SHA3_256].
pub const SUSPENDED_HMAC_SHA3_256_STATE_LEN: usize = SUSPENDED_SHA3_STATE_LEN;
/// Length in bytes of the serialized state of [HMAC_SHA3_384].
pub const SUSPENDED_HMAC_SHA3_384_STATE_LEN: usize = SUSPENDED_SHA3_STATE_LEN;
/// Length in bytes of the serialized state of [HMAC_SHA3_512].
pub const SUSPENDED_HMAC_SHA3_512_STATE_LEN: usize = SUSPENDED_SHA3_STATE_LEN;

/// HMAC is a keyed algorithm, so it implements [SuspendableKeyed] (rather than
/// [Suspendable]) for suspending and resuming in-progress operations.
/// The key is deliberately NOT written into the serialized
/// bytes and must be re-supplied at deserialization.
///
/// The serialized state is exactly the inner hasher's state (which has already absorbed `K ⊕ ipad`
/// and any message chunks provided so far) — so this is a straight passthrough to the underlying hash's
/// [Suspendable] impl. The re-supplied key is needed to reconstruct the material for the outer
/// (`K ⊕ opad`) step at finalization.
///
/// There is no way to detect a mismatched key on
/// resume: the caller MUST supply the same key the HMAC was created with, otherwise the resumed
/// operation will silently produce an incorrect MAC.
impl<
    const HASH_STATE_LEN: usize,
    const KEY_BUF_LEN: usize,
    HASH: Hash + Default + Suspendable<HASH_STATE_LEN>,
> SuspendableKeyed<HASH_STATE_LEN> for HMAC<HASH, KEY_BUF_LEN>
{
    // HMAC accepts any key material, so the key type is the trait object `dyn KeyMaterialTrait`
    // rather than a single concrete key type. The key is only used (by reference) to reload the key
    // bytes at from_serialized_state, so dynamic dispatch here is negligible.
    type Key = dyn KeyMaterialTrait;

    fn suspend(mut self) -> [u8; HASH_STATE_LEN] {
        // The key is intentionally excluded; the resumable state is just the inner hasher, which
        // already carries the library version header from the hash's own SerializableState impl.
        // `HMAC` implements `Drop` (required by `Secret`), so move the hasher out via `mem::take`
        // rather than a direct partial move.
        core::mem::take(&mut self.hasher).suspend()
    }

    fn from_suspended(
        state: [u8; HASH_STATE_LEN],
        key: &Self::Key,
    ) -> Result<Self, SuspendableError> {
        // Rebuild the inner hasher (version-compatibility is validated by the hash's impl).
        let hasher = HASH::from_suspended(state)?;

        // Re-load the key material exactly as `new()` did (pre-hashing an over-length key), but do
        // NOT re-absorb `K ⊕ ipad` — the deserialized hasher already contains it. The key is only
        // needed for the outer `K ⊕ opad` step at finalization.
        let mut hmac = HMAC { hasher, key: [0u8; KEY_BUF_LEN], key_len: 0 };
        hmac.load_key_material(key.ref_to_bytes());

        Ok(hmac)
    }
}

/* KeyGen functions */
// These need to be separate intrinsic impl's because there isn't a way to statically-type the
// KeyMaterial<N> based on the HASH type.
// Using a macro to cut down on code duplication.
// todo: once rust supports const generics, we can remove the need for this macro and impl this directly
//      on HMAC as `-> KeyMetarial<H::OUTPUT_LEN>`
macro_rules! impl_hmac_keygen {
    ($hash:ty, $block_len:literal, $n:literal, $drbg:ty) => {
        impl HMAC<$hash, $block_len> {
            pub fn keygen() -> Result<KeyMaterial<$n>, RNGError> {
                let mut key = KeyMaterial::<$n>::new();
                let mut os_rng = <$drbg>::new_from_os();
                os_rng.fill_keymaterial_out(&mut key)?;
                key.set_key_type(KeyType::MACKey)?;
                Ok(key)
            }
        }
    };
}

impl_hmac_keygen!(SHA224, 64, 28, HashDRBG_SHA256);
impl_hmac_keygen!(SHA256, 64, 32, HashDRBG_SHA256);
impl_hmac_keygen!(SHA384, 128, 48, HashDRBG_SHA512);
impl_hmac_keygen!(SHA512, 128, 64, HashDRBG_SHA512);
impl_hmac_keygen!(SHA3_224, 144, 28, HashDRBG_SHA256);
impl_hmac_keygen!(SHA3_256, 136, 32, HashDRBG_SHA256);
impl_hmac_keygen!(SHA3_384, 104, 48, HashDRBG_SHA512);
impl_hmac_keygen!(SHA3_512, 72, 64, HashDRBG_SHA512);
