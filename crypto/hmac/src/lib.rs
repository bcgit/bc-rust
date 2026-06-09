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
//! HMAC objects can be constructed with any underlying hash function that implements [Hash].
//! Type aliases are provided for the common HMAC-HASH algorithms.
//!
//! The following object instantiations are equivalent:
//!
//! ```
//! use bouncycastle_hmac::HMAC_SHA256;
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//! let hmac = HMAC_SHA256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
//! ```
//! and
//! ```
//! use bouncycastle_hmac::HMAC;
//! use bouncycastle_sha2::SHA256;
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//! let hmac = HMAC::<SHA256>::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
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
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
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
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_hmac::HMAC_SHA256;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
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
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//! let data: &[u8] = b"Hello, world!";
//!
//! // .verify() returns a bool: true if the MAC is valid, false otherwise.
//! if bouncycastle_hmac::HMAC_SHA256::new(&key).unwrap()
//!                 .verify(data,
//!                         b"\xa2\xd1\x2e\xcf\xfc\x41\xba\xf1\x23\xd6\x3e\x44\xfc\x27\x88\x90\x47\xcd\x08\xe7\x05\xd7\x0f\xa3\xb8\xaa\x8a\x5c\x18\x7c\x6c\xa9"
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
//! # Request for feedback on fallability of this API
//! We have made an effort to reduce the number of fallibly APIs in the [MAC] trait; in particular
//! the APIs for the update and most of the finalize phases are infallible -- they just work.
//! However, we were not able to design it to completely avoid runtime error conditions, such as
//! providing [MAC::do_final_out] with a buffer that is too small to hold what NIST considered the smallest
//! valid MAC value for the given underlying hash function.
//!
//! Also, the key strength and type checking in the initialization phase means that both [MAC::new] and
//! [MAC::new_allow_weak_key] have several runtime error conditions that they check for.
//!
//! All of this leads to application code that requires a lot more .unwrap(), .expect(), or match than we would
//! really like.
//!
//! We would love feedback on an alternate design for this API than carries less runtime error
//! conditions, without sacrificing the key strength checking that the metadata in the [KeyMaterialTrait] object allows.

#![forbid(unsafe_code)]
#![allow(incomplete_features)] // because at time of writing, generic_const_exprs is not a stable feature
#![feature(generic_const_exprs)]

use bouncycastle_core::errors::{KeyMaterialError, MACError};
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, Hash, MAC, SecurityStrength};
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use bouncycastle_utils::ct;

/*** String constants ***/
pub const HMAC_SHA224_NAME: &str = "HMAC-SHA224";
pub const HMAC_SHA256_NAME: &str = "HMAC-SHA256";
pub const HMAC_SHA384_NAME: &str = "HMAC-SHA384";
pub const HMAC_SHA512_NAME: &str = "HMAC-SHA512";
pub const HMAC_SHA3_224_NAME: &str = "HMAC-SHA3-224";
pub const HMAC_SHA3_256_NAME: &str = "HMAC-SHA3-256";
pub const HMAC_SHA3_384_NAME: &str = "HMAC-SHA3-384";
pub const HMAC_SHA3_512_NAME: &str = "HMAC-SHA3-512";

/*** Type aliases ***/
#[allow(non_camel_case_types)]
pub type HMAC_SHA224 = HMAC<SHA224>;
impl Algorithm for HMAC_SHA224 {
    const ALG_NAME: &'static str = HMAC_SHA224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA256 = HMAC<SHA256>;
impl Algorithm for HMAC_SHA256 {
    const ALG_NAME: &'static str = HMAC_SHA256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA384 = HMAC<SHA384>;
impl Algorithm for HMAC_SHA384 {
    const ALG_NAME: &'static str = HMAC_SHA384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA512 = HMAC<SHA512>;
impl Algorithm for HMAC_SHA512 {
    const ALG_NAME: &'static str = HMAC_SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_224 = HMAC<SHA3_224>;
impl Algorithm for HMAC_SHA3_224 {
    const ALG_NAME: &'static str = HMAC_SHA3_224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_256 = HMAC<SHA3_256>;
impl Algorithm for HMAC_SHA3_256 {
    const ALG_NAME: &'static str = HMAC_SHA3_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_384 = HMAC<SHA3_384>;
impl Algorithm for HMAC_SHA3_384 {
    const ALG_NAME: &'static str = HMAC_SHA3_384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_512 = HMAC<SHA3_512>;
impl Algorithm for HMAC_SHA3_512 {
    const ALG_NAME: &'static str = HMAC_SHA3_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

// TODO: is there a rustacious way to extract this from HASH?
const LARGEST_HASHER_OUTPUT_LEN: usize = 64;

// HMAC implements RFC 2104.
#[derive(Clone)]
pub struct HMAC<HASH: Hash + Default> {
    hasher: HASH,
    key: [u8; LARGEST_HASHER_OUTPUT_LEN],
    key_len: usize, // Doing it this way to avoid needing a vec, so that this can be made no_std friendly.
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

impl<HASH: Hash + Default> HMAC<HASH> {
    fn pad_key_into_hasher(&mut self, padding: u8) {
        // TODO: it would be nice to be able to statically extract the length of HASH and not need a Vec or over-sized array here.
        // TODO: make this no_std-friendly
        let mut padded = vec![0u8; self.hasher.block_bitlen() / 8];

        // Per RFC 2104 Section 2, if the application key exceeds the block
        // length of the underlying hashes algorithm, we apply a hash invocation
        // over the key first.
        // if self.key_len > self.hasher.block_bitlen() / 8 {
        //     HASH::default().hash_out(&self.key[..self.key_len], &mut padded[..self.hasher.output_len()])?;
        // } else {
        // TODO: does this need a guard for a key_len longer than the block length?
        padded[..self.key_len].copy_from_slice(&self.key[..self.key_len]);
        // }

        // XXX: easier way to xor over Vec?
        for entry in &mut padded {
            *entry ^= padding;
        }

        // Per RFC 2104 Section 2, write the padded key into the stream prior
        // to any other data.
        self.hasher.do_update(&padded)
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

        if key.key_len() > self.hasher.block_bitlen() / 8 {
            // then we have to pre-hash it -- use a new instance of the hasher rather than the internal one
            HASH::default().hash_out(key.ref_to_bytes(), &mut self.key[..self.hasher.output_len()]);
            self.key_len = self.hasher.output_len();
        } else {
            self.key[..key.key_len()].copy_from_slice(key.ref_to_bytes());
            self.key_len = key.key_len();
        }

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
        self.hasher.do_final_out(&mut ihash);

        // ohash
        self.hasher = HASH::default();
        self.pad_key_into_hasher(OPAD_BYTE);
        self.hasher.do_update(&ihash);
        Ok(self.hasher.do_final_out(out))
    }
}

// TODO: potential feature: add an interface that pre-computes the intermediate values (K XOR ipad) and (K XOR opad)
// TODO for a given key as described in RFC2104 section 4.
// TODO: This is essentially a "batch mode" where you want to perform many MACs or Verifications with the same key
// TODO: against different data.

impl<HASH: Hash + Default> MAC for HMAC<HASH> {
    fn new(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        let mut hmac =
            Self { hasher: HASH::default(), key: [0u8; LARGEST_HASHER_OUTPUT_LEN], key_len: 0 };
        hmac.init(key, false)?;
        Ok(hmac)
    }

    fn new_allow_weak_key(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        let mut hmac =
            Self { hasher: HASH::default(), key: [0u8; LARGEST_HASHER_OUTPUT_LEN], key_len: 0 };
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
