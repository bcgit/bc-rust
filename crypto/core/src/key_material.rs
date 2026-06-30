//! A helper class used across the bc-rust library to hold bytes-like key material.
//! The main purpose is to hold metadata about the contained key material such as the key type and
//! entropy content to prevent accidental misuse security bugs, such as deriving cryptographic keys
//! from uninitialized data.
//! The core idea of this wrapper is to keep track of the usage of the key material, including
//! the amount of entropy that it is presumed to contain in order to prevent users from accidentally
//! using it inappropriately in a way that could lead to security weaknesses.
//!
//! Various operations within the bc-rs library will consume or produce KeyMaterial objects with
//! specific key types. In normal use of the bc-rs APIs, users should never have to manually convert
//! the type of a KeyMaterial object because the various function calls will set the key type appropriately.
//!
//! Some typical workflows would be:
//!
//! * Hash functions take in \[u8\] byte data and return a KeyMaterial of type RawUnknownEntropy.
//! * Password-based key derivation functions act on KeyMaterial of any type, and in the case of RawFullEntropy, RawLowEntropy, or RawUnknownEntropy, will preserve the entropy rating.
//! * Keyed KDFs that are given a key of RawFullEntropy or KeyedHashKey a KeyMaterial data of type RawLowEntropy or RawUnknownEntropy will promote it into RawFullEntropy.
//! * Symmetric ciphers or asymmetric ciphers such as X25519 or ML-KEM that accept private key seeds will expect KeyMaterial of type AsymmetricPrivateKeySeed.
//!
//! However, there is a [KeyMaterialTrait::set_key_type] for cases where the user has more context knowledge than the library.
//! Some conversions, such as converting a key of type RawLowEntropy into a SymmetricCipherKey, will fail unless
//! run inside of a [do_hazardous_operations] closure, see below.
//!
//! # Security
//!
//! Additional security features:
//!   * Zeroizes on destruction.
//!   * Implementing Display and Debug to print metadata but not key material to prevent accidental logging.
//!
//! # Hazardous Operations
//!
//! This object allows several types of manual-overrides, many of which are considered
//! "hazardous operations" since by definition they are allowing you to bypass checks meant to detect
//! conditions that could lead to security vulnerabilities.
//! Consider, for example, that you are reading a symmetric key from somewhere outside the library,
//! maybe from disk or from another process, but maybe you handed in the wrong variable and instead
//! handed in an uninitialized (all-zero) buffer.
//! Since this is a common bug that has catestrophic security implications, the library will normally
//! check for all-zero KeyMoterial objects and throw an error.
//! But there will be cases in which you really do need to use an all-zero key, so you can create
//! one if you do it in hazardous operations mode.
//!
//! Examples of hazardous conversions that are required to be run inside of a do_hazardous_operations() closure:
//!
//! * Converting a KeyMaterial of type RawLowEntropy or RawUnknownEntropy into RawFullEntropy or any other full-entropy key type.
//! * Converting any algorithm-specific key type into a different algorithm-specific key type, which is considered hazardous since key reuse between different cryptographic algorithms is generally discouraged and can sometimes lead to key leakage.
//!
//! As with all wrappers of this nature, the intent is to protect the user from making silly mistakes, not to prevent expert users from doing what they need to do.
//! It as always possible, for example, to extract the bytes from a KeyMaterial object, manipulate them, and then re-wrap them in a new KeyMaterial object.
//!
//! See [do_hazardous_operations] for documentation and sample code.

use crate::errors::KeyMaterialError;
use crate::traits::{RNG, Secret, SecurityStrength};
use bouncycastle_utils::{ct, min};

use core::cmp::{Ordering, PartialOrd};
use core::fmt;

/// Sometimes you just need a zero-length dummy key.
pub type KeyMaterial0 = KeyMaterial<0>;

pub type KeyMaterial128 = KeyMaterial<16>;
pub type KeyMaterial256 = KeyMaterial<32>;
pub type KeyMaterial512 = KeyMaterial<64>;

/// A helper class used across the bc-rust.test library to hold bytes-like key material.
/// See [KeyMaterial] for for details, such as constructors.
#[allow(private_bounds)]
pub trait KeyMaterialTrait: KeyMaterialInternalTrait {
    /// Loads the provided data into a new KeyMaterial of the specified type.
    /// This is discouraged unless the caller knows the provenance of the data, such as loading it
    /// from a cryptographic private key file.
    ///
    /// This behaves differently on all-zero input key depending on whether it is run within a [do_hazardous_operations] closure:
    /// if not set, then it will succeed, setting the key type to [KeyType::Zeroized] and also return a [KeyMaterialError::ActingOnZeroizedKey]
    /// to indicate that you may want to perform error-handling, which could be manually setting the key type
    /// if you intend to allow zero keys, or do some other error-handling, like figure out why your RNG is broken.
    /// Note that even if a [KeyMaterialError::ActingOnZeroizedKey] is returned, the object is still populated and usable.
    /// For example, you could catch it like this:
    /// ```
    /// use bouncycastle_core::key_material::{KeyMaterial256, KeyType, KeyMaterialTrait, do_hazardous_operations};
    /// use bouncycastle_core::key_material::KeyMaterial;
    /// use bouncycastle_core::errors::KeyMaterialError;
    ///
    /// let key_bytes = [0u8; 16];
    /// let mut key = KeyMaterial256::new();
    /// let res = key.set_bytes_as_type(&key_bytes, KeyType::Unknown);
    /// match res {
    ///   Err(KeyMaterialError::ActingOnZeroizedKey) => {
    ///     // Either figure out why your passed an all-zero key,
    ///     // or set the key type manually, if that's what you intended.
    ///     do_hazardous_operations(&mut key, |key| {
    ///         key.set_key_type(KeyType::Unknown)
    ///     }).unwrap(); // probably you should do something more elegant than .unwrap in your code ;)
    ///   },
    ///   Err(_) => { /* figure out what else went wrong */ },
    ///   Ok(_) => { /* good */ },
    /// }
    /// ```
    /// On the other hand, if run inside a [do_hazardous_operations] closure then it will just do what you asked without complaining.
    ///
    /// Since this zeroizes and resets the key material, this is considered a dangerous conversion.
    ///
    /// Will set the [SecurityStrength] automatically according to the following rules:
    /// * If [KeyType] is [KeyType::Zeroized] or [KeyType::Unknown] then it will be [SecurityStrength::None].
    /// * Otherwise it will set it based on the length of the provided source bytes.
    fn set_bytes_as_type(
        &mut self,
        source: &[u8],
        key_type: KeyType,
    ) -> Result<(), KeyMaterialError>;

    /// Get a reference to the underlying key material bytes.
    ///
    /// By reading the key bytes out of the [KeyMaterialTrait] object, you lose the protections that it offers,
    /// however, this does not require [do_hazardous_operations] in the name of API ergonomics:
    /// setting [do_hazardous_operations] requires a mutable reference and reading the bytes
    /// is not an operation that should require mutability.
    fn ref_to_bytes(&self) -> &[u8];

    /// Get a mutable reference to the underlying key material bytes so that you can read or write
    /// to the underlying bytes without needing to create a temporary buffer, especially useful in
    /// cases where the required size of that buffer may be tricky to figure out at compile-time.
    ///
    /// # 🚨 Hazardous Operation🚨
    /// This function needs to be run within a [do_hazardous_operations] closure.
    ///
    /// When writing directly to the buffer, you are responsible for setting the key_len and key_type afterward.
    fn ref_to_bytes_mut(&mut self) -> Result<&mut [u8], KeyMaterialError>;

    /// The size of the internal buffer; ie the largest key that this instance can hold.
    /// Equivalent to the <KEY_LEN> constant param this object was created with.
    fn capacity(&self) -> usize;

    /// Length of the key material in bytes.
    fn key_len(&self) -> usize;

    /// Sets the internal key length without changing the capacity of the KeyMaterial.
    /// Primarily intended for truncation if you are provided with a key that is larger than you need,
    /// or to extend the length of an undersized KeyMaterial.
    ///
    /// If truncating, it will automatically downgrade the SecurityStrength accordingly.
    ///
    /// # 🚨 Hazardous Operation🚨
    /// Using this function to extend the length of a key is always hazardous and needs to be run
    /// within a [do_hazardous_operations] closure since this can result
    /// in a key containing a large number of zeroes, or containing key material from a previous key
    /// held in the same buffer. When extending the length, you take responsibility for the security
    /// implications.
    ///
    /// Truncation (that is, reducing the length) is always safe and does not require a
    /// [do_hazardous_operations] closure.
    fn set_key_len(&mut self, key_len: usize) -> Result<(), KeyMaterialError>;

    fn key_type(&self) -> KeyType;

    /// Sets (or safely converts) the [KeyType] of this KeyMaterial object.
    /// Does not perform any operations on the actual key material, other than changing the key_type field.
    ///
    /// # 🚨 Hazardous Operation🚨
    /// Inside a [do_hazardous_operations] closure this will set the key to any [KeyType].
    /// Outside such a closure, only "safe" conversions are permitted: a [KeyType::CryptographicRandom]
    /// key may be converted to any type, and any type may be converted to itself (a no-op).
    /// A hazardous conversion attempted outside a [do_hazardous_operations] closure returns
    /// [KeyMaterialError::HazardousOperationNotPermitted], and converting a [KeyType::Zeroized] key
    /// returns [KeyMaterialError::ActingOnZeroizedKey].
    fn set_key_type(&mut self, key_type: KeyType) -> Result<(), KeyMaterialError>;

    /// Security Strength, as used here, aligns with NIST SP 800-90A guidance for random number generation,
    /// specifically section 8.4.
    ///
    /// The idea is to be able to track for cryptographic seeds and bytes-like key objects across the entire library,
    /// the instatiated security level of the RNG that generated it, and whether it was handled by any intermediate
    /// objects, such as Key Derivation Functions, that have a smaller internal security level and therefore result in
    /// downgrading the security level of the key material.
    ///
    /// Note that while security strength is closely related to entropy, it is a property of the algorithms
    /// that touched the key material and not of the key material data itself, and therefore it is
    /// tracked independantly from key length and entropy level / key type.
    fn security_strength(&self) -> SecurityStrength;

    /// Set the [SecurityStrength] of the KeyMaterial.
    ///
    /// # 🚨 Hazardous Operation🚨
    /// This function needs to be run within a [do_hazardous_operations] closure to raise the security
    /// strength, but not to lower it.
    ///
    /// Outside of a [do_hazardous_operations] closure it will throw a
    /// [KeyMaterialError::HazardousOperationNotPermitted] on a request to raise the security level, and
    /// throw a [KeyMaterialError::InvalidLength] on a request to set the security level higher than the current key length. Inside a [do_hazardous_operations] it will do what you asked without complaining.
    fn set_security_strength(&mut self, strength: SecurityStrength)
    -> Result<(), KeyMaterialError>;

    /// Whether or not the KeyMaterial is one of the full entropy key types.
    fn is_full_entropy(&self) -> bool;

    /// Securely resets the contents to all zeroes.
    /// Note that KeyMaterial will automatically zeroize itself when dropped, so it is not necessary
    /// to call this method simply because the object is going out of scope, but it provided
    /// in case you want to zeroize it early, or before re-using the same instance of KeyMaterial to
    /// hold a different key, potentially of a different length.
    fn zeroize(&mut self);

    /// Perform a constant-time comparison between the two key material buffers,
    /// ignoring differences in capacity, [KeyType], [SecurityStrength], etc.
    fn equals(&self, other: &dyn KeyMaterialTrait) -> bool;
}

/// A wrapper for holding bytes-like key material (symmetric keys or seeds) which aims to apply a
/// strict typing system to prevent many kinds of mis-use mistakes.
/// The capacity of the internal buffer can be set at compile-time via the <KEY_LEN> param.
#[derive(Clone)]
pub struct KeyMaterial<const KEY_LEN: usize> {
    buf: [u8; KEY_LEN],
    key_len: usize,
    key_type: KeyType,
    security_strength: SecurityStrength,
    allow_hazardous_operations: bool,
}

impl<const KEY_LEN: usize> Secret for KeyMaterial<KEY_LEN> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyType {
    /// The KeyMaterial is zeroized and MUST NOT be used for any cryptographic operation in this state.
    Zeroized,

    /// The KeyMaterial contains non-zero data of unknown key type.
    /// A KeyMaterial of key type Unknown will always have a [SecurityStrength] of [SecurityStrength::None].
    ///
    /// This is the default KeyType for data loaded via [KeyMaterial::from_bytes].
    /// Promotion from Unknown to any other key type is considered to be a hazardous operation
    /// and must be done within a [do_hazardous_operations] closure.
    /// If you want to import key material directly into a known key type, use [KeyMaterial::from_bytes_as_type],
    /// which does not require a hazardous operations closure.
    Unknown,

    /// The KeyMaterial contains data of full entropy and can be safely converted to any other key type.
    CryptographicRandom,

    /// A seed for asymmetric private keys, RNGs, and other seed-based cryptographic objects.
    Seed,

    /// A MAC key.
    MACKey,

    /// A key for a symmetric block or stream cipher.
    SymmetricCipherKey,
}

impl<const KEY_LEN: usize> Default for KeyMaterial<KEY_LEN> {
    /// Create a new empty (zeroized) instance.
    fn default() -> Self {
        Self::new()
    }
}

impl<const KEY_LEN: usize> KeyMaterial<KEY_LEN> {
    pub fn new() -> Self {
        Self {
            buf: [0u8; KEY_LEN],
            key_len: 0,
            key_type: KeyType::Zeroized,
            security_strength: SecurityStrength::None,
            allow_hazardous_operations: false,
        }
    }

    /// Create a new instance of KeyMaterial containing random bytes from the provided random number generator.
    pub fn from_rng(rng: &mut impl RNG) -> Result<Self, KeyMaterialError> {
        let mut key = Self::new();

        do_hazardous_operations(&mut key, |key| {
            rng.next_bytes_out(&mut key.ref_to_bytes_mut().unwrap())
                .map_err(|_| KeyMaterialError::GenericError("RNG failed."))?;
            Ok(())
        })?;

        key.key_len = KEY_LEN;
        key.key_type = KeyType::CryptographicRandom;
        key.security_strength = rng.security_strength();
        Ok(key)
    }

    /// Constructor.
    /// Loads the provided data into a new KeyMaterial of type [KeyType::Unknown].
    /// It will detect if you give it all-zero source data and set the key type to [KeyType::Zeroized] instead.
    pub fn from_bytes(source: &[u8]) -> Result<Self, KeyMaterialError> {
        Self::from_bytes_as_type(source, KeyType::Unknown)
    }

    /// Constructor.
    /// Loads the provided data into a new KeyMaterial of the specified type.
    /// This is discouraged unless the caller knows the provenance of the data, such as loading it
    /// from a cryptographic private key file.
    /// It will detect if you give it all-zero source data and set the key type to [KeyType::Zeroized] instead.
    ///
    /// Will set the [SecurityStrength] automatically according to the following rules:
    /// * If [KeyType] is [KeyType::Zeroized] or [KeyType::Unknown] then it will be [SecurityStrength::None].
    /// * Otherwise it will set it based on the length of the provided source bytes.
    pub fn from_bytes_as_type(source: &[u8], key_type: KeyType) -> Result<Self, KeyMaterialError> {
        let mut key_material = Self::default();

        // Special case: catch and ignore the courtesy error about zeroized input and simply return a zeroized key.
        match key_material.set_bytes_as_type(source, key_type) {
            Ok(_) => Ok(key_material),
            Err(KeyMaterialError::ActingOnZeroizedKey) => {
                debug_assert_eq!(key_material.key_type(), KeyType::Zeroized);
                Ok(key_material)
            }
            Err(e) => Err(e),
        }
    }

    /// Copy constructor
    pub fn from_key(other: &impl KeyMaterialTrait) -> Result<Self, KeyMaterialError> {
        if other.key_len() > KEY_LEN {
            return Err(KeyMaterialError::InputDataLongerThanKeyCapacity);
        }

        let mut key = Self {
            buf: [0u8; KEY_LEN],
            key_len: other.key_len(),
            key_type: other.key_type(),
            security_strength: SecurityStrength::None,
            allow_hazardous_operations: false,
        };
        key.buf[..other.key_len()].copy_from_slice(other.ref_to_bytes());
        Ok(key)
    }
}

impl<const KEY_LEN: usize> KeyMaterialTrait for KeyMaterial<KEY_LEN> {
    fn set_bytes_as_type(
        &mut self,
        source: &[u8],
        key_type: KeyType,
    ) -> Result<(), KeyMaterialError> {
        let allowed_hazardous_operations = self.allow_hazardous_operations;

        if source.len() > KEY_LEN {
            return Err(KeyMaterialError::InputDataLongerThanKeyCapacity);
        }

        let new_key_type = if !allowed_hazardous_operations && ct::ct_eq_zero_bytes(source) {
            KeyType::Zeroized
        } else {
            key_type
        };

        self.buf[..source.len()].copy_from_slice(source);
        self.key_len = source.len();
        self.key_type = new_key_type;

        do_hazardous_operations(self, |s| {
            if new_key_type <= KeyType::Unknown {
                s.set_security_strength(SecurityStrength::None)?;
            } else {
                s.set_security_strength(SecurityStrength::from_bits(source.len() * 8))?;
            }
            Ok(())
        })?;

        // return
        if new_key_type == KeyType::Zeroized {
            Err(KeyMaterialError::ActingOnZeroizedKey)
        } else {
            Ok(())
        }
    }

    fn ref_to_bytes(&self) -> &[u8] {
        &self.buf[..self.key_len]
    }

    fn ref_to_bytes_mut(&mut self) -> Result<&mut [u8], KeyMaterialError> {
        if !self.allow_hazardous_operations {
            return Err(KeyMaterialError::HazardousOperationNotPermitted);
        }
        Ok(&mut self.buf)
    }

    fn capacity(&self) -> usize {
        KEY_LEN
    }

    fn key_len(&self) -> usize {
        self.key_len
    }

    fn set_key_len(&mut self, key_len: usize) -> Result<(), KeyMaterialError> {
        if key_len > KEY_LEN {
            return Err(KeyMaterialError::InvalidLength);
        }

        // are we extending the key length, or truncating?
        if key_len <= self.key_len {
            // truncation is always allowed (not hazardous)

            self.security_strength =
                min(&self.security_strength, &SecurityStrength::from_bits(key_len * 8)).clone();

            if key_len == 0 {
                self.key_type = KeyType::Zeroized;
            }

            self.key_len = key_len;

            Ok(())
        } else {
            if !self.allow_hazardous_operations {
                return Err(KeyMaterialError::HazardousOperationNotPermitted);
            }
            self.key_len = key_len;
            Ok(())
        }
    }
    fn key_type(&self) -> KeyType {
        self.key_type.clone()
    }
    fn set_key_type(&mut self, key_type: KeyType) -> Result<(), KeyMaterialError> {
        if self.allow_hazardous_operations {
            // just do it
            self.key_type = key_type;
            return Ok(());
        }

        match self.key_type {
            KeyType::Zeroized => {
                return Err(KeyMaterialError::ActingOnZeroizedKey);
            }
            KeyType::CryptographicRandom => {
                // raw full entropy can be safely converted to anything.
                self.key_type = key_type;
            }
            KeyType::Unknown => match key_type {
                KeyType::Unknown => { /* No change */ }
                _ => {
                    return Err(KeyMaterialError::HazardousOperationNotPermitted);
                }
            },
            KeyType::MACKey => match key_type {
                KeyType::MACKey => { /* No change */ }
                // Else: Once a KeyMaterial is typed, it should stay that way.
                _ => {
                    return Err(KeyMaterialError::HazardousOperationNotPermitted);
                }
            },
            KeyType::SymmetricCipherKey => match key_type {
                KeyType::SymmetricCipherKey => { /* No change */ }
                // Else: Once a KeyMaterial is typed, it should stay that way.
                _ => {
                    return Err(KeyMaterialError::HazardousOperationNotPermitted);
                }
            },
            KeyType::Seed => match key_type {
                KeyType::Seed => { /* No change */ }
                // Else: Once a KeyMaterial is typed, it should stay that way.
                _ => {
                    return Err(KeyMaterialError::HazardousOperationNotPermitted);
                }
            },
        }

        Ok(())
    }
    fn security_strength(&self) -> SecurityStrength {
        self.security_strength.clone()
    }

    fn set_security_strength(
        &mut self,
        strength: SecurityStrength,
    ) -> Result<(), KeyMaterialError> {
        if strength > self.security_strength && !self.allow_hazardous_operations {
            return Err(KeyMaterialError::HazardousOperationNotPermitted);
        };

        if self.key_type <= KeyType::Unknown && strength > SecurityStrength::None {
            return Err(KeyMaterialError::SecurityStrength(
                "BytesLowEntropy keys cannot have a security strength other than None.",
            ));
        }

        match strength {
            SecurityStrength::None => { /* fine, you can always downgrade */ }
            SecurityStrength::_112bit => {
                if self.key_len() < 14 {
                    return Err(KeyMaterialError::SecurityStrength(
                        "Security strength cannot be higher than key length.",
                    ));
                }
            }
            SecurityStrength::_128bit => {
                if self.key_len() < 16 {
                    return Err(KeyMaterialError::SecurityStrength(
                        "Security strength cannot be larger than key length.",
                    ));
                }
            }
            SecurityStrength::_192bit => {
                if self.key_len() < 24 {
                    return Err(KeyMaterialError::SecurityStrength(
                        "Security strength cannot be larger than key length.",
                    ));
                }
            }
            SecurityStrength::_256bit => {
                if self.key_len() < 32 {
                    return Err(KeyMaterialError::SecurityStrength(
                        "Security strength cannot be larger than key length.",
                    ));
                }
            }
        }

        self.security_strength = strength;
        Ok(())
    }
    fn is_full_entropy(&self) -> bool {
        match self.key_type {
            KeyType::CryptographicRandom
            | KeyType::Seed
            | KeyType::MACKey
            | KeyType::SymmetricCipherKey => true,
            KeyType::Zeroized | KeyType::Unknown => false,
        }
    }

    fn zeroize(&mut self) {
        self.buf.fill(0u8);
        self.key_len = 0;
        self.key_type = KeyType::Zeroized;
    }

    fn equals(&self, other: &dyn KeyMaterialTrait) -> bool {
        if self.key_len() != other.key_len() {
            return false;
        }
        ct::ct_eq_bytes(&self.ref_to_bytes(), &other.ref_to_bytes())
    }
}

/// Checks for equality of the key data (using a constant-time comparison), but does not check that
/// the two keys have the same type.
/// Therefore, for example, two keys loaded from the same bytes, one with type [KeyType::Unknown] and
/// the other with [KeyType::MACKey] will be considered equal.
impl<const KEY_LEN: usize> PartialEq for KeyMaterial<KEY_LEN> {
    fn eq(&self, other: &Self) -> bool {
        if self.key_len != other.key_len {
            return false;
        }
        ct::ct_eq_bytes(&self.buf[..self.key_len], &other.buf[..self.key_len])
    }
}
impl<const KEY_LEN: usize> Eq for KeyMaterial<KEY_LEN> {}

/// Ordering is as follows:
/// Zeroized < BytesLowEntropy < BytesFullEntropy < {Seed = MACKey = SymmetricCipherKey}
impl PartialOrd for KeyType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self {
            KeyType::Zeroized => match other {
                KeyType::Zeroized => Some(Ordering::Equal),
                _ => Some(Ordering::Less),
            },
            KeyType::Unknown => match other {
                KeyType::Zeroized => Some(Ordering::Greater),
                KeyType::Unknown => Some(Ordering::Equal),
                _ => Some(Ordering::Less),
            },
            KeyType::CryptographicRandom => match other {
                KeyType::Zeroized | KeyType::Unknown => Some(Ordering::Greater),
                KeyType::CryptographicRandom => Some(Ordering::Equal),
                _ => Some(Ordering::Less),
            },
            KeyType::Seed | KeyType::MACKey | KeyType::SymmetricCipherKey => match other {
                KeyType::Zeroized | KeyType::Unknown | KeyType::CryptographicRandom => {
                    Some(Ordering::Greater)
                }
                KeyType::Seed | KeyType::MACKey | KeyType::SymmetricCipherKey => {
                    Some(Ordering::Equal)
                }
            },
        }
    }
}

/// Block accidental logging of the internal key material buffer.
impl<const KEY_LEN: usize> fmt::Display for KeyMaterial<KEY_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyMaterial {{ len: {}, key_type: {:?}, security_strength: {:?} }}",
            self.key_len, self.key_type, self.security_strength
        )
    }
}

/// Block accidental logging of the internal key material buffer.
impl<const KEY_LEN: usize> fmt::Debug for KeyMaterial<KEY_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyMaterial {{ len: {}, key_type: {:?}, security_strength: {:?} }}",
            self.key_len, self.key_type, self.security_strength
        )
    }
}

/// Zeroize the key material on drop.
impl<const KEY_LEN: usize> Drop for KeyMaterial<KEY_LEN> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

/* Hazardous Operations Runner */

/// Internal-use trait holding the low-level hazardous-operations guard toggle.
///
/// These methods are deliberately split out of [KeyMaterialTrait] into a private trait so that
/// they are not accessible from outside this module.
///
/// This is a supertrait of [KeyMaterialTrait], so anything that implements [KeyMaterialTrait]
/// also implements this. [KeyMaterialTrait] therefore stays dyn-compatible (both methods here are
/// object-safe), which matters because `Box<dyn KeyMaterialTrait>` is used widely as a return type.
trait KeyMaterialInternalTrait {
    /// Whether this instance is currently allowed to perform potentially hazardous operations.
    fn allows_hazardous_operations(&self) -> bool;
    /// Sets this instance to be able to perform potentially hazardous operations such as
    /// casting a KeyMaterial of type RawUnknownEntropy or RawLowEntropy into RawFullEntropy or SymmetricCipherKey,
    /// or manually setting the key bytes via [KeyMaterialTrait::mut_ref_to_bytes], which then requires you to be responsible
    /// for setting the key_len and key_type afterwards.
    ///
    /// The purpose of the hazardous operations guard is not to prevent the user from accessing their data,
    /// but rather to make the developer think carefully about the operation they are about to perform,
    /// and to give static analysis tools an obvious marker that a given KeyMaterial variable warrants
    /// further inspection.
    ///
    /// Prefer the scoped [KeyMaterial::do_hazardous_operations] wrapper, which calls this and
    /// [KeyMaterialInternalTrait::drop_hazardous_operations] for you so the guard can't be left set.
    fn allow_hazardous_operations(&mut self);

    /// Resets this instance to not be able to perform potentially hazardous operations.
    fn drop_hazardous_operations(&mut self);
}

impl<const KEY_LEN: usize> KeyMaterialInternalTrait for KeyMaterial<KEY_LEN> {
    fn allows_hazardous_operations(&self) -> bool {
        self.allow_hazardous_operations
    }
    fn allow_hazardous_operations(&mut self) {
        self.allow_hazardous_operations = true;
    }
    fn drop_hazardous_operations(&mut self) {
        self.allow_hazardous_operations = false;
    }
}

/// Runs the provided closure within which hazardous operations are allowed.
/// All hazardous operations will return a [KeyMaterialError::HazardousOperationNotPermitted]
/// if used outside of this closure.
///
/// Example usage:
///
/// ```rust
/// use bouncycastle_core::key_material::{KeyType, KeyMaterial256, KeyMaterialTrait, do_hazardous_operations};
/// use bouncycastle_core::traits::SecurityStrength;
///
/// // Let's create an all-zero key
/// let mut key = KeyMaterial256::default();
///
/// // Let's set a key of all zeroes, which the library would normally force to be
/// // [KeyType::Zeroized], but we want to force it to [KeyType::Seed], which is considered a
/// // hazardous operation.
/// do_hazardous_operations(&mut key, |key| {
///     key.set_bytes_as_type(&[8u8; 32], KeyType::Seed)
///     // note that the closure is required to return Result<(), KeyMaterialError>,
///     // so we can chain [KeyMaterial::set_bytes_as_type], otherwise we would need
///     // to end with Ok(()).
/// }).unwrap();
///
/// assert_eq!(key.key_len(), 32);
/// assert_eq!(key.key_type(), KeyType::Seed);
/// ```
///
/// ```rust
/// use bouncycastle_core::key_material::{KeyType, KeyMaterial256, KeyMaterialTrait, do_hazardous_operations};
/// use bouncycastle_core::traits::SecurityStrength;
///
/// // Let's create an all-zero key
/// let mut key = KeyMaterial256::default();
/// assert_eq!(key.key_type(), KeyType::Zeroized);
/// assert_eq!(key.security_strength(), SecurityStrength::None);
///
/// // Now we want to tell the library that this all-zero key
/// // is to be used as a 32-byte [KeyType::Seed] at the 256-bit security strength,
/// // which the library will not allow you to do outside of the hazerdous operations closure.
/// do_hazardous_operations(&mut key, |key| {
///     key.set_key_len(32)?;
///     key.set_key_type(KeyType::Seed)?;
///     key.set_security_strength(SecurityStrength::_256bit)?;
///     Ok(())
/// }).unwrap();
///
/// assert_eq!(key.key_type(), KeyType::Seed);
/// assert_eq!(key.security_strength(), SecurityStrength::_256bit);
/// ```
///
/// Another common usage of hazardous operations is to get a direct mutable reference to the
/// underlying KeyMaterial byte buffer; for example if you want to copy in key bytes from somewhere else.
///
/// ```rust
/// use bouncycastle_core::key_material::{KeyType, KeyMaterial512, KeyMaterialTrait, do_hazardous_operations};
/// use bouncycastle_core::traits::SecurityStrength;
///
/// // In this example, we initialize a KeyMateriol512 (64 bytes) with only 32 bytes of input.
/// let mut key = KeyMaterial512::from_bytes_as_type(
///                                 &[1u8; 32],
///                                 KeyType::CryptographicRandom
///                         ).unwrap();
/// assert_eq!(key.key_len(), 32);
///
/// // Now we want to expand the length to 64 bytes and copy in an additional 32 bytes of key data,
/// // using [KeyMaterial::mut_ref_to_bytes].
/// let additional_bytes = [2u8; 32];
/// do_hazardous_operations(&mut key, |key| {
///     key.set_key_len(64)?;
///     key.ref_to_bytes_mut()?[32..].copy_from_slice(&additional_bytes);
///     Ok(())
/// }).unwrap();
///
/// assert_eq!(key.key_len(), 64);
/// // Reading the key bytes via [KeyMateriol::ref_to_bytes] is not a hazardous operation.
/// assert_eq!(key.ref_to_bytes()[..32], [1u8; 32]);
/// assert_eq!(key.ref_to_bytes()[32..], [2u8; 32]);
/// ```
///
// Dev note: This is a free function rather than a method on [KeyMaterialTrait] because it is
// generic over the closure type, which would make the trait non-dyn-compatible; the trait is used
// as `&dyn KeyMaterialTrait` elsewhere (e.g. [KeyMaterialTrait::concatenate], [KeyMaterialTrait::equals]).
// The toggle itself lives on the module-private [KeyMaterialInternalTrait], so external crates cannot
// flip the guard by hand and must go through this scoped wrapper (hence `#[allow(private_bounds)]`).
#[allow(private_bounds)]
pub fn do_hazardous_operations<KEY, F>(key: &mut KEY, f: F) -> Result<(), KeyMaterialError>
where
    KEY: KeyMaterialTrait + ?Sized,
    F: FnOnce(&mut KEY) -> Result<(), KeyMaterialError>,
{
    let allows = key.allows_hazardous_operations();

    key.allow_hazardous_operations();
    let ret = f(key);

    // to allow nested closures, if this key instance allowed
    // before entering, then leave it.
    if !allows {
        key.drop_hazardous_operations();
    }
    ret
}
