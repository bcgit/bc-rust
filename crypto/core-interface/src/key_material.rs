//! A helper class used across the bc-rust library to hold bytes-like key material.
//! The main purpose is to hold metadata about the contained key material such as the key type and
//! entropy content to prevent accidental misuse security bugs, such as deriving cryptographic keys
//! from uninitialized data.
//!
//! This object allows several types of manual-overrides, which typically require setting the [KeyMaterialSized::allow_hazardous_operations] flag.
//! For example, the raw bytes data can be extracted, or the key forced to a certain type,
//! but well-designed use of the bc-rust.test library should not need to ever set the [KeyMaterialSized::allow_hazardous_operations] flag.
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
//! However, there is a [KeyMaterialSized::convert_key_type] for cases where the user has more context knowledge than the library.
//! Some conversions, such as converting a key of type RawLowEntropy into a SymmetricCipherKey, will fail unless
//! the user has explicitly allowed them via calling allow_hazardous_operations() prior to the conversion.
//!
//! Examples of hazardous conversions that require allow_hazardous_operations() to be called first:
//!
//! * Converting a KeyMaterial of type RawLowEntropy or RawUnknownEntropy into RawFullEntropy or any other full-entropy key type.
//! * Converting any algorithm-specific key type into a different algorithm-specific key type, which is considered hazardous since key reuse between different cryptographic algorithms is generally discouraged and can sometimes lead to key leakage.
//!
//! Additional security features:
//!   * Zeroizes on destruction.
//!   * Implementing Display and Debug to print metadata but not key material to prevent accidental logging.
//!
//! As with all wrappers of this nature, the intent is to protect the user from making silly mistakes, not to prevent expert users from doing what they need to do.
//! It as always possible, for example, to extract the bytes from a KeyMaterial object, manipulate them, and then re-wrap them in a new KeyMaterial object.

use crate::errors::KeyMaterialError;
use crate::traits::{RNG, SecurityStrength};
use bouncycastle_utils::{ct, max, min};

use std::cmp::{Ordering, PartialOrd};
use std::fmt;

/// Sometimes you just need a zero-length dummy key.
pub type KeyMaterial0 = KeyMaterialSized<0>;

pub type KeyMaterial128 = KeyMaterialSized<16>;
pub type KeyMaterial256 = KeyMaterialSized<32>;
pub type KeyMaterial512 = KeyMaterialSized<64>;


/// A helper class used across the bc-rust.test library to hold bytes-like key material.
/// See [KeyMaterialSized] for for details, such as constructors.
pub trait KeyMaterial {
    /// Loads the provided data into a new KeyMaterial of the specified type.
    /// This is discouraged unless the caller knows the provenance of the data, such as loading it
    /// from a cryptographic private key file.
    /// It will detect if you give it all-zero source data and set the key type to [KeyType::Zeroized] instead.
    /// Since this zeroizes and resets the key material, this is considered a dangerous conversion.
    ///
    /// The only hazardous operation here that requires setting [KeyMaterial::allow_hazardous_operations] is giving it
    /// an all-zero key, which is checked as a courtesy to catch mistakes of feeding an initialized buffer
    /// instead of an actual key. See the note on [KeyMaterialSized::set_bytes_as_type] for suggestions
    /// for handling this.
    fn set_bytes_as_type(
        &mut self,
        source: &[u8],
        key_type: KeyType,
    ) -> Result<(), KeyMaterialError>;

    /// Get a reference to the underlying key material bytes.
    ///
    /// By reading the key bytes out of the [KeyMaterial] object, you lose the protections that it offers,
    /// however, this does not require [KeyMaterial::allow_hazardous_operations] in the name of API ergonomics:
    /// setting [KeyMaterial::allow_hazardous_operations] requires a mutable reference and reading the bytes
    /// is not an operation that should require mutability.
    /// TODO -- consider whether this should consume the object
    fn ref_to_bytes(&self) -> &[u8];

    /// Get a mutable reference to the underlying key material bytes so that you can read or write
    /// to the underlying bytes without needing to create a temporary buffer, especially useful in
    /// cases where the required size of that buffer may be tricky to figure out at compile-time.
    /// This requires [KeyMaterial::allow_hazardous_operations] to be set.
    /// When writing directly to the buffer, you are responsible for setting the key_len and key_type afterwards,
    /// and you should [KeyMaterial::drop_hazardous_operations].
    fn mut_ref_to_bytes(&mut self) -> Result<&mut [u8], KeyMaterialError>;

    /// The size of the internal buffer; ie the largest key that this instance can hold.
    /// Equivalent to the <KEY_LEN> constant param this object was created with.
    fn capacity(&self) -> usize;

    /// Length of the key material in bytes.
    fn key_len(&self) -> usize;

    /// Requires [KeyMaterial::allow_hazardous_operations].
    fn set_key_len(&mut self, key_len: usize) -> Result<(), KeyMaterialError>;

    fn key_type(&self) -> KeyType;

    /// Requires [KeyMaterial::allow_hazardous_operations].
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

    /// Requires [KeyMaterial::allow_hazardous_operations] to raise the security strength, but not to lower it.
    /// Throws [KeyMaterialError::HazardousOperationNotPermitted] on a request to raise the security level without
    /// [KeyMaterial::allow_hazardous_operations] set.
    /// Throws [KeyMaterialError::InvalidLength] on a request to set the security level higher than the current key length.
    fn set_security_strength(&mut self, strength: SecurityStrength)
                             -> Result<(), KeyMaterialError>;

    /// Sets this instance to be able to perform potentially hazardous conversions such as
    /// casting a KeyMaterial of type RawUnknownEntropy or RawLowEntropy into RawFullEntropy or SymmetricCipherKey,
    /// or manually setting the key bytes via [KeyMaterial::mut_ref_to_bytes], which then requires you to be responsible
    /// for setting the key_len and key_type afterwards.
    ///
    /// The purpose of the hazardous_conversions guard is not to prevent the user from accessing their data,
    /// but rather to make the developer think carefully about the operation they are about to perform,
    /// and to give static analysis tools an obvious marker that a given KeyMaterial variable warrants
    /// further inspection.
    fn allow_hazardous_operations(&mut self);

    /// Resets this instance to not be able to perform potentially hazardous conversions.
    fn drop_hazardous_operations(&mut self);

    /// Sets the key_type of this KeyMaterial object.
    /// Does not perform any operations on the actual key material, other than changing the key_type field.
    /// If allow_hazardous_operations is true, this method will allow conversion to any KeyType, otherwise
    /// checking is performed to ensure that the conversion is "safe".
    /// This drops the allow_hazardous_operations flag, so if you need to do multiple hazardous conversions
    /// on the same instance, then you'll need to call .allow_hazardous_operations() each time.
    fn convert_key_type(&mut self, new_key_type: KeyType) -> Result<(), KeyMaterialError>;

    fn is_full_entropy(&self) -> bool;

    fn zeroize(&mut self);

    /// Is simply an alias to [KeyMaterial::set_key_len], however, this does not require [KeyMaterial::allow_hazardous_operations]
    /// since truncation is a safe operation.
    /// If truncating below the current security strength, the security strength will be lowered accordingly.
    fn truncate(&mut self, new_len: usize) -> Result<(), KeyMaterialError>;

    /// Adds the other KeyMaterial into this one, assuming there is space.
    /// Does not require [KeyMaterial::allow_hazardous_operations].
    /// Throws [KeyMaterialError::InvalidLength] if this object does not have enough space to add the other one.
    /// The resulting [KeyType] and security strength will be the lesser of the two keys.
    /// In other words, concatenating two 128-bit full entropy keys generated at a 128-bit DRBG security level
    /// will result in a 256-bit full entropy key still at the 128-bit DRBG security level.
    /// Concatenating a full entropy key with a low entropy key will result in a low entropy key.
    ///
    /// Returns the new key_len.
    fn concatenate(&mut self, other: &dyn KeyMaterial) -> Result<usize, KeyMaterialError>;

    /// Perform a constant-time comparison between the two key material buffers,
    /// ignoring differences in capacity, [KeyType], [SecurityStrength], etc.
    fn equals(&self, other: &dyn KeyMaterial) -> bool;
}

/// A wrapper for holding bytes-like key material (symmetric keys or seeds) which aims to apply a
/// strict typing system to prevent many kinds of mis-use mistakes.
/// The capacity of the internal buffer can be set at compile-time via the <KEY_LEN> param.
#[derive(Clone)]
pub struct KeyMaterialSized<const KEY_LEN: usize> {
    buf: [u8; KEY_LEN],
    key_len: usize,
    key_type: KeyType,
    security_strength: SecurityStrength,
    allow_hazardous_operations: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyType {
    /// The KeyMaterial is zeroized and MUST NOT be used for any cryptographic operation in this state.
    Zeroized,

    /// The KeyMaterial contains data of low or unknown entropy.
    BytesLowEntropy,

    /// The KeyMaterial contains data of full entropy and can be safely converted to any other full-entropy key type.
    BytesFullEntropy,

    /// A seed for asymmetric private keys, RNGs, and other seed-based cryptographic objects.
    Seed,

    /// A MAC key.
    MACKey,

    /// A key for a symmetric block or stream cipher.
    SymmetricCipherKey,
}

impl<const KEY_LEN: usize> Default for KeyMaterialSized<KEY_LEN> {
    /// Create a new empty (zeroized) instance.
    fn default() -> Self {
        Self::new()
    }
}

impl<const KEY_LEN: usize> KeyMaterialSized<KEY_LEN> {
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
        key.allow_hazardous_operations();

        rng.next_bytes_out(&mut key.mut_ref_to_bytes().unwrap())
            .map_err(|_| KeyMaterialError::GenericError("RNG failed."))?;

        key.key_len = KEY_LEN;
        key.key_type = KeyType::BytesFullEntropy;
        key.security_strength = rng.security_strength();
        key.drop_hazardous_operations();
        Ok(key)
    }

    /// Constructor.
    /// Loads the provided data into a new KeyMaterial of type [KeyType::BytesLowEntropy].
    /// It will detect if you give it all-zero source data and set the key type to [KeyType::Zeroized] instead.
    pub fn from_bytes(source: &[u8]) -> Result<Self, KeyMaterialError> {
        Self::from_bytes_as_type(source, KeyType::BytesLowEntropy)
    }

    /// Constructor.
    /// Loads the provided data into a new KeyMaterial of the specified type.
    /// This is discouraged unless the caller knows the provenance of the data, such as loading it
    /// from a cryptographic private key file.
    /// It will detect if you give it all-zero source data and set the key type to [KeyType::Zeroized] instead.
    ///
    /// Will set the [SecurityStrength] automatically according to the following rules:
    /// * If [KeyType] is [KeyType::Zeroized] or [KeyType::BytesLowEntropy] then it will be [SecurityStrength::None].
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
    pub fn from_key(other: &impl KeyMaterial) -> Result<Self, KeyMaterialError> {
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

impl<const KEY_LEN: usize> KeyMaterial for KeyMaterialSized<KEY_LEN> {
    /// Loads the provided data into a new KeyMaterial of the specified type.
    /// This is discouraged unless the caller knows the provenance of the data, such as loading it
    /// from a cryptographic private key file.
    ///
    /// This behaves differently on all-zero input key depending on whether [KeyMaterial::allow_hazardous_operations] is set:
    /// if not set, then it will succeed, setting the key type to [KeyType::Zeroized] and also return a [KeyMaterialError::ActingOnZeroizedKey]
    /// to indicate that you may want to perform error-handling, which could be manually setting the key type
    /// if you intend to allow zero keys, or do some other error-handling, like figure out why your RNG is broken.
    /// Note that even if a [KeyMaterialError::ActingOnZeroizedKey] is returned, the object is still populated and usable.
    /// For example, you could catch it like this:
    /// ```
    /// use core_interface::key_material::{KeyMaterial256, KeyType};
    /// use core_interface::key_material::KeyMaterial;
    /// use core_interface::errors::KeyMaterialError;
    ///
    /// let key_bytes = [0u8; 16];
    /// let mut key = KeyMaterial256::new();
    /// let res = key.set_bytes_as_type(&key_bytes, KeyType::BytesLowEntropy);
    /// match res {
    ///   Err(KeyMaterialError::ActingOnZeroizedKey) => {
    ///     // Either figure out why your passed an all-zero key,
    ///     // or set the key type manually, if that's what you intended.
    ///     key.allow_hazardous_operations();
    ///     key.set_key_type(KeyType::BytesLowEntropy).unwrap(); // probably you should do something more elegant than .unwrap in your code ;)
    ///     key.drop_hazardous_operations();
    ///   },
    ///   Err(_) => { /* figure out what else went wrong */ },
    ///   Ok(_) => { /* good */ },
    /// }
    /// ```
    /// On the other hand, if [KeyMaterial::allow_hazardous_operations] is set then it will just do what you asked without complaining.
    ///
    /// Since this zeroizes and resets the key material, this is considered a dangerous conversion.
    ///
    /// Will set the [SecurityStrength] automatically according to the following rules:
    /// * If [KeyType] is [KeyType::Zeroized] or [KeyType::BytesLowEntropy] then it will be [SecurityStrength::None].
    /// * Otherwise it will set it based on the length of the provided source bytes.
    fn set_bytes_as_type(
        &mut self,
        source: &[u8],
        key_type: KeyType,
    ) -> Result<(), KeyMaterialError> {
        let allowed_hazardous_operations = self.allow_hazardous_operations;
        self.allow_hazardous_operations();

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

        if new_key_type <= KeyType::BytesLowEntropy {
            self.set_security_strength(SecurityStrength::None)?;
        } else {
            self.set_security_strength(SecurityStrength::from_bits(source.len() * 8))?;
        }
        self.drop_hazardous_operations();

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

    fn mut_ref_to_bytes(&mut self) -> Result<&mut [u8], KeyMaterialError> {
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
        if !self.allow_hazardous_operations {
            return Err(KeyMaterialError::HazardousOperationNotPermitted);
        }
        if key_len > KEY_LEN {
            return Err(KeyMaterialError::InvalidLength);
        }
        self.key_len = key_len;
        Ok(())
    }
    fn key_type(&self) -> KeyType {
        self.key_type.clone()
    }
    fn set_key_type(&mut self, key_type: KeyType) -> Result<(), KeyMaterialError> {
        if !self.allow_hazardous_operations {
            return Err(KeyMaterialError::HazardousOperationNotPermitted);
        }
        self.key_type = key_type.clone();
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

        if self.key_type <= KeyType::BytesLowEntropy && strength > SecurityStrength::None {
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
        self.drop_hazardous_operations();
        Ok(())
    }
    /// Sets this instance to be able to perform potentially hazardous operations such as
    /// casting a KeyMaterial of type RawUnknownEntropy or RawLowEntropy into RawFullEntropy or SymmetricCipherKey.
    ///
    /// The purpose of the hazardous operations guard is not to prevent the user from accessing their data,
    /// but rather to make the developer think carefully about the operation they are about to perform,
    /// and to give static analysis tools an obvious marker that a given KeyMaterial variable warrants
    /// further inspection.
    fn allow_hazardous_operations(&mut self) {
        self.allow_hazardous_operations = true;
    }
    /// Resets this instance to not be able to perform potentially hazardous operations.
    fn drop_hazardous_operations(&mut self) {
        self.allow_hazardous_operations = false;
    }
    /// Sets the key_type of this KeyMaterial object.
    /// Does not perform any operations on the actual key material, other than changing the key_type field.
    /// If allow_hazardous_operations is true, this method will allow conversion to any KeyType, otherwise
    /// checking is performed to ensure that the conversion is "safe".
    /// This drops the allow_hazardous_operations flag, so if you need to do multiple hazardous operations
    /// on the same instance, then you'll need to call .allow_hazardous_operations() each time.
    fn convert_key_type(&mut self, new_key_type: KeyType) -> Result<(), KeyMaterialError> {
        if self.allow_hazardous_operations {
            // just do it
            self.key_type = new_key_type;
            return Ok(());
        }

        match self.key_type {
            KeyType::Zeroized => {
                return Err(KeyMaterialError::ActingOnZeroizedKey);
            }
            KeyType::BytesFullEntropy => {
                // raw full entropy can be safely converted to anything.
                self.key_type = new_key_type;
            }
            KeyType::BytesLowEntropy => {
                match new_key_type {
                    KeyType::BytesLowEntropy => { /* No change */ }
                    _ => {
                        return Err(KeyMaterialError::HazardousOperationNotPermitted);
                    }
                }
            }
            KeyType::MACKey => {
                match new_key_type {
                    KeyType::MACKey => { /* No change */ }
                    // Else: Once a KeyMaterial is typed, it should stay that way.
                    _ => {
                        return Err(KeyMaterialError::HazardousOperationNotPermitted);
                    }
                }
            }
            KeyType::SymmetricCipherKey => {
                match new_key_type {
                    KeyType::SymmetricCipherKey => { /* No change */ }
                    // Else: Once a KeyMaterial is typed, it should stay that way.
                    _ => {
                        return Err(KeyMaterialError::HazardousOperationNotPermitted);
                    }
                }
            }
            KeyType::Seed => {
                match new_key_type {
                    KeyType::Seed => { /* No change */ }
                    // Else: Once a KeyMaterial is typed, it should stay that way.
                    _ => {
                        return Err(KeyMaterialError::HazardousOperationNotPermitted);
                    }
                }
            }
        }

        // each call to allow_hazardous_operations() is only good for one conversion.
        self.drop_hazardous_operations();
        Ok(())
    }
    fn is_full_entropy(&self) -> bool {
        match self.key_type {
            KeyType::BytesFullEntropy
            | KeyType::Seed
            | KeyType::MACKey
            | KeyType::SymmetricCipherKey => true,
            KeyType::Zeroized | KeyType::BytesLowEntropy => false,
        }
    }

    fn zeroize(&mut self) {
        self.buf.fill(0u8);
        self.key_len = 0;
        self.key_type = KeyType::Zeroized;
    }

    fn truncate(&mut self, new_len: usize) -> Result<(), KeyMaterialError> {
        if new_len > self.key_len {
            return Err(KeyMaterialError::InvalidLength);
        }

        self.security_strength =
            min(&self.security_strength, &SecurityStrength::from_bits(new_len * 8)).clone();

        if new_len == 0 {
            self.key_type = KeyType::Zeroized;
        }

        self.key_len = new_len;
        Ok(())
    }

    //
    // Q. T. Felix - start
    //
    fn concatenate(&mut self, other: &dyn KeyMaterial) -> Result<usize, KeyMaterialError> {
        let new_key_len = self.key_len() + other.key_len();
        if self.key_len() + other.key_len() > KEY_LEN {
            return Err(KeyMaterialError::InputDataLongerThanKeyCapacity);
        }
        self.buf[self.key_len..new_key_len].copy_from_slice(other.ref_to_bytes());
        self.key_len += other.key_len();
        // Q. T. Felix NOTE: concatenate 트레이트 Docstring에는 고품질 키와 저품질 키를 섞으면
        //                   보안성이 낮은 쪽(Low Entropy)으로 하향 평준화되어야 한다고 명시되어 있음
        //                   하지만 아래 실제 구현에는 bouncycastle_utils::max 함수로 Docstring 내용과
        //                   정확하게 반대됨.
        self.key_type = min(&self.key_type, &other.key_type()).clone();
        self.security_strength = min(&self.security_strength, &other.security_strength()).clone();
        Ok(self.key_len())
    }
    //
    // Q. T. Felix - end
    //

    fn equals(&self, other: &dyn KeyMaterial) -> bool {
        if self.key_len() != other.key_len() {
            return false;
        }
        ct::ct_eq_bytes(&self.ref_to_bytes(), &other.ref_to_bytes())
    }
}

/// Checks for equality of the key data (using a constant-time comparison), but does not check that
/// the two keys have the same type.
/// Therefore, for example, two keys loaded from the same bytes, one with type [KeyType::BytesLowEntropy] and
/// the other with [KeyType::MACKey] will be considered equal.
impl<const KEY_LEN: usize> PartialEq for KeyMaterialSized<KEY_LEN> {
    fn eq(&self, other: &Self) -> bool {
        if self.key_len != other.key_len {
            return false;
        }
        ct::ct_eq_bytes(&self.buf[..self.key_len], &other.buf[..self.key_len])
    }
}
impl<const KEY_LEN: usize> Eq for KeyMaterialSized<KEY_LEN> {}

/// Ordering is as follows:
/// Zeroized < BytesLowEntropy < BytesFullEntropy < {Seed = MACKey = SymmetricCipherKey}
impl PartialOrd for KeyType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self {
            KeyType::Zeroized => match other {
                KeyType::Zeroized => Some(Ordering::Equal),
                _ => Some(Ordering::Less),
            },
            KeyType::BytesLowEntropy => match other {
                KeyType::Zeroized => Some(Ordering::Greater),
                KeyType::BytesLowEntropy => Some(Ordering::Equal),
                _ => Some(Ordering::Less),
            },
            KeyType::BytesFullEntropy => match other {
                KeyType::Zeroized | KeyType::BytesLowEntropy => Some(Ordering::Greater),
                KeyType::BytesFullEntropy => Some(Ordering::Equal),
                _ => Some(Ordering::Less),
            },
            KeyType::Seed | KeyType::MACKey | KeyType::SymmetricCipherKey => match other {
                KeyType::Zeroized | KeyType::BytesLowEntropy | KeyType::BytesFullEntropy => {
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
impl<const KEY_LEN: usize> fmt::Display for KeyMaterialSized<KEY_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyMaterial {{ len: {}, key_type: {:?}, security_strength: {:?} }}",
            self.key_len, self.key_type, self.security_strength
        )
    }
}

/// Block accidental logging of the internal key material buffer.
impl<const KEY_LEN: usize> fmt::Debug for KeyMaterialSized<KEY_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyMaterial {{ len: {}, key_type: {:?}, security_strength: {:?} }}",
            self.key_len, self.key_type, self.security_strength
        )
    }
}

/// Zeroize the key material on drop.
impl<const KEY_LEN: usize> Drop for KeyMaterialSized<KEY_LEN> {
    fn drop(&mut self) {
        self.zeroize()
    }
}
