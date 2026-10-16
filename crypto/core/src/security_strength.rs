//! Provides the [`SecurityStrength`] struct.

use crate::errors::SuspendableError;

/// A general indicator used across the library for marking the security level of a cryptographic primitive,
/// and for tracking the security level of the algorithms that interacted with a given piece of data.
/// For example, if a KDF at the 128-bit security strength is used to produce a 512-bit key, that key
/// will also be tagged as having a 128-bit security strength.
///
/// Some functions across the library may reject or behave differently based on the security strength
/// of the inputs they are given. For example a `keygen_from_seed()` may reject a seed taged at a lower
/// security strength than the one required by the algorithm, or it may proceed, but lower its own
/// advertised security strength accordingly -- each cryptographic primitive may have additional detail.
// Dev note: The explicit `#[repr(u8)]` discriminants are the stable on-the-wire encoding used by
// `SerializableState` implementations (see the corresponding `TryFrom<u8>` impl below).
// If additional strength levels are added in the future, they can be placed into the enum in
// any order, but should use currently unassigned values (unless you're doing this on a MAJOR or MINOR
// release as a breaking change).
#[derive(Eq, PartialEq, PartialOrd, Clone, Copy, Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum SecurityStrength {
    ///
    None = 0,
    ///
    _112bit = 1,
    ///
    _128bit = 2,
    ///
    _192bit = 3,
    ///
    _256bit = 4,
}

impl TryFrom<u8> for SecurityStrength {
    type Error = SuspendableError;

    /// Inverse of `self as u8`; rejects unrecognized discriminants with [`SuspendableError::InvalidData`].
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::None,
            1 => Self::_112bit,
            2 => Self::_128bit,
            3 => Self::_192bit,
            4 => Self::_256bit,
            _ => return Err(SuspendableError::InvalidData),
        })
    }
}

impl SecurityStrength {
    /// Rounds down to the closest supported security strength.
    /// For example, 120-bits is rounded down to 112-bit.
    pub const fn from_bits(bits: usize) -> Self {
        if bits < 112 {
            Self::None
        } else if bits < 128 {
            Self::_112bit
        } else if bits < 192 {
            Self::_128bit
        } else if bits < 256 {
            Self::_192bit
        } else {
            Self::_256bit
        }
    }

    /// Rounds down to the closest supported security strength.
    /// For example, 15 bytes (120-bits) is rounded down to 112-bit.
    pub const fn from_bytes(bytes: usize) -> Self {
        Self::from_bits(bytes * 8)
    }

    /// Outputs the security strength in bits for easier computation.
    pub fn as_int(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::_112bit => 112,
            Self::_128bit => 128,
            Self::_192bit => 192,
            Self::_256bit => 256,
        }
    }
}
