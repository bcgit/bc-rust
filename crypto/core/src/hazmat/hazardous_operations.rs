//! [`do_hazardous_operations`]: the scoped override for [`KeyMaterial`](crate::key_material)'s checks.

use crate::errors::KeyMaterialError;
use crate::key_material::KeyMaterialTrait;

/// Runs the provided closure within which hazardous operations are allowed.
/// All hazardous operations will return a [`KeyMaterialError::HazardousOperationNotPermitted`]
/// if used outside of this closure.
///
/// Example usage:
///
/// ```rust
/// use bouncycastle_core::hazmat::do_hazardous_operations;
/// use bouncycastle_core::key_material::{KeyType, KeyMaterial256, KeyMaterialTrait};
/// use bouncycastle_core::security_strength::SecurityStrength;
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
/// use bouncycastle_core::hazmat::do_hazardous_operations;
/// use bouncycastle_core::key_material::{KeyType, KeyMaterial256, KeyMaterialTrait};
/// use bouncycastle_core::security_strength::SecurityStrength;
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
/// use bouncycastle_core::hazmat::do_hazardous_operations;
/// use bouncycastle_core::key_material::{KeyType, KeyMaterial512, KeyMaterialTrait};
/// use bouncycastle_core::security_strength::SecurityStrength;
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
// The toggle itself lives on the crate-private [KeyMaterialInternalTrait], so external crates cannot
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
