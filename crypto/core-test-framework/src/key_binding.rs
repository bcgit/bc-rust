//! The algorithm-binding half of the key policy every cipher's init enforces: a key bound to the
//! cipher's own [`Algorithm::ALG_NAME`] is accepted, and one bound to any other algorithm is
//! refused with [`KeyMaterialError::InvalidKeyType`]. Unbound keys are what every other check in
//! these suites uses, so their acceptance is covered there.
//!
//! [`Algorithm::ALG_NAME`]: bouncycastle_core::traits::Algorithm::ALG_NAME

use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};

/// A name no algorithm reports, for a key bound "somewhere else".
const OTHER_ALGORITHM: &str = "bouncycastle-core-test-framework: some other algorithm";

/// `key`, bound to `alg_name`.
pub(crate) fn bound_to<const KEY_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    alg_name: &'static str,
) -> KeyMaterial<KEY_LEN> {
    let mut bound = key.clone();
    bound.set_algorithm(Some(alg_name)).unwrap();
    bound
}

/// `key`, bound to an algorithm that no cipher is.
pub(crate) fn bound_elsewhere<const KEY_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
) -> KeyMaterial<KEY_LEN> {
    bound_to(key, OTHER_ALGORITHM)
}

/// Asserts that `what` refused a key bound to another algorithm, for that reason.
pub(crate) fn assert_refused<T>(result: Result<T, SymmetricCipherError>, what: &str) {
    match result {
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
        Ok(_) => panic!("{what} accepted a key bound to a different algorithm"),
        Err(_) => {
            panic!("{what} refused a key bound to a different algorithm with the wrong error")
        }
    }
}
