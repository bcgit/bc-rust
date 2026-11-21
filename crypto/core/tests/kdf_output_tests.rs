//! `hazmat::label_kdf_output`, the `KDF` trait's rule for typing derived keying material.

use bouncycastle_core::hazmat::{do_hazardous_operations, label_kdf_output};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;

/// A key of `len` bytes typed `key_type`, with the strength its length gives (none below 14
/// bytes, and none for `Unknown`).
fn key(len: usize, key_type: KeyType) -> KeyMaterial<64> {
    let bytes: Vec<u8> = (1..=len as u8).collect();
    KeyMaterial::from_bytes_as_type(&bytes, key_type).unwrap()
}

/// As [`key`], with the strength set to `strength`.
fn key_at(len: usize, key_type: KeyType, strength: SecurityStrength) -> KeyMaterial<64> {
    let mut k = key(len, key_type);
    do_hazardous_operations(&mut k, |k| k.set_security_strength(strength)).unwrap();
    k
}

/// The type and strength `label_kdf_output` gives `len` bytes derived from `keys`.
fn label(
    keys: &[&dyn KeyMaterialTrait],
    len: usize,
    seed_len: usize,
    max_strength: SecurityStrength,
) -> (KeyType, SecurityStrength) {
    let mut dkm = KeyMaterial::<64>::new();
    label_kdf_output(keys, len, seed_len, max_strength, &mut dkm).unwrap();
    assert_eq!(dkm.key_len(), len);
    (dkm.key_type(), dkm.security_strength())
}

const UNKNOWN: (KeyType, SecurityStrength) = (KeyType::Unknown, SecurityStrength::None);
const MAX: SecurityStrength = SecurityStrength::_256bit;

fn random(strength: SecurityStrength) -> (KeyType, SecurityStrength) {
    (KeyType::CryptographicRandom, strength)
}

/// The output is `CryptographicRandom` exactly when the credited bytes reach the bound.
#[test]
fn the_seeding_threshold() {
    let k16 = key(16, KeyType::CryptographicRandom);
    assert_eq!(label(&[&k16], 32, 16, MAX), random(SecurityStrength::_128bit));
    assert_eq!(label(&[&k16], 32, 17, MAX), UNKNOWN);

    // The bytes of several keys add up.
    let k14 = key(14, KeyType::CryptographicRandom);
    assert_eq!(label(&[&k14, &k14], 32, 28, MAX), random(SecurityStrength::_112bit));
    assert_eq!(label(&[&k14, &k14], 32, 29, MAX), UNKNOWN);

    assert_eq!(label(&[], 32, 16, MAX), UNKNOWN);
}

/// Only a full-entropy key with a strength credits its bytes, or lends its strength.
#[test]
fn which_keys_are_credited() {
    for full_entropy in [
        KeyType::CryptographicRandom,
        KeyType::Seed,
        KeyType::MACKey,
        KeyType::SymmetricCipherKey,
        KeyType::SharedSecret,
    ] {
        // Stated outright: a `SharedSecret` is given no strength by its length.
        let k = key_at(32, full_entropy, SecurityStrength::_256bit);
        assert_eq!(
            label(&[&k], 32, 32, MAX),
            random(SecurityStrength::_256bit),
            "{full_entropy:?}"
        );
    }

    let unknown = key(32, KeyType::Unknown);
    assert_eq!(label(&[&unknown], 32, 16, MAX), UNKNOWN);

    // A shared secret whose producer stated no strength, and a key too short to carry one.
    let unstated = key(32, KeyType::SharedSecret);
    assert_eq!(unstated.security_strength(), SecurityStrength::None);
    assert_eq!(label(&[&unstated], 32, 16, MAX), UNKNOWN);
    let short = key(13, KeyType::CryptographicRandom);
    assert_eq!(short.security_strength(), SecurityStrength::None);
    assert_eq!(label(&[&short, &short], 32, 16, MAX), UNKNOWN);

    // Beside a credited key, neither adds bytes: 16 credited bytes do not reach 17.
    let k16 = key(16, KeyType::CryptographicRandom);
    assert_eq!(
        label(&[&k16, &unknown, &unstated, &short], 32, 16, MAX),
        random(SecurityStrength::_128bit)
    );
    assert_eq!(label(&[&k16, &unknown, &unstated, &short], 32, 17, MAX), UNKNOWN);
}

/// The strength is the least of the strongest credited key's, the function's and the length's.
#[test]
fn the_strength_of_the_output() {
    let k128 = key(16, KeyType::CryptographicRandom);
    let k256 = key(32, KeyType::CryptographicRandom);

    // The strongest key's, in either order.
    assert_eq!(label(&[&k128, &k256], 32, 16, MAX), random(SecurityStrength::_256bit));
    assert_eq!(label(&[&k256, &k128], 32, 16, MAX), random(SecurityStrength::_256bit));
    // A key's stated strength counts, not its length.
    let long_weak = key_at(32, KeyType::CryptographicRandom, SecurityStrength::_128bit);
    assert_eq!(label(&[&long_weak], 32, 16, MAX), random(SecurityStrength::_128bit));

    // Capped by the function.
    assert_eq!(
        label(&[&k256], 32, 16, SecurityStrength::_192bit),
        random(SecurityStrength::_192bit)
    );
    assert_eq!(
        label(&[&k256], 32, 16, SecurityStrength::_128bit),
        random(SecurityStrength::_128bit)
    );
    assert_eq!(
        label(&[&k128], 32, 16, SecurityStrength::_192bit),
        random(SecurityStrength::_128bit)
    );

    // Capped by what the length can hold; below 14 bytes that is nothing, on a random output.
    assert_eq!(label(&[&k256], 24, 16, MAX), random(SecurityStrength::_192bit));
    assert_eq!(label(&[&k256], 16, 16, MAX), random(SecurityStrength::_128bit));
    assert_eq!(label(&[&k256], 14, 16, MAX), random(SecurityStrength::_112bit));
    assert_eq!(label(&[&k256], 13, 16, MAX), random(SecurityStrength::None));
}

/// A length the buffer cannot hold is the setters' error.
#[test]
fn a_length_beyond_the_buffer_is_refused() {
    let k = key(32, KeyType::CryptographicRandom);
    let mut dkm = KeyMaterial::<16>::new();
    assert!(label_kdf_output(&[&k], 17, 16, MAX, &mut dkm).is_err());
    assert!(label_kdf_output(&[&k], 16, 16, MAX, &mut dkm).is_ok());
}
