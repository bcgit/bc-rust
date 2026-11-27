//! `hazmat::label_kdf_output` and `hazmat::KdfCredit`, the `KDF` trait's rule for typing derived
//! keying material.

use bouncycastle_core::hazmat::{KdfCredit, do_hazardous_operations, label_kdf_output};
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

/// The running account: each key returns what it credits, the count is the sum, and the label
/// it gives is `label_kdf_output`'s over the same keys, a copy of the account included.
#[test]
fn the_running_account_is_the_rule() {
    let k16 = key(16, KeyType::CryptographicRandom);
    let k32 = key(32, KeyType::MACKey);
    let unknown = key(32, KeyType::Unknown);
    let unstated = key(32, KeyType::SharedSecret);
    let short = key(13, KeyType::CryptographicRandom);
    let zeroized = KeyMaterial::<64>::new();

    let mut credit = KdfCredit::new();
    assert_eq!(credit.credited(), 0);
    assert_eq!(KdfCredit::default().credited(), 0);
    for uncredited in [&unknown, &unstated, &short, &zeroized] {
        assert_eq!(credit.credit(uncredited), 0);
        assert_eq!(credit.credited(), 0);
    }
    assert_eq!(credit.credit(&k16), 16);
    assert_eq!(credit.credited(), 16);
    let after_one = credit;
    assert_eq!(credit.credit(&k32 as &dyn KeyMaterialTrait), 32);
    assert_eq!(credit.credited(), 48);
    assert_eq!(after_one.credited(), 16, "a copy is its own account");

    let labelled = |credit: &KdfCredit, len, seed_len, max_strength| {
        let mut dkm = KeyMaterial::<64>::new();
        credit.label_output(len, seed_len, max_strength, &mut dkm).unwrap();
        assert_eq!(dkm.key_len(), len);
        (dkm.key_type(), dkm.security_strength())
    };
    for (len, seed_len, max_strength) in [
        (32, 16, MAX),
        (32, 17, MAX),
        (32, 48, MAX),
        (32, 49, MAX),
        (32, 16, SecurityStrength::_192bit),
        (13, 16, MAX),
        (32, 16, SecurityStrength::None),
    ] {
        assert_eq!(
            labelled(&after_one, len, seed_len, max_strength),
            label(&[&k16], len, seed_len, max_strength)
        );
        assert_eq!(
            labelled(&credit, len, seed_len, max_strength),
            label(&[&unknown, &k16, &k32], len, seed_len, max_strength)
        );
    }
    // Spelled out at the ends: nothing credited, and both keys.
    assert_eq!(labelled(&KdfCredit::new(), 32, 16, MAX), UNKNOWN);
    assert_eq!(labelled(&after_one, 32, 17, MAX), UNKNOWN);
    assert_eq!(labelled(&credit, 32, 48, MAX), random(SecurityStrength::_256bit));
    assert_eq!(labelled(&credit, 32, 49, MAX), UNKNOWN);

    // The same key given again counts again.
    let mut twice = KdfCredit::new();
    twice.credit(&k32);
    twice.credit(&k32);
    assert_eq!(twice.credited(), 64);
}

/// A function that claims no strength labels a seeded output `CryptographicRandom` with none.
#[test]
fn a_function_with_no_strength() {
    let k32 = key(32, KeyType::CryptographicRandom);
    assert_eq!(label(&[&k32], 32, 10, SecurityStrength::None), random(SecurityStrength::None));
    assert_eq!(label(&[&k32], 32, 33, SecurityStrength::None), UNKNOWN);
}
