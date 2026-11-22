//! `hazmat::FixedSeedRNG`: the bytes it was given come back, in order and repeated, through
//! every `RNG` method off one cursor.

use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::key_material::{KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;

const SEED: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x05];

fn draw<const N: usize>(rng: &mut dyn RNG) -> [u8; N] {
    let mut out = [0u8; N];
    assert_eq!(rng.next_bytes_out(&mut out).unwrap(), N);
    out
}

#[test]
fn the_stream_is_the_seed_repeated() {
    let mut rng = FixedSeedRNG::new(SEED);
    let mut out = [0xAAu8; 12];
    assert_eq!(rng.next_bytes_out(&mut out).unwrap(), 12);
    assert_eq!(out, [1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2]);
    assert_eq!(rng.next_bytes_out(&mut []).unwrap(), 0);
}

/// Each method takes up where the last one stopped.
#[test]
fn every_method_draws_from_one_cursor() {
    let mut rng = FixedSeedRNG::new(&SEED[..]);
    assert_eq!(draw(&mut rng), [1, 2]);
    assert_eq!(rng.next_int().unwrap(), u32::from_le_bytes([3, 4, 5, 1]));
    let mut out = [0u8; 3];
    rng.next_bytes_out(&mut out).unwrap();
    assert_eq!(out, [2, 3, 4]);
    let mut key = KeyMaterial256::new();
    assert_eq!(rng.fill_keymaterial_out(&mut key).unwrap(), 32);
    assert_eq!(&key.ref_to_bytes()[..7], [5, 1, 2, 3, 4, 5, 1]);
    // 41 bytes drawn so far: the next is the second of the seed.
    assert_eq!(draw(&mut rng), [2]);
}

#[test]
fn two_instances_over_one_seed_agree() {
    let (mut a, mut b) = (FixedSeedRNG::new(SEED), FixedSeedRNG::new(SEED));
    assert_eq!(draw::<17>(&mut a), draw::<17>(&mut b));
    assert_eq!(a.next_int().unwrap(), b.next_int().unwrap());
}

/// What the Security Considerations warn of: the filled key is labelled a full 256-bit seed.
#[test]
fn filled_key_material_is_labelled_a_256_bit_seed() {
    let mut rng = FixedSeedRNG::new(SEED);
    let mut key = KeyMaterial256::new();
    rng.fill_keymaterial_out(&mut key).unwrap();
    assert_eq!(key.key_len(), 32);
    assert_eq!(key.key_type(), KeyType::Seed);
    assert_eq!(key.security_strength(), SecurityStrength::_256bit);
}

#[test]
fn the_reported_strength_is_256_bits_until_set() {
    let mut rng = FixedSeedRNG::new(SEED);
    assert_eq!(rng.security_strength(), SecurityStrength::_256bit);
    rng.set_security_strength(SecurityStrength::_128bit);
    assert_eq!(rng.security_strength(), SecurityStrength::_128bit);
}

/// Reseeding is ignored: the stream is fixed by construction.
#[test]
fn added_seed_material_changes_nothing() {
    let mut rng = FixedSeedRNG::new(SEED);
    rng.add_seed_keymaterial(&KeyMaterial256::from_bytes(&[0xFFu8; 32]).unwrap()).unwrap();
    assert_eq!(draw(&mut rng), SEED);
}

#[test]
#[should_panic]
fn an_empty_seed_panics_on_the_first_draw() {
    let _ = FixedSeedRNG::new([0u8; 0]).next_int();
}
