//! The two engines on the same random inputs: `Bitsliced`, the portable reference, against
//! `Arm`, the Crypto Extensions engine that is the default on this target.
//!
//! The known-answer suites in this directory already run on whichever engine is the default,
//! so on an AArch64 build with `aes` they exercise `Arm`. This file adds the randomised
//! comparison for every key size, both directions and all three widths, and pins that the
//! default really is `Arm` here.

#![cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "aes",
    target_feature = "neon"
))]

use bouncycastle_aes::hazmat::engine::{Arm, Bitsliced};
use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal, AESInternal};
use bouncycastle_aes::{AES128Params, AES192Params, AES256Params};
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::RNG;
use bouncycastle_rng::DefaultRNG;

type Block = [u8; 16];

fn random_key<const N: usize>(rng: &mut DefaultRNG) -> KeyMaterial<N> {
    let mut bytes = [0u8; N];
    rng.next_bytes_out(&mut bytes).unwrap();
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn random_blocks(rng: &mut DefaultRNG) -> [Block; 4] {
    let mut blocks = [[0u8; 16]; 4];
    for block in blocks.iter_mut() {
        rng.next_bytes_out(block).unwrap();
    }
    blocks
}

/// Runs both engines over the same key and blocks through all six entry points and demands
/// byte-identical results, in both directions.
fn agree<const K: usize, A, B>(rng: &mut DefaultRNG)
where
    A: ElectronicCodeBook<K, 16>,
    B: ElectronicCodeBook<K, 16>,
{
    let key = random_key::<K>(rng);
    let a = A::new(&key).unwrap();
    let b = B::new(&key).unwrap();
    let plaintext = random_blocks(rng);

    let mut four_a = plaintext;
    let mut four_b = plaintext;
    a.encrypt_4blocks(&mut four_a);
    b.encrypt_4blocks(&mut four_b);
    assert_eq!(four_a, four_b, "encrypt_4blocks");
    let ciphertext = four_a;
    a.decrypt_4blocks(&mut four_a);
    b.decrypt_4blocks(&mut four_b);
    assert_eq!(four_a, plaintext, "decrypt_4blocks, engine A");
    assert_eq!(four_b, plaintext, "decrypt_4blocks, engine B");

    for i in [0, 2] {
        let mut pair_a = [plaintext[i], plaintext[i + 1]];
        let mut pair_b = pair_a;
        a.encrypt_2blocks(&mut pair_a);
        b.encrypt_2blocks(&mut pair_b);
        assert_eq!(pair_a, [ciphertext[i], ciphertext[i + 1]], "encrypt_2blocks, engine A");
        assert_eq!(pair_b, pair_a, "encrypt_2blocks");
        a.decrypt_2blocks(&mut pair_a);
        b.decrypt_2blocks(&mut pair_b);
        assert_eq!(pair_a, [plaintext[i], plaintext[i + 1]], "decrypt_2blocks, engine A");
        assert_eq!(pair_b, pair_a, "decrypt_2blocks");
    }

    for i in 0..4 {
        let mut one_a = plaintext[i];
        let mut one_b = plaintext[i];
        a.encrypt_block(&mut one_a);
        b.encrypt_block(&mut one_b);
        assert_eq!(one_a, ciphertext[i], "encrypt_block, engine A");
        assert_eq!(one_b, one_a, "encrypt_block");
        a.decrypt_block(&mut one_a);
        b.decrypt_block(&mut one_b);
        assert_eq!(one_a, plaintext[i], "decrypt_block, engine A");
        assert_eq!(one_b, one_a, "decrypt_block");
    }
}

#[test]
fn engines_agree_for_aes128_on_random_keys_and_blocks() {
    let mut rng = DefaultRNG::default();
    for _ in 0..200 {
        agree::<
            16,
            AESInternal<AES128Params, Bitsliced<AES128Params>>,
            AESInternal<AES128Params, Arm<AES128Params>>,
        >(&mut rng);
    }
}

#[test]
fn engines_agree_for_aes192_on_random_keys_and_blocks() {
    let mut rng = DefaultRNG::default();
    for _ in 0..200 {
        agree::<
            24,
            AESInternal<AES192Params, Bitsliced<AES192Params>>,
            AESInternal<AES192Params, Arm<AES192Params>>,
        >(&mut rng);
    }
}

#[test]
fn engines_agree_for_aes256_on_random_keys_and_blocks() {
    let mut rng = DefaultRNG::default();
    for _ in 0..200 {
        agree::<
            32,
            AESInternal<AES256Params, Bitsliced<AES256Params>>,
            AESInternal<AES256Params, Arm<AES256Params>>,
        >(&mut rng);
    }
}

/// On this target the default engine is `Arm`: the aliases are the `Arm` instantiations, which
/// the compiler checks here, and they carry both schedules, which the sizes check.
#[test]
fn the_default_engine_on_this_target_is_arm() {
    fn is_arm_128(_: &AESInternal<AES128Params, Arm<AES128Params>>) {}
    fn is_arm_192(_: &AESInternal<AES192Params, Arm<AES192Params>>) {}
    fn is_arm_256(_: &AESInternal<AES256Params, Arm<AES256Params>>) {}
    let mut rng = DefaultRNG::default();
    is_arm_128(&AES128Internal::new(&random_key::<16>(&mut rng)).unwrap());
    is_arm_192(&AES192Internal::new(&random_key::<24>(&mut rng)).unwrap());
    is_arm_256(&AES256Internal::new(&random_key::<32>(&mut rng)).unwrap());
    assert_eq!(size_of::<AES128Internal>(), 2 * 11 * 16);
    assert_eq!(size_of::<AES192Internal>(), 2 * 13 * 16);
    assert_eq!(size_of::<AES256Internal>(), 2 * 15 * 16);
    assert_eq!(size_of::<AESInternal<AES128Params, Bitsliced<AES128Params>>>(), 44 * 4);
}
