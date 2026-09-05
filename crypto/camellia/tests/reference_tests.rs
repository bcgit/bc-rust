//! Cross-check of the constant-time engine against a transcription of BC Java's
//! `CamelliaLightEngine` (`tests/common/mod.rs`), on many keys and blocks of every length, in
//! every lane, in both directions.
//!
//! The known-answer files pin published values. This file pins *agreement with the source
//! implementation* over thousands of inputs, which is what catches a circuit, mask or schedule
//! error that happens not to be exercised by the published examples -- and the reference is
//! organised quite differently (32-bit quarters, direction-dependent subkey layout, table
//! S-boxes), so agreement is not tautological.

mod common;

use bouncycastle_camellia::{Block, Camellia_128, Camellia_192, Camellia_256, LANES};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::ElectronicCodeBook;

fn engine<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, 16>>(key: &[u8; KEY_LEN]) -> P {
    <P as ElectronicCodeBook<KEY_LEN, 16>>::new(
        &KeyMaterial::<KEY_LEN>::from_bytes_as_type(key, KeyType::SymmetricCipherKey)
            .expect("a valid symmetric cipher key"),
    )
    .expect("a valid key")
}

/// The reference itself reproduces RFC 3713 Appendix A, so it can be trusted to judge.
#[test]
fn reference_sanity() {
    let pt: Block = common::bytes("0123456789abcdeffedcba9876543210");
    for (key, ct) in [
        (
            &common::bytes::<32>(
                "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
            )[..16],
            "67673138549669730857065648eabe43",
        ),
        (
            &common::bytes::<32>(
                "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
            )[..24],
            "b4993401b3e996f84ee5cee7d79b09b9",
        ),
        (
            &common::bytes::<32>(
                "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
            )[..],
            "9acc237dff16d76c20ef7c919e3a7509",
        ),
    ] {
        let mut block = pt;
        common::encrypt_block(key, &mut block);
        assert_eq!(block, common::bytes::<16>(ct), "{}-byte key", key.len());
        common::decrypt_block(key, &mut block);
        assert_eq!(block, pt);
    }
}

fn single_block_agrees<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, 16>>(seed: u32) {
    let mut seed = seed;
    for _ in 0..256 {
        let key: [u8; KEY_LEN] = common::pseudo_random(&mut seed);
        let perm: P = engine(&key);
        for _ in 0..8 {
            let block: Block = common::pseudo_random(&mut seed);

            let mut ours = block;
            let mut theirs = block;
            perm.encrypt_block(&mut ours);
            common::encrypt_block(&key, &mut theirs);
            assert_eq!(ours, theirs, "encrypt, key {key:02x?}, block {block:02x?}");

            let mut ours = block;
            let mut theirs = block;
            perm.decrypt_block(&mut ours);
            common::decrypt_block(&key, &mut theirs);
            assert_eq!(ours, theirs, "decrypt, key {key:02x?}, block {block:02x?}");
        }
    }
}

fn two_block_override_matches<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, 16>>(seed: u32) {
    let mut seed = seed;
    for _ in 0..64 {
        let key: [u8; KEY_LEN] = common::pseudo_random(&mut seed);
        let perm: P = engine(&key);
        let a: Block = common::pseudo_random(&mut seed);
        let b: Block = common::pseudo_random(&mut seed);

        let mut singly = [a, b];
        perm.encrypt_block(&mut singly[0]);
        perm.encrypt_block(&mut singly[1]);
        let mut paired = [a, b];
        perm.encrypt_2blocks(&mut paired);
        assert_eq!(paired, singly);
        let mut theirs = [a, b];
        common::encrypt_block(&key, &mut theirs[0]);
        common::encrypt_block(&key, &mut theirs[1]);
        assert_eq!(paired, theirs);

        perm.decrypt_2blocks(&mut paired);
        assert_eq!(paired, [a, b]);
    }
}

/// Single-block API against the reference: 256 keys of each length, 8 blocks each, both directions.
#[test]
fn single_block_agrees_with_the_reference() {
    single_block_agrees::<16, Camellia_128>(0x5EED_0001);
    single_block_agrees::<24, Camellia_192>(0x5EED_0002);
    single_block_agrees::<32, Camellia_256>(0x5EED_0003);
}

/// The four-lane API -- the natural unit -- against the reference, every lane, both directions.
#[test]
fn four_lanes_agree_with_the_reference() {
    fn run<const KEY_LEN: usize, P: bouncycastle_camellia::CamelliaParams>(
        mut seed: u32,
        new: impl Fn(&[u8; KEY_LEN]) -> bouncycastle_camellia::Camellia<P>,
    ) {
        for _ in 0..128 {
            let key: [u8; KEY_LEN] = common::pseudo_random(&mut seed);
            let perm = new(&key);
            let blocks: [Block; LANES] = core::array::from_fn(|_| common::pseudo_random(&mut seed));

            let mut ours = blocks;
            perm.encrypt_4blocks(&mut ours);
            for (lane, (o, b)) in ours.iter().zip(blocks.iter()).enumerate() {
                let mut theirs = *b;
                common::encrypt_block(&key, &mut theirs);
                assert_eq!(*o, theirs, "encrypt lane {lane}");
            }
            perm.decrypt_4blocks(&mut ours);
            assert_eq!(ours, blocks, "decrypt_4blocks must invert encrypt_4blocks");

            let mut ours = blocks;
            perm.decrypt_4blocks(&mut ours);
            for (lane, (o, b)) in ours.iter().zip(blocks.iter()).enumerate() {
                let mut theirs = *b;
                common::decrypt_block(&key, &mut theirs);
                assert_eq!(*o, theirs, "decrypt lane {lane}");
            }
        }
    }
    let km =
        |k: &[u8]| KeyMaterial::<16>::from_bytes_as_type(k, KeyType::SymmetricCipherKey).unwrap();
    run::<16, _>(0x5EED_0031, |k| Camellia_128::new(&km(k)).unwrap());
    let km =
        |k: &[u8]| KeyMaterial::<24>::from_bytes_as_type(k, KeyType::SymmetricCipherKey).unwrap();
    run::<24, _>(0x5EED_0032, |k| Camellia_192::new(&km(k)).unwrap());
    let km =
        |k: &[u8]| KeyMaterial::<32>::from_bytes_as_type(k, KeyType::SymmetricCipherKey).unwrap();
    run::<32, _>(0x5EED_0033, |k| Camellia_256::new(&km(k)).unwrap());
}

/// The two-block override against two single-block calls and the reference, in both slots.
#[test]
fn two_block_override_matches_two_single_calls() {
    two_block_override_matches::<16, Camellia_128>(0x5EED_0021);
    two_block_override_matches::<24, Camellia_192>(0x5EED_0022);
    two_block_override_matches::<32, Camellia_256>(0x5EED_0023);
}
