//! Cross-check of the constant-time engine against a table-driven transcription of BC Java's
//! `SM4Engine` (`tests/common/mod.rs`), on many keys and blocks, in every lane, in both
//! directions.
//!
//! The known-answer files pin a handful of published values. This file pins *agreement with the
//! source implementation* over thousands of inputs, which is what catches a circuit or layout
//! error that happens not to be exercised by the published examples.

mod common;

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_sm4::{Block, LANES, SM4};

fn engine(key: &[u8; 16]) -> SM4 {
    SM4::new(
        &KeyMaterial::<16>::from_bytes_as_type(key, KeyType::SymmetricCipherKey)
            .expect("a valid symmetric cipher key"),
    )
    .expect("a valid SM4 key")
}

/// The reference itself reproduces GB/T 32907-2016 Example 1, so it can be trusted to judge.
#[test]
fn reference_sanity() {
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let mut block = key;
    common::encrypt_block(&key, &mut block);
    assert_eq!(
        block,
        [
            0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E,
            0x42, 0x46
        ]
    );
    common::decrypt_block(&key, &mut block);
    assert_eq!(block, key);
}

/// Single-block API against the reference: 256 keys, 8 blocks each, both directions.
#[test]
fn single_block_agrees_with_the_reference() {
    let mut seed = 0x5EED_0001;
    for _ in 0..256 {
        let key: [u8; 16] = common::pseudo_random(&mut seed);
        let sm4 = engine(&key);
        for _ in 0..8 {
            let block: Block = common::pseudo_random(&mut seed);

            let mut ours = block;
            let mut theirs = block;
            sm4.encrypt_block(&mut ours);
            common::encrypt_block(&key, &mut theirs);
            assert_eq!(ours, theirs, "encrypt, key {key:02x?}, block {block:02x?}");

            let mut ours = block;
            let mut theirs = block;
            sm4.decrypt_block(&mut ours);
            common::decrypt_block(&key, &mut theirs);
            assert_eq!(ours, theirs, "decrypt, key {key:02x?}, block {block:02x?}");
        }
    }
}

/// Four-lane API -- the natural unit -- against the reference: every lane must carry its own
/// block, undisturbed by the others.
#[test]
fn four_lanes_agree_with_the_reference() {
    let mut seed = 0x5EED_0002;
    for _ in 0..128 {
        let key: [u8; 16] = common::pseudo_random(&mut seed);
        let sm4 = engine(&key);
        let blocks: [Block; LANES] = core::array::from_fn(|_| common::pseudo_random(&mut seed));

        let mut ours = blocks;
        sm4.encrypt_4blocks(&mut ours);
        for (lane, (o, b)) in ours.iter().zip(blocks.iter()).enumerate() {
            let mut theirs = *b;
            common::encrypt_block(&key, &mut theirs);
            assert_eq!(*o, theirs, "encrypt lane {lane}");
        }

        sm4.decrypt_4blocks(&mut ours);
        assert_eq!(ours, blocks, "decrypt_4blocks must invert encrypt_4blocks");

        let mut ours = blocks;
        sm4.decrypt_4blocks(&mut ours);
        for (lane, (o, b)) in ours.iter().zip(blocks.iter()).enumerate() {
            let mut theirs = *b;
            common::decrypt_block(&key, &mut theirs);
            assert_eq!(*o, theirs, "decrypt lane {lane}");
        }
    }
}

/// The two-block override against two single-block calls, in both slots.
#[test]
fn two_block_override_matches_two_single_calls() {
    let mut seed = 0x5EED_0003;
    for _ in 0..64 {
        let key: [u8; 16] = common::pseudo_random(&mut seed);
        let sm4 = engine(&key);
        let a: Block = common::pseudo_random(&mut seed);
        let b: Block = common::pseudo_random(&mut seed);

        let mut singly = [a, b];
        sm4.encrypt_block(&mut singly[0]);
        sm4.encrypt_block(&mut singly[1]);
        let mut paired = [a, b];
        sm4.encrypt_2blocks(&mut paired);
        assert_eq!(paired, singly);

        sm4.decrypt_2blocks(&mut paired);
        assert_eq!(paired, [a, b]);
    }
}
