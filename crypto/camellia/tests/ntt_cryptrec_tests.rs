//! All 3840 known-answer vectors of NTT's CRYPTREC test-vector file `t_camellia.txt`, for all three
//! key lengths, in both directions, through the four-block and single-block paths.
//!
//! The data module `ntt_cryptrec_data.rs` describes the file and its provenance. Each key set is
//! the 128 single-bit plaintexts under one key, so the 128 ciphertexts go through
//! `encrypt_4blocks` as thirty-two batches of four (one four-lane pass each) and back through
//! `decrypt_4blocks`; the first
//! plaintext of every set is also run through the single-block methods. Between them the 30 keys
//! cover all-zero, all-one and patterned keys of every length, and the plaintexts cover every bit
//! position of the block, which is a good test of the byte-lane masks and the bit-plane layout.

mod common;
mod ntt_cryptrec_data;

use bouncycastle_camellia::{BLOCK_LEN, Camellia_128, Camellia_192, Camellia_256};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{ElectronicCodeBook, SecurityStrength};
use common::bytes;
use ntt_cryptrec_data::{CAMELLIA_128, CAMELLIA_192, CAMELLIA_256, KeySet};

/// `P No.i`: the block with only bit `128 - i` set (bit 0 least significant), `i` in `1..=128`.
fn plaintext(i: usize) -> [u8; BLOCK_LEN] {
    (1u128 << (128 - i)).to_be_bytes()
}

fn engine<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, 16>>(key: &str) -> P {
    let key_bytes: [u8; KEY_LEN] = bytes(key);
    let mut km =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
            .expect("a key");
    // `K No.001` is all zero, which `from_bytes_as_type` tags `Zeroized`; retag it as the CLI does.
    do_hazardous_operations(&mut km, |k| {
        k.set_key_type(KeyType::SymmetricCipherKey)?;
        k.set_security_strength(SecurityStrength::from_bytes(KEY_LEN))
    })
    .expect("retagging the key");
    P::new(&km).expect("a valid key")
}

fn check_key_set<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, 16>>(
    bits: usize,
    kno: usize,
    set: &KeySet,
) -> usize {
    let perm: P = engine::<KEY_LEN, P>(set.key);
    let expected: Vec<[u8; BLOCK_LEN]> = set.ciphertexts.iter().map(|c| bytes(c)).collect();
    let plaintexts: Vec<[u8; BLOCK_LEN]> = (1..=128).map(plaintext).collect();

    // Thirty-two batches of four, both directions.
    for (batch, (pts, cts)) in plaintexts.chunks(4).zip(expected.chunks(4)).enumerate() {
        let mut blocks: [[u8; BLOCK_LEN]; 4] = pts.try_into().unwrap();
        perm.encrypt_4blocks(&mut blocks);
        for (lane, (got, want)) in blocks.iter().zip(cts.iter()).enumerate() {
            assert_eq!(
                got,
                want,
                "{bits}-bit K No.{kno:03}, P No.{:03} (batch {batch}, slot {lane}): encrypt",
                batch * 4 + lane + 1
            );
        }
        perm.decrypt_4blocks(&mut blocks);
        assert_eq!(&blocks[..], pts, "{bits}-bit K No.{kno:03}, batch {batch}: decrypt_4blocks");
    }

    // The first vector of the set through the single-block methods too.
    let mut b = plaintexts[0];
    perm.encrypt_block(&mut b);
    assert_eq!(b, expected[0], "{bits}-bit K No.{kno:03}, P No.001: encrypt_block");
    perm.decrypt_block(&mut b);
    assert_eq!(b, plaintexts[0], "{bits}-bit K No.{kno:03}, C No.001: decrypt_block");

    expected.len()
}

#[test]
fn plaintexts_are_single_bits() {
    assert_eq!(plaintext(1), bytes("80000000000000000000000000000000"));
    assert_eq!(plaintext(2), bytes("40000000000000000000000000000000"));
    assert_eq!(plaintext(128), bytes("00000000000000000000000000000001"));
}

#[test]
fn camellia_128_all_ten_keys() {
    let mut n = 0;
    for (i, set) in CAMELLIA_128.iter().enumerate() {
        n += check_key_set::<16, Camellia_128>(128, i + 1, set);
    }
    assert_eq!(n, 1280);
}

#[test]
fn camellia_192_all_ten_keys() {
    let mut n = 0;
    for (i, set) in CAMELLIA_192.iter().enumerate() {
        n += check_key_set::<24, Camellia_192>(192, i + 1, set);
    }
    assert_eq!(n, 1280);
}

#[test]
fn camellia_256_all_ten_keys() {
    let mut n = 0;
    for (i, set) in CAMELLIA_256.iter().enumerate() {
        n += check_key_set::<32, Camellia_256>(256, i + 1, set);
    }
    assert_eq!(n, 1280);
}

/// The file's first vector is also BC Java's `CamelliaTest` vector 0 and NESSIE's; pin it by hand
/// so a regenerated data module cannot silently shift.
#[test]
fn first_vector_is_the_nessie_one() {
    assert_eq!(CAMELLIA_128[0].key, "00000000000000000000000000000000");
    assert_eq!(CAMELLIA_128[0].ciphertexts[0], "07923A39EB0A817D1C4D87BDB82D1F1C");
}
