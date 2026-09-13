//! Known-answer tests from NIST SP 800-38A Appendix F.1, "ECB Example Vectors".
//!
//! These are the only NIST-published known-answer vectors for AES-192 and AES-256 that live in a
//! specification document rather than a separate vector file -- FIPS 197 Appendix B only covers
//! AES-128, and FIPS 197 (Update 1) removed the Appendix C example vectors in favour of a pointer
//! to the CSRC website. `acvp_tests.rs` covers far more cases, but only when the `bc-test-data`
//! repository is present, so these vectors are the always-available known-answer floor.
//!
//! ECB applies the raw permutation to each block independently, so an ECB example vector *is* a
//! block-permutation test vector. (That is the only reason ECB appears in this crate; see the
//! crate docs on why you must not use it to encrypt anything.)
//!
//! The keys are the same three keys as FIPS 197 Appendix A.1, A.2 and A.3, so these vectors also
//! pin each key expansion against a NIST-published answer, in both directions.
//!
//! Transcribed from the published SP 800-38A PDF, sections F.1.1 through F.1.6.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256, BLOCK_LEN};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_hex as hex;

/// The four plaintext blocks shared by every F.1 subsection.
const PLAINTEXTS: [&str; 4] = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
];

/// F.1.1 / F.1.2 key.
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// F.1.1 ECB-AES128.Encrypt output blocks.
const CIPHERTEXTS_128: [&str; 4] = [
    "3ad77bb40d7a3660a89ecaf32466ef97",
    "f5d3d58503b9699de785895a96fdbaaf",
    "43b1cd7f598ece23881b00e3ed030688",
    "7b0c785e27e8ad3f8223207104725dd4",
];

/// F.1.3 / F.1.4 key.
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
/// F.1.3 ECB-AES192.Encrypt output blocks.
const CIPHERTEXTS_192: [&str; 4] = [
    "bd334f1d6e45f25ff712a214571fa5cc",
    "974104846d0ad3ad7734ecb3ecee4eef",
    "ef7afd2270e2e60adce0ba2face6444e",
    "9a4b41ba738d6c72fb16691603c18e0e",
];

/// F.1.5 / F.1.6 key.
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
/// F.1.5 ECB-AES256.Encrypt output blocks.
const CIPHERTEXTS_256: [&str; 4] = [
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
    "591ccb10d410ed26dc5ba74a31362870",
    "b6ed21b99ca6f4f9f153e7b1beafed1d",
    "23304b7a39f9f3ff067d8d8f9e24ecc7",
];

fn block(hex_str: &str) -> [u8; BLOCK_LEN] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("16 bytes")
}

fn key_material<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    let bytes = hex::decode(hex_str).expect("valid hex");
    assert_eq!(bytes.len(), N, "key length");
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

// ---- F.1.1 / F.1.2  ECB-AES128 -------------------------------------------------------------

#[test]
fn f_1_1_ecb_aes128_encrypt() {
    let aes = Aes128::new(&key_material::<16>(KEY_128)).unwrap();
    for (i, (pt, ct)) in PLAINTEXTS.iter().zip(CIPHERTEXTS_128.iter()).enumerate() {
        let mut b = block(pt);
        aes.encrypt_block(&mut b);
        assert_eq!(b, block(ct), "F.1.1 block #{}", i + 1);
    }
}

#[test]
fn f_1_2_ecb_aes128_decrypt() {
    let aes = Aes128::new(&key_material::<16>(KEY_128)).unwrap();
    for (i, (pt, ct)) in PLAINTEXTS.iter().zip(CIPHERTEXTS_128.iter()).enumerate() {
        let mut b = block(ct);
        aes.decrypt_block(&mut b);
        assert_eq!(b, block(pt), "F.1.2 block #{}", i + 1);
    }
}

// ---- F.1.3 / F.1.4  ECB-AES192 -------------------------------------------------------------

#[test]
fn f_1_3_ecb_aes192_encrypt() {
    let aes = Aes192::new(&key_material::<24>(KEY_192)).unwrap();
    for (i, (pt, ct)) in PLAINTEXTS.iter().zip(CIPHERTEXTS_192.iter()).enumerate() {
        let mut b = block(pt);
        aes.encrypt_block(&mut b);
        assert_eq!(b, block(ct), "F.1.3 block #{}", i + 1);
    }
}

#[test]
fn f_1_4_ecb_aes192_decrypt() {
    let aes = Aes192::new(&key_material::<24>(KEY_192)).unwrap();
    for (i, (pt, ct)) in PLAINTEXTS.iter().zip(CIPHERTEXTS_192.iter()).enumerate() {
        let mut b = block(ct);
        aes.decrypt_block(&mut b);
        assert_eq!(b, block(pt), "F.1.4 block #{}", i + 1);
    }
}

// ---- F.1.5 / F.1.6  ECB-AES256 -------------------------------------------------------------

#[test]
fn f_1_5_ecb_aes256_encrypt() {
    let aes = Aes256::new(&key_material::<32>(KEY_256)).unwrap();
    for (i, (pt, ct)) in PLAINTEXTS.iter().zip(CIPHERTEXTS_256.iter()).enumerate() {
        let mut b = block(pt);
        aes.encrypt_block(&mut b);
        assert_eq!(b, block(ct), "F.1.5 block #{}", i + 1);
    }
}

#[test]
fn f_1_6_ecb_aes256_decrypt() {
    let aes = Aes256::new(&key_material::<32>(KEY_256)).unwrap();
    for (i, (pt, ct)) in PLAINTEXTS.iter().zip(CIPHERTEXTS_256.iter()).enumerate() {
        let mut b = block(ct);
        aes.decrypt_block(&mut b);
        assert_eq!(b, block(pt), "F.1.6 block #{}", i + 1);
    }
}

// ---- the two-block path against the same vectors -------------------------------------------

/// The two-block entry points must produce exactly the single-block answers.
///
/// This is the test that pins the interleave: a mistake in which bit of each pair belongs to
/// which block shows up here and nowhere in the single-block tests, because a single-block call
/// puts the same data in both halves.
#[test]
fn two_block_path_matches_the_f_1_vectors() {
    let aes = Aes128::new(&key_material::<16>(KEY_128)).unwrap();

    // Blocks 1 and 2 as a pair, then 3 and 4.
    for chunk in 0..2 {
        let (i, j) = (chunk * 2, chunk * 2 + 1);
        let mut pair = [block(PLAINTEXTS[i]), block(PLAINTEXTS[j])];
        aes.encrypt_blocks2(&mut pair);
        assert_eq!(pair[0], block(CIPHERTEXTS_128[i]), "pair {chunk} slot 0");
        assert_eq!(pair[1], block(CIPHERTEXTS_128[j]), "pair {chunk} slot 1");

        aes.decrypt_blocks2(&mut pair);
        assert_eq!(pair[0], block(PLAINTEXTS[i]));
        assert_eq!(pair[1], block(PLAINTEXTS[j]));
    }
}

/// Swapping the two slots must swap the two results, and nothing else.
#[test]
fn two_block_path_is_slot_symmetric() {
    let aes = Aes256::new(&key_material::<32>(KEY_256)).unwrap();

    let mut forward = [block(PLAINTEXTS[0]), block(PLAINTEXTS[1])];
    let mut reversed = [block(PLAINTEXTS[1]), block(PLAINTEXTS[0])];
    aes.encrypt_blocks2(&mut forward);
    aes.encrypt_blocks2(&mut reversed);

    assert_eq!(forward[0], reversed[1]);
    assert_eq!(forward[1], reversed[0]);
    assert_eq!(forward[0], block(CIPHERTEXTS_256[0]));
    assert_eq!(forward[1], block(CIPHERTEXTS_256[1]));
}
