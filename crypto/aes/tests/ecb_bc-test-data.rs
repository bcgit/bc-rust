//! Known-answer tests against the NIST ACVP `ACVP-AES-ECB` vectors from the `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the tests print a warning and pass,
//! matching the convention used by the ML-KEM and ML-DSA test suites -- `cargo test` must stay
//! green for someone who has only cloned this repository.
//!
//! # Why ECB, and where the other ACVP AES files are used
//!
//! The vectors are driven through [`Ecb`] over the AES engines, which is the AES-ECB this crate
//! exposes under `hazmat`. See the crate docs on why you must never use ECB to encrypt data.
//!
//! `bc-test-data` ships sixteen ACVP AES vector sets, one per mode. This file deliberately
//! consumes only `ACVP-AES-ECB`. The others belong with whatever implements the mode:
//!
//! | Vector set | Consumed by |
//! |---|---|
//! | `ACVP-AES-ECB` | this file (the `Ecb` mode's structural tests are toy-driven, in `crypto/cipher/tests/modes/ecb_tests.rs`) |
//! | `ACVP-AES-CBC` | `cbc_bc-test-data.rs` |
//! | `ACVP-AES-CBC-CS1` / `-CS2` / `-CS3` | nothing yet (ciphertext stealing is unimplemented) |
//! | `ACVP-AES-CCM` | `ccm_bc-test-data.rs` |
//! | `ACVP-AES-CFB128` | `cfb_bc-test-data.rs` |
//! | `ACVP-AES-CFB8` | `cfb8_bc-test-data.rs` |
//! | `ACVP-AES-OFB` | nothing yet (OFB is unimplemented) |
//! | `ACVP-AES-CTR` | `ctr_bc-test-data.rs` |
//! | `ACVP-AES-GCM` / `-GMAC` | `gcm_bc-test-data.rs` / `gmac_bc-test-data.rs` |
//! | `ACVP-AES-KW` / `-KWP` | nothing yet (key wrap is unimplemented) |
//! | `ACVP-AES-FF1` / `-FF3-1` | nothing yet (format-preserving encryption is unimplemented) |
//!
//! So an unused vector set here means an unimplemented mode, not an untested one. Adding a mode
//! should include wiring up its file.
//!
//! The response file records `key`, `pt` and `ct` for every test case regardless of the group's
//! declared direction, so each case is checked in **both** directions: encrypting `pt` must give
//! `ct` and decrypting `ct` must give `pt`. That is strictly stronger than honouring the declared
//! direction, and it means the group metadata in the request file is not needed.
//!
//! # Coverage and one gap
//!
//! The AFT (Algorithm Functional Test) groups cover all three key lengths in both directions,
//! including cases whose plaintext spans several blocks. The six MCT (Monte Carlo Test) groups
//! are **not** implemented: their expected output is a `resultsArray` produced by a chained
//! key/plaintext update rule defined in the ACVP AES specification rather than in FIPS 197, and
//! implementing it from anything other than that specification would be guesswork. The test
//! reports how many it skipped so the gap is visible rather than silent.

use bouncycastle_aes::AES_BLOCK_LEN;
use bouncycastle_aes::hazmat::{
    AES_ECB_128_Key, AES_ECB_192_Key, AES_ECB_256_Key, AES128Internal, AES192Internal,
    AES256Internal,
};
use bouncycastle_cipher::modes::hazmat::Ecb;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, SymmetricCipherKey};
use bouncycastle_core_test_framework::test_data_loaders::{Value, bc_test_data_json};
use bouncycastle_hex as hex;

const TEST_DATA_DIR: &str = "crypto/aes_tdes_vectors/AES";
const RESPONSE_FILE: &str = "ACVP-AES-ECB.4014527.rsp.json";

/// Builds a `KeyMaterial` from raw ACVP key bytes, including the all-zero keys.
///
/// The ACVP set deliberately includes an all-zero key (the GFSbox-style groups vary only the
/// plaintext under a zero key). `KeyMaterial` tags an all-zero buffer as [`KeyType::Zeroized`]
/// and will not promote it outside a [`do_hazardous_operations`] closure, which is the right
/// default, since an all-zero key normally means a broken RNG. Here the zero key is deliberate and
/// comes from NIST, so this opts in explicitly rather than the library weakening its guard.
fn cipher_key<K: SymmetricCipherKey<N>, const N: usize>(bytes: &[u8]) -> K {
    assert_eq!(bytes.len(), N, "key length should match the parameter set");
    let mut key = KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("ACVP key bytes fit the buffer");

    if key.key_type() != KeyType::SymmetricCipherKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(N))
        })
        .expect("promoting a NIST all-zero test key");
    }

    K::from_keymaterial(key).expect("a valid key")
}

/// How the blocks are handed to the mode: one at a time, or in pairs through the two-block entry
/// point, which must agree with the single-block path on real vectors too.
#[derive(Clone, Copy)]
enum Grouping {
    Single,
    Pairs,
}

/// Runs `data` through [`Ecb`] over `P` in the given direction, grouped as asked.
fn run_case<P, K, const KEY_LEN: usize>(
    key_bytes: &[u8],
    data: &[u8],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<u8>
where
    K: SymmetricCipherKey<KEY_LEN>,
    P: ElectronicCodeBook<K, KEY_LEN, AES_BLOCK_LEN>,
{
    assert_eq!(data.len() % AES_BLOCK_LEN, 0, "ACVP ECB data must be block-aligned");
    let key = cipher_key::<K, KEY_LEN>(key_bytes);
    let mut blocks: Vec<[u8; AES_BLOCK_LEN]> = data.as_chunks::<AES_BLOCK_LEN>().0.to_vec();

    if encrypt {
        let (mut enc, _) = Ecb::<P, Encrypting, K, KEY_LEN, AES_BLOCK_LEN>::do_encrypt_init(&key)
            .expect("encrypt init");
        match grouping {
            Grouping::Single => {
                for block in blocks.iter_mut() {
                    enc.do_encrypt_inplace(block).unwrap();
                }
            }
            Grouping::Pairs => {
                let (pairs, tail) = blocks.as_chunks_mut::<2>();
                for pair in pairs {
                    enc.do_encrypt_blocks_inplace(pair).unwrap();
                }
                for block in tail {
                    enc.do_encrypt_inplace(block).unwrap();
                }
            }
        }
    } else {
        let mut dec = Ecb::<P, Decrypting, K, KEY_LEN, AES_BLOCK_LEN>::do_decrypt_init(&key, &[])
            .expect("decrypt init");
        match grouping {
            Grouping::Single => {
                for block in blocks.iter_mut() {
                    dec.do_decrypt_inplace(block).unwrap();
                }
            }
            Grouping::Pairs => {
                let (pairs, tail) = blocks.as_chunks_mut::<2>();
                for pair in pairs {
                    dec.do_decrypt_blocks_inplace(pair).unwrap();
                }
                for block in tail {
                    dec.do_decrypt_inplace(block).unwrap();
                }
            }
        }
    }

    blocks.concat()
}

/// Encrypts or decrypts `data` with AES-ECB, dispatching on the key length.
fn ecb(key: &[u8], data: &[u8], encrypt: bool, grouping: Grouping) -> Vec<u8> {
    match key.len() {
        16 => run_case::<AES128Internal, AES_ECB_128_Key, 16>(key, data, encrypt, grouping),
        24 => run_case::<AES192Internal, AES_ECB_192_Key, 24>(key, data, encrypt, grouping),
        32 => run_case::<AES256Internal, AES_ECB_256_Key, 32>(key, data, encrypt, grouping),
        other => panic!("ACVP AES vectors should only use 16, 24 or 32 byte keys, got {other}"),
    }
}

#[test]
fn acvp_aes_ecb_known_answer_tests() {
    let Some(parsed) = bc_test_data_json(TEST_DATA_DIR, RESPONSE_FILE) else { return };

    // The ACVP file is an array: element 0 is the version header, element 1 the vector set.
    let groups = parsed
        .get(1)
        .and_then(|set| set.get("testGroups"))
        .and_then(Value::as_array)
        .expect("testGroups array");

    let mut checked = 0usize;
    let mut skipped_mct = 0usize;
    let mut by_key_len = [0usize; 3]; // 128, 192, 256

    for group in groups {
        let tests = group.get("tests").and_then(Value::as_array).expect("tests array");
        for test in tests {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");

            // Monte Carlo groups carry a chained resultsArray instead of a single pt/ct pair.
            if test.get("resultsArray").is_some() {
                skipped_mct += 1;
                continue;
            }

            let get = |name: &str| -> Vec<u8> {
                let s = test
                    .get(name)
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {name}"));
                hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {name}"))
            };

            let key = get("key");
            let pt = get("pt");
            let ct = get("ct");

            assert_eq!(pt.len(), ct.len(), "tcId {tc_id}: pt and ct differ in length");

            assert_eq!(
                ecb(&key, &pt, true, Grouping::Single),
                ct,
                "tcId {tc_id}: AES-{} encrypt",
                key.len() * 8
            );
            assert_eq!(
                ecb(&key, &ct, false, Grouping::Single),
                pt,
                "tcId {tc_id}: AES-{} decrypt",
                key.len() * 8
            );

            // The two-block path must agree with the single-block path on real vectors too.
            assert_eq!(
                ecb(&key, &pt, true, Grouping::Pairs),
                ct,
                "tcId {tc_id}: AES-{} encrypt in pairs",
                key.len() * 8
            );
            assert_eq!(
                ecb(&key, &ct, false, Grouping::Pairs),
                pt,
                "tcId {tc_id}: AES-{} decrypt in pairs",
                key.len() * 8
            );

            by_key_len[match key.len() {
                16 => 0,
                24 => 1,
                _ => 2,
            }] += 1;
            checked += 1;
        }
    }

    println!(
        "ACVP AES-ECB: {checked} test cases checked in both directions \
         (AES-128: {}, AES-192: {}, AES-256: {}); {skipped_mct} MCT cases skipped",
        by_key_len[0], by_key_len[1], by_key_len[2]
    );

    // Guard against a silently-empty run: the published vector set has thousands of AFT cases
    // across all three key lengths.
    assert!(checked > 1000, "expected the full ACVP AFT set, only checked {checked}");
    assert!(by_key_len.iter().all(|&n| n > 0), "every key length should be covered");
}
