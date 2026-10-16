//! Known-answer tests against Project Wycheproof's `testvectors_v1/aes_cbc_pkcs5_test.json`.
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the test prints a warning and passes, matching the convention used by the other vector
//! suites in this crate.
//!
//! # PKCS #5 is PKCS #7 at a 16-byte block
//!
//! The file's "PKCS #5" is the padding of RFC 5652 Sec 6.3 (`k - (lth mod k)` octets of value
//! `k - (lth mod k)`), which the cipher crate provides as [`PKCS7`]; the two names differ only in
//! that PKCS #5 was written for 8-byte blocks. So these vectors drive the padded aliases
//! `AES_CBC_128<_, PKCS7>` and friends, i.e. CBC through the `PaddedBlockCipherEncryptor` /
//! `PaddedBlockCipherDecryptor` adapters, where `cbc_bc-test-data.rs` and `sp800_38a_cbc_tests.rs`
//! drive the unpadded [`Cbc`](bouncycastle_cipher::modes::Cbc) underneath them.
//!
//! # Why this set is worth having alongside the ACVP one
//!
//! Two thirds of the file is `result: "invalid"`: ciphertexts of a message padded with zeros, with
//! `0xff`, with the wrong count, with a count of 0 or above 16, and so on (`BadPadding`, 141
//! cases), plus an empty ciphertext (`NoPadding`, 3 cases). The ACVP set has no padding at all,
//! so this is the only external check that [`PKCS7::unpad`] rejects every malformed block rather
//! than accepting an alternative padding, and that the adapter refuses a ciphertext too short to
//! carry one. See the file's own `"notes"` object for what each `flags` entry is checking.
//!
//! The IV is supplied through a `FixedSeedRNG`, as in `cbc_bc-test-data.rs`, and the returned IV is
//! asserted to be the vector's.

use bouncycastle_aes::{AES_CBC_128, AES_CBC_192, AES_CBC_256};
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{PaddingError, SymmetricCipherError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};

const BLOCK_LEN: usize = 16;

/// Wraps the vector's raw key bytes, promoting them if `KeyMaterial`'s entropy heuristic declined
/// to call them a cipher key. Same helper as the other vector suites in this crate.
fn cipher_key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
    assert_eq!(bytes.len(), N, "key length should match the parameter set");
    let mut key = KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("wycheproof key bytes fit the buffer");

    if key.key_type() != KeyType::SymmetricCipherKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(N))
        })
        .expect("promoting a wycheproof test key");
    }
    key
}

/// What an invalid case must fail with, from its `flags`.
///
/// `BadPadding` is a well-formed ciphertext whose final block does not unpad, so the adapter
/// surfaces [`PKCS7::unpad`]'s single undifferentiated [`PaddingError::InvalidPadding`].
/// `NoPadding` is an empty ciphertext: there is no final block to unpad at all, which the adapter
/// reports as [`SymmetricCipherError::DecryptionFailed`] before any padding is looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Valid,
    BadPadding,
    NoFinalBlock,
}

/// Runs one case through the padded `AES_CBC_*<_, PKCS7>` pair at one key length.
///
/// For a valid case, `msg` must encrypt to exactly `expected_ct` under the vector's IV, and
/// `expected_ct` must decrypt back to `msg`. For an invalid case only the decrypt direction is
/// checked -- re-encrypting `msg` with correct padding has no reason to reproduce a deliberately
/// mis-padded `ct` -- and it must fail with the variant the case's flags predict.
fn run_case<E, D, const KEY_LEN: usize>(
    tc_id: u64,
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    msg: &[u8],
    expected_ct: &[u8],
    expected: Expected,
) where
    E: SymmetricCipherEncryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
    D: SymmetricCipherDecryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    let key = cipher_key::<KEY_LEN>(key_bytes);

    if expected == Expected::Valid {
        let mut ct = vec![0u8; E::encrypt_out_len(msg.len())];
        let (got_iv, written) =
            E::encrypt_rng_out(&key, &mut FixedSeedRNG::<BLOCK_LEN>::new(iv), msg, &mut ct)
                .unwrap_or_else(|e| panic!("tcId {tc_id}: valid case failed to encrypt: {e:?}"));
        assert_eq!(got_iv, iv, "tcId {tc_id}: the seeded RNG must reproduce the vector's IV");
        ct.truncate(written);
        assert_eq!(ct, expected_ct, "tcId {tc_id}: ciphertext mismatch");
    }

    let mut plaintext = vec![0u8; D::decrypt_out_len(expected_ct.len())];
    let outcome = D::decrypt_out(&key, &iv, expected_ct, &mut plaintext);
    match (expected, outcome) {
        (Expected::Valid, Ok(n)) => {
            plaintext.truncate(n);
            assert_eq!(plaintext, msg, "tcId {tc_id}: decrypted plaintext mismatch");
        }
        (Expected::BadPadding, Err(SymmetricCipherError::PaddingError(e))) => {
            assert_eq!(
                e,
                PaddingError::InvalidPadding,
                "tcId {tc_id}: bad padding must be refused"
            );
        }
        (Expected::NoFinalBlock, Err(SymmetricCipherError::DecryptionFailed)) => {}
        (expected, outcome) => {
            panic!("tcId {tc_id}: expected {expected:?}, got {outcome:?}")
        }
    }
}

/// Dispatches on the key length to the matching `AES_CBC_*` alias pair.
fn dispatch(
    tc_id: u64,
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    msg: &[u8],
    expected_ct: &[u8],
    expected: Expected,
) {
    match key_bytes.len() {
        16 => run_case::<AES_CBC_128<Encrypting, PKCS7>, AES_CBC_128<Decrypting, PKCS7>, 16>(
            tc_id, key_bytes, iv, msg, expected_ct, expected,
        ),
        24 => run_case::<AES_CBC_192<Encrypting, PKCS7>, AES_CBC_192<Decrypting, PKCS7>, 24>(
            tc_id, key_bytes, iv, msg, expected_ct, expected,
        ),
        32 => run_case::<AES_CBC_256<Encrypting, PKCS7>, AES_CBC_256<Decrypting, PKCS7>, 32>(
            tc_id, key_bytes, iv, msg, expected_ct, expected,
        ),
        other => panic!("tcId {tc_id}: AES keys are 16, 24 or 32 bytes, got {other}"),
    }
}

#[test]
fn wycheproof_aes_cbc_pkcs7_known_answer_tests() {
    let Some(doc) = wycheproof_json("aes_cbc_pkcs5_test.json") else {
        return;
    };

    assert_eq!(
        doc.get("algorithm").and_then(Value::as_str),
        Some("AES-CBC-PKCS5"),
        "this is the AES-CBC-PKCS5 vector file"
    );

    let groups = doc.get("testGroups").and_then(Value::as_array).expect("testGroups");

    let mut valid_count = 0usize;
    let mut bad_padding_count = 0usize;
    let mut no_final_block_count = 0usize;

    for group in groups {
        let iv_size_bits = group.get("ivSize").and_then(Value::as_u64).expect("ivSize");
        let key_size_bits = group.get("keySize").and_then(Value::as_u64).expect("keySize");
        assert_eq!(iv_size_bits as usize, 8 * BLOCK_LEN, "CBC's IV is one block");
        assert_eq!(key_size_bits % 8, 0, "keySize must be a whole number of octets");

        let tests = group.get("tests").and_then(Value::as_array).expect("tests");

        for test in tests {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let key_bytes = hex_field(test, "key", tc_id);
            let iv: [u8; BLOCK_LEN] = hex_field(test, "iv", tc_id)
                .try_into()
                .unwrap_or_else(|_| panic!("tcId {tc_id}: the IV must be one block"));
            let msg = hex_field(test, "msg", tc_id);
            let ct = hex_field(test, "ct", tc_id);
            let result = test.get("result").and_then(Value::as_str).expect("result");
            let flags: Vec<&str> = test
                .get("flags")
                .and_then(Value::as_array)
                .expect("flags")
                .iter()
                .map(|f| f.as_str().expect("flag"))
                .collect();

            // The flags say *how* an invalid case is invalid, and so which error it must produce.
            let expected = match result {
                "valid" => Expected::Valid,
                "invalid" if flags.contains(&"BadPadding") => Expected::BadPadding,
                "invalid" if flags.contains(&"NoPadding") => Expected::NoFinalBlock,
                other => panic!("tcId {tc_id}: unexpected result/flags {other} {flags:?}"),
            };

            dispatch(tc_id, &key_bytes, iv, &msg, &ct, expected);

            match expected {
                Expected::Valid => valid_count += 1,
                Expected::BadPadding => bad_padding_count += 1,
                Expected::NoFinalBlock => no_final_block_count += 1,
            }
        }
    }

    println!(
        "Wycheproof AES-CBC-PKCS5: {valid_count} valid, {bad_padding_count} bad-padding and \
         {no_final_block_count} empty-ciphertext cases run"
    );

    // Guards against a silently-vacuous run.
    assert!(valid_count > 0, "expected valid cases");
    assert!(bad_padding_count > 0, "expected bad-padding cases, which are the point of this set");
    assert!(no_final_block_count > 0, "expected the empty-ciphertext cases");
}
