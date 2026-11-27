//! Interoperability with bc-fips: the CBC-CS1, CBC-CS2 and CBC-CS3 vectors that bc-fips 2.1.3
//! (`FipsAES.CBCwithCS1`, `CBCwithCS2`, `CBCwithCS3`) generated under AES-128, AES-192 and
//! AES-256, in `bc-test-data`'s `crypto/aes_tdes_vectors/CBC/bc-fips/`, whose README gives the
//! generator, the provider and how to reproduce the file.
//!
//! The lengths are every one from 15 to 49 bytes -- a single block, and every partial last block
//! after one and after two whole blocks -- and 0, 1, 63, 64, 65, 100, 255, 256, 257, 1000 and
//! 4097. For each record and variant this checks that encryption gives bc-fips's ciphertext byte
//! for byte, through the one-shot and in 1-byte and 17-byte pieces, that bc-fips's ciphertext
//! decrypts to the plaintext, and that the `CTS` key gives the CS3 ciphertext, which the generator
//! checked to be what bc-fips's own CTS names (`AES/CTS/NoPadding`, `AES/CBC/CTSPadding`) give. The
//! lengths below one block, which bc-fips refuses, are refused here too, in both directions.
//!
//! These are vectors from one implementation, not NIST's; the ACVP suite beside this file has
//! those.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
use bouncycastle_core_test_framework::test_data_loaders::{Value, bc_test_data_json, hex_field};
use bouncycastle_symmetric::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_symmetric::modes::{CBC_CS_FINAL_LEN, CBC_CS1, CBC_CS2, CBC_CS3, CTS};

#[path = "aes_common/acvp_helpers.rs"]
mod acvp_helpers;
use acvp_helpers::cipher_key;

const BLOCK_LEN: usize = 16;
const FINAL_LEN: usize = CBC_CS_FINAL_LEN;

const TEST_DATA_DIR: &str = "crypto/aes_tdes_vectors/CBC/bc-fips";
const TEST_DATA_FILE: &str = "AES-CBC-CS-bc-fips-2.1.3.json";

fn stream_encrypt<K, const KEY_LEN: usize>(
    key: &K,
    iv: &[u8; BLOCK_LEN],
    pt: &[u8],
    chunk: usize,
) -> Vec<u8>
where
    K: SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
{
    let mut enc = key.create_encryptor_nonce(iv);
    let mut out = Vec::new();
    for piece in pt.chunks(chunk) {
        let mut buf = vec![0u8; enc.do_encrypt_out_len(piece.len())];
        enc.do_encrypt_out(piece, &mut buf).expect("streaming encryption");
        out.extend_from_slice(&buf);
    }
    let (last, last_len) = enc.do_encrypt_final().expect("a message of at least one block");
    out.extend_from_slice(&last[..last_len]);
    out
}

fn stream_decrypt<K, const KEY_LEN: usize>(
    key: &K,
    iv: &[u8; BLOCK_LEN],
    ct: &[u8],
    chunk: usize,
) -> Vec<u8>
where
    K: SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
{
    let mut dec = key.create_decryptor(iv);
    let mut out = Vec::new();
    for piece in ct.chunks(chunk) {
        let mut buf = vec![0u8; dec.do_decrypt_out_len(piece.len())];
        dec.do_decrypt_out(piece, &mut buf).expect("streaming decryption");
        out.extend_from_slice(&buf);
    }
    let (last, last_len) = dec.do_decrypt_final().expect("a ciphertext of at least one block");
    out.extend_from_slice(&last[..last_len]);
    out
}

/// bc-fips's ciphertext, `ct`, of `pt` under one key type: encrypting gives it, through the one-shot
/// and streamed, and it decrypts back to `pt`, both ways.
fn agrees<K, const KEY_LEN: usize>(key: &K, iv: &[u8; BLOCK_LEN], pt: &[u8], ct: &[u8], what: &str)
where
    K: SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
{
    assert_eq!(key.encrypt_nonce(iv, pt).expect("encryption"), ct, "{what}: encrypt_nonce");
    assert_eq!(key.decrypt(iv, ct).expect("decryption"), pt, "{what}: decrypt");
    for chunk in [1, 17] {
        assert_eq!(
            stream_encrypt(key, iv, pt, chunk),
            ct,
            "{what}: encrypted in {chunk}-byte pieces"
        );
        assert_eq!(
            stream_decrypt(key, iv, ct, chunk),
            pt,
            "{what}: decrypted in {chunk}-byte pieces"
        );
    }
}

/// A message, or a ciphertext, that bc-fips refuses as shorter than a block: refused here too.
fn refuses<K, const KEY_LEN: usize>(key: &K, iv: &[u8; BLOCK_LEN], short: &[u8], what: &str)
where
    K: SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
{
    assert!(
        matches!(key.encrypt_nonce(iv, short), Err(SymmetricCipherError::InvalidInputLength(_))),
        "{what}: a {}-byte message must be refused",
        short.len()
    );
    assert!(
        matches!(key.decrypt(iv, short), Err(SymmetricCipherError::InvalidInputLength(_))),
        "{what}: a {}-byte ciphertext must be refused",
        short.len()
    );
}

/// One record, under the three variants and `CTS`, at one key length.
fn check_record<K1, K2, K3, KC, const KEY_LEN: usize>(record: &Value, tc_id: u64)
where
    K1: FromKeyMaterial<KEY_LEN>
        + SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
    K2: FromKeyMaterial<KEY_LEN>
        + SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
    K3: FromKeyMaterial<KEY_LEN>
        + SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
    KC: FromKeyMaterial<KEY_LEN>
        + SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
{
    let material = cipher_key::<KEY_LEN>(&hex_field(record, "key", tc_id));
    let iv: [u8; BLOCK_LEN] = hex_field(record, "iv", tc_id).try_into().expect("a 16-byte IV");
    let pt = hex_field(record, "pt", tc_id);
    let len = record.get("len").and_then(Value::as_u64).expect("len") as usize;
    assert_eq!(pt.len(), len, "tcId {tc_id}: len");

    let cs1 = K1::from_key_material(&material).expect("a key");
    let cs2 = K2::from_key_material(&material).expect("a key");
    let cs3 = K3::from_key_material(&material).expect("a key");
    let cts = KC::from_key_material(&material).expect("a key");

    if record.get("refused").and_then(Value::as_bool) == Some(true) {
        assert!(len < BLOCK_LEN, "tcId {tc_id}: only a length below one block is refused");
        refuses(&cs1, &iv, &pt, "CS1");
        refuses(&cs2, &iv, &pt, "CS2");
        refuses(&cs3, &iv, &pt, "CS3");
        refuses(&cts, &iv, &pt, "CTS");
        return;
    }
    let what = |v: &str| format!("tcId {tc_id}: AES-{} {v}, {len} bytes", KEY_LEN * 8);
    agrees(&cs1, &iv, &pt, &hex_field(record, "cs1", tc_id), &what("CBC-CS1"));
    agrees(&cs2, &iv, &pt, &hex_field(record, "cs2", tc_id), &what("CBC-CS2"));
    agrees(&cs3, &iv, &pt, &hex_field(record, "cs3", tc_id), &what("CBC-CS3"));
    agrees(&cts, &iv, &pt, &hex_field(record, "cs3", tc_id), &what("CTS"));
}

#[test]
fn bc_fips_cbc_cs_interop() {
    let Some(file) = bc_test_data_json(TEST_DATA_DIR, TEST_DATA_FILE) else {
        return;
    };
    let groups = file.get("testGroups").and_then(Value::as_array).expect("testGroups");
    let (mut checked, mut refused) = (0usize, 0usize);
    let mut key_lens = Vec::new();
    for group in groups {
        let key_len = group.get("keyLen").and_then(Value::as_u64).expect("keyLen");
        key_lens.push(key_len);
        for record in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = record.get("tcId").and_then(Value::as_u64).expect("tcId");
            match key_len {
                128 => check_record::<
                    AES128Key<CBC_CS1>,
                    AES128Key<CBC_CS2>,
                    AES128Key<CBC_CS3>,
                    AES128Key<CTS>,
                    16,
                >(record, tc_id),
                192 => check_record::<
                    AES192Key<CBC_CS1>,
                    AES192Key<CBC_CS2>,
                    AES192Key<CBC_CS3>,
                    AES192Key<CTS>,
                    24,
                >(record, tc_id),
                256 => check_record::<
                    AES256Key<CBC_CS1>,
                    AES256Key<CBC_CS2>,
                    AES256Key<CBC_CS3>,
                    AES256Key<CTS>,
                    32,
                >(record, tc_id),
                other => panic!("unexpected keyLen {other}"),
            }
            if record.get("refused").is_some() {
                refused += 1;
            } else {
                checked += 1;
            }
        }
    }
    println!(
        "bc-fips CBC-CS interop: {checked} records in all three variants and CTS, {refused} refused lengths"
    );
    // Guard against a silently empty or partial run.
    assert_eq!(key_lens, [128, 192, 256], "all three key lengths");
    assert_eq!((checked, refused), (129, 9), "the whole file");
}
