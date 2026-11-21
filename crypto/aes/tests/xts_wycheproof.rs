//! Project Wycheproof's `aes_xts_test.json` through `XTS_AES_128` and `XTS_AES_256`. Requires the
//! Wycheproof repository at `../wycheproof`; absent, the test warns and passes.
//!
//! Every case is a valid encryption of a pseudorandom message of 16 to 136 bytes, which between
//! them cover each ciphertext-stealing tail length; each is checked in both directions. The file
//! gives the tweak as an `iv` of 1 to 16 bytes, which is the leading bytes of the 128-bit tweak
//! with the rest zero: the tweak value's little-endian encoding (IEEE 1619-2007 Sec 5.1) at the
//! width written, as the standard's Annex C pads a 64-bit sector number. OpenSSL reproduces every
//! case in the file under that reading. The 384-bit-key groups are XTS over AES-192, which
//! neither IEEE 1619 nor SP 800-38E defines; they are counted and skipped.

use bouncycastle_aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_cipher::modes::XTSKey;
use bouncycastle_core::hazmat::BlockPermutation;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};

/// Checks one case through `XTSKey<P, N>` under its `KEY_LEN`-byte key, in both directions.
fn check<P, const KEY_LEN: usize, const N: usize>(case: &Value, tc_id: u64)
where
    P: BlockPermutation<16>,
    XTSKey<P, N>: FromKeyMaterial<KEY_LEN>,
{
    let material = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
        &hex_field(case, "key", tc_id),
        KeyType::SymmetricCipherKey,
    )
    .unwrap();
    let key = XTSKey::<P, N>::from_key_material(&material)
        .unwrap_or_else(|e| panic!("tcId {tc_id}: the key is refused: {e:?}"));

    let iv = hex_field(case, "iv", tc_id);
    let mut tweak = [0u8; 16];
    tweak[..iv.len()].copy_from_slice(&iv);

    let msg: [u8; N] = hex_field(case, "msg", tc_id).try_into().unwrap();
    let ct: [u8; N] = hex_field(case, "ct", tc_id).try_into().unwrap();

    let mut data_unit = msg;
    key.encrypt_inplace(&tweak, &mut data_unit);
    assert_eq!(data_unit, ct, "tcId {tc_id}: encryption");
    key.decrypt_inplace(&tweak, &mut data_unit);
    assert_eq!(data_unit, msg, "tcId {tc_id}: decryption");
}

fn check_128<const N: usize>(case: &Value, tc_id: u64) {
    check::<AES128Internal, 32, N>(case, tc_id);
}

fn check_256<const N: usize>(case: &Value, tc_id: u64) {
    check::<AES256Internal, 64, N>(case, tc_id);
}

/// Calls `$check::<N>` for the message length `$len`. The data-unit length is a const parameter
/// of the key type, so every length in the file needs an arm; a new one fails loudly.
macro_rules! dispatch {
    ($len:expr, $check:ident, $case:expr, $tc_id:expr) => {
        match $len {
            16 => $check::<16>($case, $tc_id),
            17 => $check::<17>($case, $tc_id),
            18 => $check::<18>($case, $tc_id),
            19 => $check::<19>($case, $tc_id),
            20 => $check::<20>($case, $tc_id),
            21 => $check::<21>($case, $tc_id),
            22 => $check::<22>($case, $tc_id),
            23 => $check::<23>($case, $tc_id),
            24 => $check::<24>($case, $tc_id),
            25 => $check::<25>($case, $tc_id),
            26 => $check::<26>($case, $tc_id),
            27 => $check::<27>($case, $tc_id),
            28 => $check::<28>($case, $tc_id),
            29 => $check::<29>($case, $tc_id),
            30 => $check::<30>($case, $tc_id),
            31 => $check::<31>($case, $tc_id),
            32 => $check::<32>($case, $tc_id),
            33 => $check::<33>($case, $tc_id),
            48 => $check::<48>($case, $tc_id),
            51 => $check::<51>($case, $tc_id),
            64 => $check::<64>($case, $tc_id),
            68 => $check::<68>($case, $tc_id),
            96 => $check::<96>($case, $tc_id),
            102 => $check::<102>($case, $tc_id),
            128 => $check::<128>($case, $tc_id),
            136 => $check::<136>($case, $tc_id),
            other => panic!("tcId {}: no arm for a {other}-byte message; add one", $tc_id),
        }
    };
}

#[test]
fn wycheproof_aes_xts() {
    let Some(file) = wycheproof_json("aes_xts_test.json") else {
        return;
    };
    let (mut ran_128, mut ran_256, mut skipped_192) = (0usize, 0usize, 0usize);
    for group in file["testGroups"].as_array().expect("testGroups") {
        let key_size = group["keySize"].as_u64().expect("keySize");
        for case in group["tests"].as_array().expect("tests") {
            let tc_id = case["tcId"].as_u64().expect("tcId");
            assert_eq!(case["result"], "valid", "tcId {tc_id}: only valid cases are expected");
            let len = hex_field(case, "msg", tc_id).len();
            match key_size {
                256 => {
                    dispatch!(len, check_128, case, tc_id);
                    ran_128 += 1;
                }
                512 => {
                    dispatch!(len, check_256, case, tc_id);
                    ran_256 += 1;
                }
                384 => skipped_192 += 1,
                other => panic!("tcId {tc_id}: unexpected keySize {other}"),
            }
        }
    }
    println!(
        "Wycheproof AES-XTS: {ran_128} XTS-AES-128 and {ran_256} XTS-AES-256 cases, \
         {skipped_192} AES-192 cases skipped"
    );
    assert!(ran_128 > 0 && ran_256 > 0, "expected cases at both key sizes to run");
}
