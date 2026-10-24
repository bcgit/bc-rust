//! Camellia-CBC known-answer tests, through `Camellia128Key<CBC<Blocks>>` and its siblings -- the
//! block-aligned keys the padded `Camellia_CBC_*` aliases wrap.
//!
//! RFC 3713 has no CBC vectors (it only assigns the `id-camellia*-cbc` identifiers, Sec 3), so
//! these are the `CAMELLIA-*-CBC` entries of OpenSSL's `test/recipes/30-test_evp_data/evpciph_camellia.txt`
//! (OpenSSL 3.6.2), transcribed from the file. For each key length the first three entries chain
//! -- each `IV` is the previous `Ciphertext` -- so they form one three-block CBC message under the
//! IV `000102..0f`; that is what is checked here, in one call and block by block, both directions.
//! (The fourth 128-bit entry has an IV unrelated to the third's ciphertext and is checked on its
//! own.) The plaintext blocks and the 128/192/256-bit keys are those of NIST SP 800-38A Appendix F,
//! so a CBC vector here is also a cross-check of the single-block cipher under fresh keys.
//!
//! There is no API for supplying an IV, so encryption is driven through the key's
//! `create_encryptor` with a [`FixedSeedRNG`] whose stream is the vector's IV, and the test asserts
//! the returned init data really is that IV before comparing any ciphertext. Decryption takes the
//! IV directly.

mod common;

use bouncycastle_camellia::{BLOCK_LEN, Camellia128Key, Camellia192Key, Camellia256Key};
use bouncycastle_cipher::modes::{Blocks, CBC};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use common::bytes;

/// The IV of the first entry of every chain.
const IV: &str = "000102030405060708090A0B0C0D0E0F";

/// The plaintext blocks, in order (SP 800-38A F.2's four blocks; the first three chain here).
const PT: [&str; 4] = [
    "6BC1BEE22E409F96E93D7E117393172A",
    "AE2D8A571E03AC9C9EB76FAC45AF8E51",
    "30C81C46A35CE411E5FBC1191A0A52EF",
    "F69F2445DF4F9B17AD2B417BE66C3710",
];

const KEY_128: &str = "2B7E151628AED2A6ABF7158809CF4F3C";
const CT_128: [&str; 3] = [
    "1607CF494B36BBF00DAEB0B503C831AB",
    "A2F2CF671629EF7840C5A5DFB5074887",
    "0F06165008CF8B8B5A63586362543E54",
];
/// The fourth 128-bit entry: its own IV.
const IV_128_4: &str = "36A84CDAFD5F9A85ADA0F0A993D6D577";
const CT_128_4: &str = "74C64268CDB8B8FAF5B34E8AF3732980";

const KEY_192: &str = "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B";
const CT_192: [&str; 4] = [
    "2A4830AB5AC4A1A2405955FD2195CF93",
    "5D5A869BD14CE54264F892A6DD2EC3D5",
    "37D359C3349836D884E310ADDF68C449",
    "01FAAA930B4AB9916E9668E1428C6B08",
];

const KEY_256: &str = "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4";
const CT_256: [&str; 4] = [
    "E6CFA35FC02B134A4D2C0B6737AC3EDA",
    "36CBEB73BD504B4070B1B7DE2B21EB50",
    "E31A6055297D96CA3330CDF1B1860A83",
    "5D563F6D1CCCF236051C0C5C1C58F28F",
];

fn key<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&bytes::<N>(hex_str), KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

fn concat<const N: usize>(blocks: &[&str]) -> [u8; N] {
    let joined: String = blocks.iter().copied().collect();
    bytes(&joined)
}

/// A chained CBC message of `N` bytes under `IV`, through a `CBC<Blocks>` key: one call, block by
/// block, both directions.
fn check_chain<'k, const KEY_LEN: usize, K, const N: usize>(
    name: &str,
    key: &'k K,
    pt: &[u8; N],
    ct: &[u8; N],
) where
    K: BlockEncryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>
        + BlockDecryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    let iv: [u8; 16] = bytes(IV);

    // Encrypt, all blocks in one call, under the vector's IV.
    let (mut enc, got_iv) = key.create_encryptor(&mut FixedSeedRNG::<16>::new(iv)).unwrap();
    assert_eq!(got_iv, iv, "{name}: the pinned RNG should produce the vector's IV");
    let mut data = *pt;
    enc.do_encrypt_blocks_inplace(data.as_chunks_mut::<BLOCK_LEN>().0).unwrap();
    assert_eq!(data, *ct, "{name}: encrypt, all blocks in one call");

    // Encrypt one block at a time.
    let (mut enc, _) = key.create_encryptor(&mut FixedSeedRNG::<16>::new(iv)).unwrap();
    let mut data = *pt;
    for block in data.as_chunks_mut::<BLOCK_LEN>().0.iter_mut() {
        enc.do_encrypt_blocks_inplace(core::slice::from_mut(block)).unwrap();
    }
    assert_eq!(data, *ct, "{name}: encrypt, one block at a time");

    // Decrypt with the IV as init data: one shot, and streaming.
    let mut data = *ct;
    key.decrypt_inplace(&iv, &mut data).unwrap();
    assert_eq!(data, *pt, "{name}: decrypt, one shot");

    let mut dec = key.create_decryptor(&iv);
    let mut data = *ct;
    for block in data.as_chunks_mut::<BLOCK_LEN>().0.iter_mut() {
        dec.do_decrypt_blocks_inplace(core::slice::from_mut(block)).unwrap();
    }
    assert_eq!(data, *pt, "{name}: decrypt, one block at a time");
}

#[test]
fn camellia_128_cbc_chain() {
    let key = Camellia128Key::<CBC<Blocks>>::from_key_material(&key::<16>(KEY_128)).unwrap();
    check_chain::<16, _, 48>(
        "CAMELLIA-128-CBC",
        &key,
        &concat::<48>(&PT[..3]),
        &concat::<48>(&CT_128),
    );
    // The fourth entry stands alone: one block under its own IV.
    let iv: [u8; 16] = bytes(IV_128_4);
    let mut data: [u8; 16] = bytes(PT[3]);
    let (mut enc, got_iv) = key.create_encryptor(&mut FixedSeedRNG::<16>::new(iv)).unwrap();
    assert_eq!(got_iv, iv);
    enc.do_encrypt_blocks_inplace(core::slice::from_mut(&mut data)).unwrap();
    assert_eq!(data, bytes::<16>(CT_128_4), "CAMELLIA-128-CBC entry 4");
    key.decrypt_inplace(&iv, &mut data).unwrap();
    assert_eq!(data, bytes::<16>(PT[3]));
}

#[test]
fn camellia_192_cbc_chain() {
    let key = Camellia192Key::<CBC<Blocks>>::from_key_material(&key::<24>(KEY_192)).unwrap();
    check_chain::<24, _, 64>("CAMELLIA-192-CBC", &key, &concat::<64>(&PT), &concat::<64>(&CT_192));
}

#[test]
fn camellia_256_cbc_chain() {
    let key = Camellia256Key::<CBC<Blocks>>::from_key_material(&key::<32>(KEY_256)).unwrap();
    check_chain::<32, _, 64>("CAMELLIA-256-CBC", &key, &concat::<64>(&PT), &concat::<64>(&CT_256));
}
