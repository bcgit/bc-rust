//! KISA's published ARIA test vectors -- 10 blocks under each key length, in ECB and in CBC -- as
//! carried in OpenSSL's `test/recipes/30-test_evp_data/evpciph_aria.txt` (OpenSSL 3.6.2), which
//! attributes them to `ARIA-testvector-e.pdf` from the ARIA site. Transcribed from the OpenSSL
//! file.
//!
//! The ECB vectors are 10 independent blocks, so they exercise the four-block, pair
//! and single-block paths against published answers (two fours and a pair). The CBC vectors go through the
//! [`ARIA_CBC_128`] / `_192` / `_256` aliases: encryption is driven through
//! [`BlockCipherEncryptor::do_encrypt_init_rng`] with a [`FixedSeedRNG`] whose stream is the
//! vector's IV (there is no API for supplying one), and the test asserts the returned init data
//! really is that IV before comparing any ciphertext; decryption takes the IV directly.

mod common;

use bouncycastle_aria::{ARIA, ARIA_128, ARIA_192, ARIA_256, ARIAParams, BLOCK_LEN, Block};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, ElectronicCodeBook};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
use common::bytes;

/// The published CBC vectors are whole blocks, so they are checked against the mode
/// itself rather than through the `ARIA_CBC_*` aliases: those carry a padding scheme and
/// are the arbitrary-length API, which would append a padding block to an already-aligned
/// message. `cbc_alias_tests.rs` covers the aliases.
/// ARIA-128 in CBC mode, block-aligned and in place -- what `ARIA_CBC_128` wraps.
type Aria128Cbc<Dir> = Cbc<ARIA_128, Dir, 16, 16>;
/// ARIA-192 in CBC mode, block-aligned and in place -- what `ARIA_CBC_192` wraps.
type Aria192Cbc<Dir> = Cbc<ARIA_192, Dir, 24, 16>;
/// ARIA-256 in CBC mode, block-aligned and in place -- what `ARIA_CBC_256` wraps.
type Aria256Cbc<Dir> = Cbc<ARIA_256, Dir, 32, 16>;

/// The 160-byte plaintext shared by all six vectors.
const PLAINTEXT: &str = "11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd";

/// The IV shared by the three CBC vectors.
const IV: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

const KEY_128: &str = "00112233445566778899aabbccddeeff";
const ECB_128: &str = "c6ecd08e22c30abdb215cf74e2075e6e29ccaac63448708d331b2f816c51b17d9e133d1528dbf0af5787c7f3a3f5c2bf6b6f345907a3055612ce072ff54de7d788424da6e8ccfe8172b391be499354165665ba7864917000a6eeb2ecb4a698edfc7887e7f556377614ab0a282293e6d884dbb84206cdb16ed1754e77a1f243fd086953f752cc1e46c7c794ae85537dcaec8dd721f55c93b6edfe2adea43873e8";
const CBC_128: &str = "49d61860b14909109cef0d22a9268134fadf9fb23151e9645fba75018bdb1538b53334634bbf7d4cd4b5377033060c155fe3948ca75de1031e1d85619e0ad61eb419a866b3c2dbfd10a4ed18b22149f75897f0b8668b0c1c542c687778835fb7cd46e45f85eaa7072437dd9fa6793d6f8d4ccefc4eb1ac641ac1bd30b18c6d64c49bca137eb21c2e04da62712ca2b4f540c57112c38791852cfac7a5d19ed83a";

const KEY_192: &str = "00112233445566778899aabbccddeeff0011223344556677";
const ECB_192: &str = "8d1470625f59ebacb0e55b534b3e462b5f23d33bff78f46c3c15911f4a21809aaccad80b4bda915aa9dae6bcebe06a6c83f77fd5391acfe61de2f646b5d447edbfd5bb49b12fbb9145b227895a757b2af1f7188734863d7b8b6ede5a5b2f06a0a233c8523d2db778fb31b0e311f32700152f33861e9d040c83b5eb40cd88ea49975709dc629365a189f78a3ec40345fc6a5a307a8f9a4413091e007eca5645a0";
const CBC_192: &str = "afe6cf23974b533c672a826264ea785f4e4f7f780dc7f3f1e0962b80902386d514e9c3e77259de92dd1102ffab086c1ea52a71260db5920a83295c25320e421147ca45d532f327b856ea947cd2196ae2e040826548b4c891b0ed0ca6e714dbc4631998d548110d666b3d54c2a091955c6f05beb4f62309368696c9791fc4c551564a2637f194346ec45fbca6c72a5b4612e208d531d6c34cc5c64eac6bd0cf8c";

const KEY_256: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const ECB_256: &str = "58a875e6044ad7fffa4f58420f7f442d8e191016f28e79aefc01e204773280d7018e5f7a938ec30711719953bae86542cd7ebc752474c1a5f6eaaace2a7e29462ee7dfa5afdb84177ead95ccd4b4bb6e1ed17b9534cff0a5fc2941429cfee2ee49c7adbeb7e9d1b0d2a8531d942079596a27ed79f5b1dd13ecd604b07a48885a3afa0627a0e4e60a3c703af292f1baa77b702f16c54aa74bc727ea95c7468b00";
const CBC_256: &str = "523a8a806ae621f155fdd28dbc34e1ab7b9b42432ad8b2efb96e23b13f0a6e52f36185d50ad002c5f601bee5493f118b243ee2e313642bffc3902e7b2efd9a12fa682edd2d23c8b9c5f043c18b17c1ec4b5867918270fbec1027c19ed6af833da5d620994668ca22f599791d292dd6273b2959082aafb7a996167cce1eec5f0cfd15f610d87e2dda9ba68ce1260ca54b222491418374294e7909b1e8551cd8de";

fn key<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&bytes::<N>(hex_str), KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

fn blocks10(hex_str: &str) -> [Block; 10] {
    let flat: [u8; 160] = bytes(hex_str);
    let (chunks, _) = flat.as_chunks::<BLOCK_LEN>();
    chunks.try_into().unwrap()
}

/// ECB: 10 independent blocks through every batching, both directions.
fn check_ecb<P: ARIAParams>(name: &str, perm: &ARIA<P>, ct_hex: &str) {
    let pt = blocks10(PLAINTEXT);
    let ct = blocks10(ct_hex);

    // Two fours and a pair.
    let mut fours = pt;
    {
        let (head, tail) = fours.split_at_mut(8);
        for four in head.as_chunks_mut::<4>().0 {
            perm.encrypt_4blocks(four);
        }
        perm.encrypt_2blocks(tail.try_into().unwrap());
    }
    assert_eq!(fours, ct, "{name}: encrypt_4blocks");
    {
        let (head, tail) = fours.split_at_mut(8);
        for four in head.as_chunks_mut::<4>().0 {
            perm.decrypt_4blocks(four);
        }
        perm.decrypt_2blocks(tail.try_into().unwrap());
    }
    assert_eq!(fours, pt, "{name}: decrypt_4blocks");

    // Five pairs, and ten singles.
    let mut pairs = ct;
    for pair in pairs.as_mut_slice().as_chunks_mut::<2>().0 {
        perm.decrypt_2blocks(pair);
    }
    assert_eq!(pairs, pt, "{name}: decrypt_2blocks");
    for (i, (p, c)) in pt.iter().zip(ct.iter()).enumerate() {
        let mut b = *p;
        perm.encrypt_block(&mut b);
        assert_eq!(&b, c, "{name}: encrypt_block #{i}");
    }
}

/// CBC: the 10-block message in one call, block by block, both directions.
fn check_cbc<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>>(
    name: &str,
    key: &KeyMaterial<KEY_LEN>,
    ct_hex: &str,
) {
    let iv: [u8; 16] = bytes(IV);
    let pt: [u8; 160] = bytes(PLAINTEXT);
    let ct: [u8; 160] = bytes(ct_hex);

    let (mut enc, got_iv) = Cbc::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
        key,
        &mut FixedSeedRNG::<16>::new(iv),
    )
    .unwrap();
    assert_eq!(got_iv, iv, "{name}: the pinned RNG should produce the vector's IV");
    let mut data = pt;
    enc.do_encrypt(&mut data).unwrap();
    assert_eq!(data, ct, "{name}: encrypt, all blocks in one call");

    let (mut enc, _) = Cbc::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
        key,
        &mut FixedSeedRNG::<16>::new(iv),
    )
    .unwrap();
    let mut data = pt;
    for block in data.as_chunks_mut::<BLOCK_LEN>().0.iter_mut() {
        enc.do_encrypt(block).unwrap();
    }
    assert_eq!(data, ct, "{name}: encrypt, one block at a time");

    let mut data = ct;
    Cbc::<P, Decrypting, KEY_LEN, BLOCK_LEN>::decrypt(key, &iv, &mut data).unwrap();
    assert_eq!(data, pt, "{name}: decrypt, one shot");

    let mut dec = Cbc::<P, Decrypting, KEY_LEN, BLOCK_LEN>::do_decrypt_init(key, &iv).unwrap();
    let mut data = ct;
    for block in data.as_chunks_mut::<BLOCK_LEN>().0.iter_mut() {
        dec.do_decrypt(block).unwrap();
    }
    assert_eq!(data, pt, "{name}: decrypt, one block at a time");
}

#[test]
fn aria_128_ecb() {
    check_ecb("ARIA-128-ECB", &ARIA_128::new(&key::<16>(KEY_128)).unwrap(), ECB_128);
}

#[test]
fn aria_192_ecb() {
    check_ecb("ARIA-192-ECB", &ARIA_192::new(&key::<24>(KEY_192)).unwrap(), ECB_192);
}

#[test]
fn aria_256_ecb() {
    check_ecb("ARIA-256-ECB", &ARIA_256::new(&key::<32>(KEY_256)).unwrap(), ECB_256);
}

#[test]
fn aria_128_cbc() {
    let key = key::<16>(KEY_128);
    check_cbc::<16, ARIA_128>("ARIA-128-CBC", &key, CBC_128);
    let mut data: [u8; 160] = bytes(CBC_128);
    Aria128Cbc::<Decrypting>::decrypt(&key, &bytes::<16>(IV), &mut data).unwrap();
    assert_eq!(data, bytes::<160>(PLAINTEXT));
}

#[test]
fn aria_192_cbc() {
    let key = key::<24>(KEY_192);
    check_cbc::<24, ARIA_192>("ARIA-192-CBC", &key, CBC_192);
    let mut data: [u8; 160] = bytes(CBC_192);
    Aria192Cbc::<Decrypting>::decrypt(&key, &bytes::<16>(IV), &mut data).unwrap();
    assert_eq!(data, bytes::<160>(PLAINTEXT));
}

#[test]
fn aria_256_cbc() {
    let key = key::<32>(KEY_256);
    check_cbc::<32, ARIA_256>("ARIA-256-CBC", &key, CBC_256);
    let mut data: [u8; 160] = bytes(CBC_256);
    Aria256Cbc::<Decrypting>::decrypt(&key, &bytes::<16>(IV), &mut data).unwrap();
    assert_eq!(data, bytes::<160>(PLAINTEXT));
}
