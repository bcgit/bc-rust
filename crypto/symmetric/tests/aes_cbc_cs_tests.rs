//! What sets CBC-CS1, CBC-CS2 and CBC-CS3 apart over AES, and what they share, each checked
//! against plain CBC: `AES*Key<CBC<Blocks>>`, which the SP 800-38A and ACVP CBC suites pin. The
//! expected ciphertext of every case is built here from the Addendum to NIST SP 800-38A's own
//! definition rather than taken from the code under test:
//!
//! * CBC-CS1-Encrypt (Sec 2) is CBC over the message with its last block zero-padded (steps 2 and
//!   3), the second-to-last ciphertext block cut to the length of the last (step 4), in CBC's order
//!   (step 5); CBC-CS2 (Sec 3) swaps the last two portions when the last block is partial, and
//!   CBC-CS3 (Sec 4) always.
//! * A message of exactly one block is its CBC encryption under every variant.
//! * Less than one block is refused in both directions, through every API.
//!
//! The lengths: 0, 1 and 15, which are refused; 16; every partial last block after one and after
//! two whole blocks, 17 to 31 and 33 to 47; the boundaries 32, 48, 49, 63, 64 and 65; and longer
//! messages up to 4097 bytes. Streaming is checked against the one-shot at every split point of a
//! few lengths and byte by byte for every length up to 65, which is where a worker decides which
//! blocks it can release.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::symmetric_key::{
    BlockEncryptionKey, FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
use bouncycastle_symmetric::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_symmetric::modes::{Blocks, CBC, CBC_CS_FINAL_LEN, CBC_CS1, CBC_CS2, CBC_CS3};

const BLOCK_LEN: usize = 16;
const FINAL_LEN: usize = CBC_CS_FINAL_LEN;

/// The variant a key type is for, which decides the expected ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    CS1,
    CS2,
    CS3,
}

/// A CBC-CS key of some variant at `KEY_LEN`.
trait CsKey<const KEY_LEN: usize>:
    FromKeyMaterial<KEY_LEN>
    + SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
    + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
{
}
impl<K, const KEY_LEN: usize> CsKey<KEY_LEN> for K where
    K: FromKeyMaterial<KEY_LEN>
        + SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
{
}

fn material<const KEY_LEN: usize>() -> KeyMaterial<KEY_LEN> {
    let bytes: [u8; KEY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(7));
    KeyMaterial::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a cipher key")
}

fn key<K: CsKey<KEY_LEN>, const KEY_LEN: usize>() -> K {
    K::from_key_material(&material::<KEY_LEN>()).expect("a valid key")
}

const IV: [u8; BLOCK_LEN] = [
    0xA0, 0x51, 0x3C, 0x07, 0x99, 0x12, 0xEE, 0x48, 0x6B, 0x01, 0xD3, 0x70, 0x2F, 0xC4, 0x85, 0x5E,
];

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect()
}

/// `C1 || .. || Cn`: CBC over `pt` with its last block zero-padded (Sec 2, CBC-CS1-Encrypt steps 2
/// and 3), through the plain CBC key.
fn cbc_of_zero_padded<C, const KEY_LEN: usize>(pt: &[u8]) -> Vec<u8>
where
    C: FromKeyMaterial<KEY_LEN> + BlockEncryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    let mut blocks = pt.to_vec();
    blocks.resize(pt.len().next_multiple_of(BLOCK_LEN), 0);
    let cbc = C::from_key_material(&material::<KEY_LEN>()).expect("a valid key");
    cbc.encrypt_inplace_nonce(&IV, &mut blocks).expect("whole blocks");
    blocks
}

/// The Addendum's ciphertext of a `len`-byte message whose zero-padded CBC encryption is `c`.
fn by_definition(variant: Variant, c: &[u8], len: usize) -> Vec<u8> {
    let n = len.div_ceil(BLOCK_LEN);
    if n == 1 {
        return c.to_vec();
    }
    let d = len - (n - 1) * BLOCK_LEN;
    let head = &c[..(n - 2) * BLOCK_LEN];
    let c_nm1_star = &c[(n - 2) * BLOCK_LEN..(n - 2) * BLOCK_LEN + d]; // step 4: MSB_d(Cn-1)
    let c_n = &c[(n - 1) * BLOCK_LEN..];
    let swapped = match variant {
        Variant::CS1 => false,         // Sec 2 step 5
        Variant::CS2 => d < BLOCK_LEN, // Sec 3 step 3
        Variant::CS3 => true,          // Sec 4 step 2
    };
    let mut out = head.to_vec();
    if swapped {
        out.extend_from_slice(c_n);
        out.extend_from_slice(c_nm1_star);
    } else {
        out.extend_from_slice(c_nm1_star);
        out.extend_from_slice(c_n);
    }
    out
}

/// The lengths every property is checked at.
fn lengths() -> Vec<usize> {
    let mut lens: Vec<usize> = (16..=101).collect();
    lens.extend([127, 128, 129, 255, 256, 257, 1000, 4097]);
    lens
}

fn stream_encrypt<K: CsKey<KEY_LEN>, const KEY_LEN: usize>(
    key: &K,
    pt: &[u8],
    cuts: &[usize],
) -> Vec<u8> {
    let mut enc = key.create_encryptor_nonce(&IV);
    let mut out = Vec::new();
    let mut from = 0;
    for &to in cuts.iter().chain(core::iter::once(&pt.len())) {
        let piece = &pt[from..to];
        let mut buf = vec![0u8; enc.do_encrypt_out_len(piece.len())];
        let n = enc.do_encrypt_out(piece, &mut buf).expect("streaming encryption");
        assert_eq!(n, buf.len(), "do_encrypt_out_len must be exact");
        out.extend_from_slice(&buf);
        from = to;
    }
    let (last, last_len) = enc.do_encrypt_final().expect("a message of at least one block");
    out.extend_from_slice(&last[..last_len]);
    out
}

fn stream_decrypt<K: CsKey<KEY_LEN>, const KEY_LEN: usize>(
    key: &K,
    ct: &[u8],
    cuts: &[usize],
) -> Vec<u8> {
    let mut dec = key.create_decryptor(&IV);
    let mut out = Vec::new();
    let mut from = 0;
    for &to in cuts.iter().chain(core::iter::once(&ct.len())) {
        let piece = &ct[from..to];
        let mut buf = vec![0u8; dec.do_decrypt_out_len(piece.len())];
        let n = dec.do_decrypt_out(piece, &mut buf).expect("streaming decryption");
        assert_eq!(n, buf.len(), "do_decrypt_out_len must be exact");
        out.extend_from_slice(&buf);
        from = to;
    }
    let mut last = [0u8; FINAL_LEN];
    let last_len = dec.do_decrypt_final_out(&mut last).expect("a ciphertext of at least one block");
    out.extend_from_slice(&last[..last_len]);
    out
}

/// Every length, under one variant at one key length, against the definition over CBC.
fn matches_its_definition<K, C, const KEY_LEN: usize>(variant: Variant)
where
    K: CsKey<KEY_LEN>,
    C: FromKeyMaterial<KEY_LEN> + BlockEncryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    let key = key::<K, KEY_LEN>();
    for len in lengths() {
        let pt = message(len);
        let expected = by_definition(variant, &cbc_of_zero_padded::<C, KEY_LEN>(&pt), len);
        let ct = key.encrypt_nonce(&IV, &pt).expect("encryption");
        assert_eq!(ct, expected, "AES-{} {variant:?}, {len} bytes", KEY_LEN * 8);
        assert_eq!(ct.len(), len, "the ciphertext is as long as the plaintext");
        assert_eq!(key.decrypt(&IV, &ct).expect("decryption"), pt, "{variant:?}, {len} bytes");
    }
}

#[test]
fn every_variant_at_every_length_is_its_definition_over_cbc() {
    matches_its_definition::<AES128Key<CBC_CS1>, AES128Key<CBC<Blocks>>, 16>(Variant::CS1);
    matches_its_definition::<AES128Key<CBC_CS2>, AES128Key<CBC<Blocks>>, 16>(Variant::CS2);
    matches_its_definition::<AES128Key<CBC_CS3>, AES128Key<CBC<Blocks>>, 16>(Variant::CS3);
    matches_its_definition::<AES192Key<CBC_CS1>, AES192Key<CBC<Blocks>>, 24>(Variant::CS1);
    matches_its_definition::<AES192Key<CBC_CS2>, AES192Key<CBC<Blocks>>, 24>(Variant::CS2);
    matches_its_definition::<AES192Key<CBC_CS3>, AES192Key<CBC<Blocks>>, 24>(Variant::CS3);
    matches_its_definition::<AES256Key<CBC_CS1>, AES256Key<CBC<Blocks>>, 32>(Variant::CS1);
    matches_its_definition::<AES256Key<CBC_CS2>, AES256Key<CBC<Blocks>>, 32>(Variant::CS2);
    matches_its_definition::<AES256Key<CBC_CS3>, AES256Key<CBC<Blocks>>, 32>(Variant::CS3);
}

/// The three ciphertexts of one message, under CS1, CS2 and CS3 at AES-128.
fn all_three(pt: &[u8]) -> [Vec<u8>; 3] {
    [
        key::<AES128Key<CBC_CS1>, 16>().encrypt_nonce(&IV, pt).expect("CS1"),
        key::<AES128Key<CBC_CS2>, 16>().encrypt_nonce(&IV, pt).expect("CS2"),
        key::<AES128Key<CBC_CS3>, 16>().encrypt_nonce(&IV, pt).expect("CS3"),
    ]
}

#[test]
fn one_block_is_its_cbc_encryption_under_every_variant() {
    let pt = message(BLOCK_LEN);
    let cbc = cbc_of_zero_padded::<AES128Key<CBC<Blocks>>, 16>(&pt);
    for (ct, variant) in all_three(&pt).iter().zip(["CS1", "CS2", "CS3"]) {
        assert_eq!(ct, &cbc, "{variant}: one block is not stolen from or swapped");
    }
}

#[test]
fn whole_blocks_are_cbc_under_cs1_and_cs2_and_swapped_under_cs3() {
    for len in [32, 48, 64, 160, 4096] {
        let pt = message(len);
        let cbc = cbc_of_zero_padded::<AES128Key<CBC<Blocks>>, 16>(&pt);
        let [cs1, cs2, cs3] = all_three(&pt);
        assert_eq!(cs1, cbc, "CS1 is CBC on whole blocks ({len} bytes)");
        assert_eq!(cs2, cbc, "CS2 is CBC on whole blocks ({len} bytes)");
        let mut swapped = cbc.clone();
        let (c_nm1, c_n) = swapped[len - 2 * BLOCK_LEN..].split_at_mut(BLOCK_LEN);
        c_nm1.swap_with_slice(c_n);
        assert_eq!(cs3, swapped, "CS3 is CBC with the last two blocks swapped ({len} bytes)");
    }
}

#[test]
fn a_partial_last_block_gives_cs2_and_cs3_one_ciphertext_and_cs1_the_other_order() {
    for len in lengths().into_iter().filter(|len| len % BLOCK_LEN != 0) {
        let pt = message(len);
        let [cs1, cs2, cs3] = all_three(&pt);
        assert_eq!(cs2, cs3, "CS2 and CS3 agree when the last block is partial ({len} bytes)");
        // CS1 is the same two portions in the other order: Cn-1* (d bytes) then Cn.
        let d = len % BLOCK_LEN;
        let head = len - BLOCK_LEN - d;
        assert_eq!(cs1[..head], cs2[..head], "the blocks before the last two portions ({len})");
        assert_eq!(cs1[head..head + d], cs2[len - d..], "Cn-1* ({len} bytes)");
        assert_eq!(cs1[head + d..], cs2[head..head + BLOCK_LEN], "Cn ({len} bytes)");
    }
}

#[test]
fn a_ciphertext_decrypts_only_under_its_own_variant() {
    let cs1 = key::<AES128Key<CBC_CS1>, 16>();
    let cs2 = key::<AES128Key<CBC_CS2>, 16>();
    let cs3 = key::<AES128Key<CBC_CS3>, 16>();
    for len in [17, 31, 33, 47, 49, 100] {
        let pt = message(len);
        let ct = cs1.encrypt_nonce(&IV, &pt).expect("encryption");
        assert_ne!(cs2.decrypt(&IV, &ct).expect("any length decrypts"), pt, "CS1 as CS2, {len}");
        assert_ne!(cs3.decrypt(&IV, &ct).expect("any length decrypts"), pt, "CS1 as CS3, {len}");
    }
    for len in [32, 48, 64] {
        let pt = message(len);
        let ct = cs3.encrypt_nonce(&IV, &pt).expect("encryption");
        assert_ne!(cs1.decrypt(&IV, &ct).expect("any length decrypts"), pt, "CS3 as CS1, {len}");
        assert_ne!(cs2.decrypt(&IV, &ct).expect("any length decrypts"), pt, "CS3 as CS2, {len}");
    }
}

fn is_too_short<T>(r: &Result<T, SymmetricCipherError>) -> bool {
    matches!(r, Err(SymmetricCipherError::InvalidInputLength(_)))
}

/// Less than one block, refused by every route in both directions, and written to nowhere.
fn refuses_short<K: CsKey<KEY_LEN>, const KEY_LEN: usize>(variant: &str) {
    let key = key::<K, KEY_LEN>();
    for len in [0, 1, 15] {
        let short = message(len);

        let mut ct = [0xA5u8; 64];
        let r = key.encrypt_nonce_out(&IV, &short, &mut ct);
        assert!(is_too_short(&r), "{variant} encrypt_nonce_out, {len} bytes: {r:?}");
        assert!(ct.iter().all(|&b| b == 0), "{variant}: the refused one-shot's buffer is zeroized");
        assert!(
            is_too_short(&key.encrypt_nonce(&IV, &short).map(|_| ())),
            "{variant} encrypt_nonce"
        );

        let mut enc = key.create_encryptor_nonce(&IV);
        assert_eq!(enc.do_encrypt_out_len(len), 0, "{variant}: nothing to release below a block");
        assert_eq!(enc.do_encrypt_out(&short, &mut []).expect("held"), 0);
        assert!(
            is_too_short(&enc.do_encrypt_final().map(|_| ())),
            "{variant} do_encrypt_final, {len}"
        );

        let mut pt = [0xA5u8; 64];
        let r = key.decrypt_out(&IV, &short, &mut pt);
        assert!(is_too_short(&r), "{variant} decrypt_out, {len} bytes: {r:?}");
        assert!(pt.iter().all(|&b| b == 0), "{variant}: the refused one-shot's buffer is zeroized");
        assert!(is_too_short(&key.decrypt(&IV, &short).map(|_| ())), "{variant} decrypt");

        let mut dec = key.create_decryptor(&IV);
        assert_eq!(dec.do_decrypt_out(&short, &mut []).expect("held"), 0);
        let mut last = [0xA5u8; FINAL_LEN];
        assert!(
            is_too_short(&dec.do_decrypt_final_out(&mut last)),
            "{variant} do_decrypt_final_out"
        );
        assert_eq!(last, [0u8; FINAL_LEN], "{variant}: the refused final's buffer is zeroized");
    }
}

#[test]
fn less_than_one_block_is_refused_in_both_directions() {
    refuses_short::<AES128Key<CBC_CS1>, 16>("CS1");
    refuses_short::<AES128Key<CBC_CS2>, 16>("CS2");
    refuses_short::<AES128Key<CBC_CS3>, 16>("CS3");
    refuses_short::<AES256Key<CBC_CS3>, 32>("CS3 under AES-256");
}

/// Streaming in two pieces at every split point, in three at a spread of them, and byte by byte,
/// against the one-shot, in both directions.
fn streams_like_the_one_shot<K: CsKey<KEY_LEN>, const KEY_LEN: usize>(variant: &str) {
    let key = key::<K, KEY_LEN>();
    for len in 16..=65 {
        let pt = message(len);
        let ct = key.encrypt_nonce(&IV, &pt).expect("encryption");
        let bytes: Vec<usize> = (1..len).collect();
        assert_eq!(stream_encrypt(&key, &pt, &bytes), ct, "{variant}, {len} bytes, byte by byte");
        assert_eq!(stream_decrypt(&key, &ct, &bytes), pt, "{variant}, {len} bytes, byte by byte");
    }
    for len in [16, 17, 31, 32, 33, 47, 48, 49, 64, 65, 100] {
        let pt = message(len);
        let ct = key.encrypt_nonce(&IV, &pt).expect("encryption");
        for cut in 0..=len {
            assert_eq!(
                stream_encrypt(&key, &pt, &[cut]),
                ct,
                "{variant}, {len} bytes cut at {cut}"
            );
            assert_eq!(
                stream_decrypt(&key, &ct, &[cut]),
                pt,
                "{variant}, {len} bytes cut at {cut}"
            );
            let second = (cut + 17).min(len);
            assert_eq!(
                stream_encrypt(&key, &pt, &[cut, second]),
                ct,
                "{variant}, {len}: {cut}, {second}"
            );
            assert_eq!(
                stream_decrypt(&key, &ct, &[cut, second]),
                pt,
                "{variant}, {len}: {cut}, {second}"
            );
        }
    }
}

#[test]
fn streaming_in_any_pieces_matches_the_one_shot() {
    streams_like_the_one_shot::<AES128Key<CBC_CS1>, 16>("CS1");
    streams_like_the_one_shot::<AES128Key<CBC_CS2>, 16>("CS2");
    streams_like_the_one_shot::<AES128Key<CBC_CS3>, 16>("CS3");
}

/// An update refused for a short buffer consumes nothing: the same update, retried with the length
/// the error names, continues the message as if the refusal had not happened.
fn a_refused_update_consumes_nothing<K: CsKey<KEY_LEN>, const KEY_LEN: usize>(variant: &str) {
    let key = key::<K, KEY_LEN>();
    let pt = message(83);
    let ct = key.encrypt_nonce(&IV, &pt).expect("encryption");

    let mut enc = key.create_encryptor_nonce(&IV);
    let mut out = Vec::new();
    let mut first = vec![0u8; enc.do_encrypt_out_len(20)];
    enc.do_encrypt_out(&pt[..20], &mut first).expect("20 bytes");
    out.extend_from_slice(&first);
    let need = enc.do_encrypt_out_len(50);
    assert_eq!(need, 48, "{variant}: 70 bytes so far, of which the first three blocks can go");
    let mut short = vec![0xA5u8; need - 1];
    assert_eq!(
        enc.do_encrypt_out(&pt[20..70], &mut short),
        Err(SymmetricCipherError::OutputBufferTooSmall(need)),
        "{variant}"
    );
    assert!(short.iter().all(|&b| b == 0), "{variant}: the refused call zeroizes its buffer");
    let mut retry = vec![0u8; need];
    assert_eq!(enc.do_encrypt_out(&pt[20..70], &mut retry), Ok(need), "{variant}");
    out.extend_from_slice(&retry);
    let mut rest = vec![0u8; enc.do_encrypt_out_len(13)];
    enc.do_encrypt_out(&pt[70..], &mut rest).expect("the rest");
    out.extend_from_slice(&rest);
    let (last, last_len) = enc.do_encrypt_final().expect("final");
    out.extend_from_slice(&last[..last_len]);
    assert_eq!(out, ct, "{variant}: the refusal left the encryptor as it was");

    let mut dec = key.create_decryptor(&IV);
    let mut rec = Vec::new();
    let mut first = vec![0u8; dec.do_decrypt_out_len(20)];
    dec.do_decrypt_out(&ct[..20], &mut first).expect("20 bytes");
    rec.extend_from_slice(&first);
    let need = dec.do_decrypt_out_len(50);
    let mut short = vec![0xA5u8; need - 1];
    assert_eq!(
        dec.do_decrypt_out(&ct[20..70], &mut short),
        Err(SymmetricCipherError::OutputBufferTooSmall(need)),
        "{variant}"
    );
    let mut retry = vec![0u8; need];
    assert_eq!(dec.do_decrypt_out(&ct[20..70], &mut retry), Ok(need), "{variant}");
    rec.extend_from_slice(&retry);
    let mut rest = vec![0u8; dec.do_decrypt_out_len(13)];
    dec.do_decrypt_out(&ct[70..], &mut rest).expect("the rest");
    rec.extend_from_slice(&rest);
    let (last, last_len) = dec.do_decrypt_final().expect("final");
    rec.extend_from_slice(&last[..last_len]);
    assert_eq!(rec, pt, "{variant}: the refusal left the decryptor as it was");
}

#[test]
fn an_update_refused_for_a_short_buffer_consumes_nothing() {
    a_refused_update_consumes_nothing::<AES128Key<CBC_CS1>, 16>("CS1");
    a_refused_update_consumes_nothing::<AES128Key<CBC_CS2>, 16>("CS2");
    a_refused_update_consumes_nothing::<AES128Key<CBC_CS3>, 16>("CS3");
}
