//! The stream modes of operation over SM4: the known-answer tests from draft-ribose-cfrg-sm4-10
//! Appendix A.2 that cover them, and the wiring of the `SM4_CFB`, `SM4_CFB8` and `SM4_CTR` aliases.
//!
//! Appendix A.2 has an SM4-CFB section (A.2.4) and an SM4-CTR section (A.2.5), and the two are used
//! differently here because only one of them lines up with the alias's parameters:
//!
//! * **A.2.4, SM4-CFB.** Straight known-answer tests through `SM4_CFB`. There is no API for
//!   supplying an IV, so encryption is driven through
//!   [`StreamCipherEncryptor::do_encrypt_init_rng`] with a [`FixedSeedRNG`] whose stream is the
//!   vector's IV, and the test asserts the returned init data really is that IV before comparing
//!   any ciphertext. Decryption takes the IV directly.
//! * **A.2.5, SM4-CTR.** The draft's counter sequence makes the whole 16-byte IV the first counter
//!   block and increments it as a unit; `Ctr` splits the block into a 12-byte nonce and a 4-byte
//!   counter that starts at zero (see the `SM4_CTR` docs, and Sec 8.7, which leaves the sequence to
//!   the caller: "the counter could be any sequence that does not repeat within the block size").
//!   The published counter blocks are therefore not ones the alias can produce. The vectors instead
//!   pin [`reference_ctr`], written straight from the Sec 8.7.1 equations over the permutation, and
//!   `SM4_CTR` is then required to agree with that same reference on the counter blocks it does
//!   produce. Everything internal to the mode -- the counter increment, the short final block, the
//!   chunking -- is covered by the ACVP vectors in `bouncycastle-modes`.
//!
//! The draft defines SM4-CFB-8 (Sec 8.5.1) but publishes no example of it, so `SM4_CFB8` is pinned
//! the same way: against [`reference_cfb8`], the Sec 8.5.2 equations at `s = 8` evaluated over the
//! permutation.
//!
//! All vector values are transcribed from the downloaded text of the draft.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Decrypting, Encrypting};
use bouncycastle_sm4::{BLOCK_LEN, CTR_NONCE_LEN, KEY_LEN, SM4, SM4_CFB, SM4_CFB8, SM4_CTR};

/// A.2.x Example 1 key.
const KEY_1: &str = "0123456789abcdeffedcba9876543210";
/// A.2.x Example 2 key.
const KEY_2: &str = "fedcba98765432100123456789abcdef";
/// The IV shared by every A.2 IV-based example.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The two plaintext blocks shared by the A.2.4 SM4-CFB examples.
const CFB_PT: &str = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb";
/// A.2.4.1 SM4-CFB Example 1 ciphertext.
const CFB_CT_1: &str = "ac3236cb861dd316e6413b4e3c7524b769d4c54ed433b9a0346009beb37b2b3f";
/// A.2.4.2 SM4-CFB Example 2 ciphertext.
const CFB_CT_2: &str = "5dcccd25a84ba16560d7f265887068490d9b86ff20c3bfe115ffa02ca6192cc5";

/// The four plaintext blocks shared by the A.2.5 SM4-CTR examples.
const CTR_PT: &str = concat!(
    "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",
    "ccccccccccccccccdddddddddddddddd",
    "eeeeeeeeeeeeeeeeffffffffffffffff",
    "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",
);
/// A.2.5.1 SM4-CTR Example 1 ciphertext.
const CTR_CT_1: &str = concat!(
    "ac3236cb970cc20791364c395a1342d1",
    "a3cbc1878c6f30cd074cce385cdd70c7",
    "f234bc0e24c11980fd1286310ce37b92",
    "6e02fcd0faa0baf38b2933851d824514",
);
/// A.2.5.2 SM4-CTR Example 2 ciphertext.
const CTR_CT_2: &str = concat!(
    "5dcccd25b95ab07417a08512ee160e2f",
    "8f661521cbbab44cc87138445bc29e5c",
    "0ae0297205d62704173b21239b887f6c",
    "8cb5b800917a2488284bde9e16ea2906",
);

fn bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("valid hex")
}

fn key_material(hex_str: &str) -> KeyMaterial<KEY_LEN> {
    let k: [u8; KEY_LEN] = bytes(hex_str).try_into().expect("a 16-byte key");
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&k, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

fn iv_bytes() -> [u8; BLOCK_LEN] {
    bytes(IV).try_into().expect("a 16-byte IV")
}

/// Deterministic filler, so nothing here depends on an RNG.
fn filler(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

// ---- A.2.4  SM4-CFB, through the alias -------------------------------------------------------

/// Both A.2.4 examples, each encrypted under the vector's own IV and decrypted back, in one call
/// and then one block at a time. The chunked pass is the point of a stream cipher: the draft
/// defines the mode on the whole message, and `Cfb` must give the same answer whatever the
/// chunking.
fn check_cfb(section: &str, key_hex: &str, expected: &str) {
    let key = key_material(key_hex);
    let iv = iv_bytes();
    let pt = bytes(CFB_PT);
    let ct = bytes(expected);

    // Encrypt in one call, under the vector's IV.
    let (mut enc, got_iv) =
        SM4_CFB::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<BLOCK_LEN>::new(iv))
            .expect("encryption init");
    assert_eq!(got_iv, iv, "{section}: the pinned RNG should produce the vector's IV");
    let mut data = pt.clone();
    let written = enc.do_encrypt(&mut data).expect("encryption");
    assert_eq!(written, pt.len(), "{section}: a stream cipher writes exactly what it was given");
    assert_eq!(data, ct, "{section} encrypt, one call");

    // Encrypt one block at a time: same answer.
    let (mut enc, _) =
        SM4_CFB::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<BLOCK_LEN>::new(iv))
            .expect("encryption init");
    let mut data = pt.clone();
    for chunk in data.chunks_mut(BLOCK_LEN) {
        enc.do_encrypt(chunk).expect("encryption");
    }
    assert_eq!(data, ct, "{section} encrypt, one block at a time");

    // Decrypt with the IV as init data: one shot, and streaming at an unaligned boundary.
    let mut data = ct.clone();
    SM4_CFB::<Decrypting>::decrypt(&key, &iv, &mut data).expect("decryption");
    assert_eq!(data, pt, "{section} decrypt, one shot");

    let mut dec = SM4_CFB::<Decrypting>::do_decrypt_init(&key, &iv).expect("decryption init");
    let mut data = ct.clone();
    for chunk in data.chunks_mut(7) {
        dec.do_decrypt(chunk).expect("decryption");
    }
    assert_eq!(data, pt, "{section} decrypt, seven bytes at a time");
}

#[test]
fn a_2_4_1_cfb_example_1() {
    check_cfb("A.2.4.1", KEY_1, CFB_CT_1);
}

#[test]
fn a_2_4_2_cfb_example_2() {
    check_cfb("A.2.4.2", KEY_2, CFB_CT_2);
}

// ---- A.2.5  SM4-CTR, through a reference built from the equations ------------------------------

/// CTR straight from Sec 8.7.1, with the draft's own counter sequence.
///
/// ```text
/// for i = 1 to n
///   O_i = SM4Encrypt(T_i)
/// C_i = P_i xor O_i           (i < n)
/// C_n = P_n xor MSB(u, O_n)
/// ```
///
/// `T_1` is the caller's counter block and each `T_{i+1}` is `T_i` incremented as a 128-bit
/// big-endian integer, which is what reproduces the A.2.5 ciphertexts. Encryption and decryption
/// are the same operation, so one function serves both.
fn reference_ctr(key: &KeyMaterial<KEY_LEN>, t1: [u8; BLOCK_LEN], data: &mut [u8]) {
    let sm4 = SM4::new(key).expect("a valid SM4 key");
    let mut t = t1;
    for chunk in data.chunks_mut(BLOCK_LEN) {
        // O_i = SM4Encrypt(T_i); a short final chunk takes MSB(u, O_n) by simply stopping early.
        let mut o = t;
        sm4.encrypt_block(&mut o);
        for (d, k) in chunk.iter_mut().zip(o.iter()) {
            *d ^= k;
        }
        // T_{i+1}: increment the whole block, carrying from the least significant byte.
        for b in t.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }
}

/// The reference reproduces both published A.2.5 ciphertexts with `T_1 = IV`, in both directions.
/// This is what pins the reference; the alias is then checked against it below.
#[test]
fn a_2_5_ctr_examples_pin_the_reference() {
    for (section, key_hex, expected) in [("A.2.5.1", KEY_1, CTR_CT_1), ("A.2.5.2", KEY_2, CTR_CT_2)]
    {
        let key = key_material(key_hex);
        let pt = bytes(CTR_PT);
        let ct = bytes(expected);

        let mut data = pt.clone();
        reference_ctr(&key, iv_bytes(), &mut data);
        assert_eq!(data, ct, "{section}: the reference should reproduce the published ciphertext");

        reference_ctr(&key, iv_bytes(), &mut data);
        assert_eq!(data, pt, "{section}: and encryption is its own inverse");
    }
}

/// `SM4_CTR` agrees with the pinned reference on the counter blocks it does produce: `nonce`
/// followed by a four-byte counter starting at zero. Lengths are chosen to cross the block
/// boundary and to end on a short final block, which is where `MSB(u, O_n)` applies.
#[test]
fn the_ctr_alias_agrees_with_the_reference() {
    let key = key_material(KEY_1);
    let nonce: [u8; CTR_NONCE_LEN] =
        bytes("000102030405060708090a0b").try_into().expect("a 12-byte nonce");

    // The counter block the alias starts from: the nonce, then four zero bytes.
    let mut t1 = [0u8; BLOCK_LEN];
    t1[..CTR_NONCE_LEN].copy_from_slice(&nonce);

    for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 129] {
        let plaintext = filler(len, len as u32);

        let mut expected = plaintext.clone();
        reference_ctr(&key, t1, &mut expected);

        let mut data = plaintext.clone();
        let mut enc = SM4_CTR::<Encrypting>::do_encrypt_init_rng(
            &key,
            &mut FixedSeedRNG::<CTR_NONCE_LEN>::new(nonce),
        )
        .map(|(enc, got)| {
            assert_eq!(got, nonce, "the pinned RNG should produce the chosen nonce");
            enc
        })
        .expect("encryption init");
        enc.do_encrypt(&mut data).expect("encryption");
        assert_eq!(data, expected, "len {len}: SM4_CTR should match the reference");

        // ...and decryption undoes it under the same nonce.
        SM4_CTR::<Decrypting>::decrypt(&key, &nonce, &mut data).expect("decryption");
        assert_eq!(data, plaintext, "len {len}: round trip");
    }
}

// ---- SM4-CFB-8, against the Sec 8.5.2 equations at s = 8 ---------------------------------------

/// CFB straight from Sec 8.5.2 with `s = 8`, one byte per forward cipher call.
///
/// ```text
/// I_1 = IV
/// I_i = LSB(b - s, I_{i-1}) || C#_{i-1}
/// O_i = SM4Encrypt(I_i, K)
/// C#_i = P#_i xor MSB(s, O_i)
/// ```
///
/// `encrypting` selects which of the two byte streams feeds the shift register: the ciphertext
/// segment, which is the output when encrypting and the input when decrypting.
fn reference_cfb8(
    key: &KeyMaterial<KEY_LEN>,
    iv: [u8; BLOCK_LEN],
    data: &mut [u8],
    encrypting: bool,
) {
    let sm4 = SM4::new(key).expect("a valid SM4 key");
    let mut i = iv;
    for byte in data.iter_mut() {
        let mut o = i;
        sm4.encrypt_block(&mut o);
        let input = *byte;
        // C#_i = P#_i xor MSB(8, O_i), one byte of the output block.
        *byte ^= o[0];
        let feedback = if encrypting { *byte } else { input };
        // I_{i+1} = LSB(b - 8, I_i) || C#_i: drop the top byte, append the ciphertext byte.
        i.rotate_left(1);
        i[BLOCK_LEN - 1] = feedback;
    }
}

/// `SM4_CFB8` agrees with the equations, both directions, at lengths either side of a block.
#[test]
fn the_cfb8_alias_agrees_with_the_equations() {
    let key = key_material(KEY_1);
    let iv = iv_bytes();

    for len in [0usize, 1, 2, 15, 16, 17, 33, 64] {
        let plaintext = filler(len, len as u32 + 7);

        let mut expected = plaintext.clone();
        reference_cfb8(&key, iv, &mut expected, true);

        let mut data = plaintext.clone();
        let (mut enc, got_iv) = SM4_CFB8::<Encrypting>::do_encrypt_init_rng(
            &key,
            &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
        )
        .expect("encryption init");
        assert_eq!(got_iv, iv);
        enc.do_encrypt(&mut data).expect("encryption");
        assert_eq!(data, expected, "len {len}: SM4_CFB8 encrypt should match the equations");

        let mut back = data.clone();
        reference_cfb8(&key, iv, &mut back, false);
        assert_eq!(back, plaintext, "len {len}: the reference decrypts its own output");

        SM4_CFB8::<Decrypting>::decrypt(&key, &iv, &mut data).expect("decryption");
        assert_eq!(data, plaintext, "len {len}: SM4_CFB8 decrypt should match");
    }
}
