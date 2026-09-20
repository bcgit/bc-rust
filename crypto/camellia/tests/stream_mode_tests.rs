//! Known-answer tests for the stream modes of operation over Camellia: CFB128 from OpenSSL's
//! vector file, CTR from RFC 5528, and CFB8 from the SP 800-38A equations for want of anything
//! published.
//!
//! RFC 3713 has no mode vectors at all (Sec 3 only assigns the `id-camellia*-cbc` identifiers), so
//! each mode is pinned against the best published source there is, and each source needs a
//! different amount of work to line up with these aliases:
//!
//! * **CFB128.** The `CAMELLIA-*-CFB` entries of OpenSSL's
//!   `test/recipes/30-test_evp_data/evpciph_camellia.txt` (OpenSSL 3.6.2), transcribed from the
//!   file. For each key length the four entries chain -- each `IV` is the previous `Ciphertext` --
//!   so they form one four-block CFB128 message under the IV `000102..0f`, which is what is checked
//!   here through the [`Camellia_CFB_128`] / `_192` / `_256` aliases. The plaintext blocks and the
//!   keys are NIST SP 800-38A Appendix F's.
//! * **CTR.** RFC 5528's nine Camellia-CTR test vectors (Sec 4.1). Its counter block is a 4-octet
//!   nonce, an 8-octet IV and a 4-octet block counter **starting at one**, where `Ctr` here takes a
//!   12-byte nonce and a counter starting at zero, so the published counter blocks are one step
//!   past the first block these aliases generate and cannot be reached through them. The vectors
//!   therefore pin [`reference_ctr`], written from the SP 800-38A Sec 6.5 equations over the
//!   permutation, and the aliases are then required to agree with that same reference on the
//!   counter blocks they do produce.
//! * **CFB8.** There is no published vector: the OpenSSL file says in as many words that it does
//!   not carry `CFB{1,8}-CAMELLIAxxx`. [`reference_cfb8`] evaluates the Sec 6.3 equations at
//!   `s = 8` over the permutation, and the aliases are held to it.
//!
//! Everything internal to the modes -- the counter increment, the short final block, the shift
//! register, the chunking -- is covered by the SP 800-38A and ACVP vectors in `bouncycastle-modes`.

mod common;

use bouncycastle_camellia::{
    BLOCK_LEN, CTR_NONCE_LEN, Camellia_128, Camellia_192, Camellia_256, Camellia_CFB_128,
    Camellia_CFB_192, Camellia_CFB_256, Camellia_CFB8_128, Camellia_CFB8_192, Camellia_CFB8_256,
    Camellia_CTR_128, Camellia_CTR_192, Camellia_CTR_256,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_modes::{Decrypting, Encrypting};
use common::bytes;

const KEY_128: &str = "2B7E151628AED2A6ABF7158809CF4F3C";
const KEY_192: &str = "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B";
const KEY_256: &str = "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4";

fn key_material<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&bytes::<N>(hex_str), KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

// ---- CFB128: the OpenSSL vectors, through the aliases ------------------------------------------

/// The IV of the first entry of every CFB chain.
const CFB_IV: &str = "000102030405060708090A0B0C0D0E0F";

/// SP 800-38A Appendix F's four plaintext blocks, concatenated.
const CFB_PT: &str = concat!(
    "6BC1BEE22E409F96E93D7E117393172A",
    "AE2D8A571E03AC9C9EB76FAC45AF8E51",
    "30C81C46A35CE411E5FBC1191A0A52EF",
    "F69F2445DF4F9B17AD2B417BE66C3710",
);

/// `CFB128-CAMELLIA128.Encrypt`, the four chained entries concatenated.
const CFB_CT_128: &str = concat!(
    "14F7646187817EB586599146B82BD719",
    "A53D28BB82DF741103EA4F921A44880B",
    "9C2157A664626D1DEF9EA420FDE69B96",
    "742A25F0542340C7BAEF24CA8482BB09",
);
/// `CFB128-CAMELLIA192.Encrypt`.
const CFB_CT_192: &str = concat!(
    "C832BB9780677DAA82D9B6860DCD565E",
    "86F8491627906D780C7A6D46EA331F98",
    "69511CCE594CF710CB98BB63D7221F01",
    "D5B5378A3ABED55803F25565D8907B84",
);
/// `CFB128-CAMELLIA256.Encrypt`.
const CFB_CT_256: &str = concat!(
    "CF6107BB0CEA7D7FB1BD31F5E7B06C93",
    "89BEDB4CCDD864EA11BA4CBE849B5E2B",
    "555FC3F34BDD2D54C62D9E3BF338C1C4",
    "5953ADCE14DB8C7F39F1BD39F359BFFA",
);

/// One key length's CFB128 vector: encrypted under the vector's own IV, in one call and then block
/// by block, and decrypted back both ways.
fn check_cfb<const KEY_LEN: usize, Enc, Dec>(name: &str, key_hex: &str, expected: &str)
where
    Enc: StreamCipherEncryptor<KEY_LEN, BLOCK_LEN>,
    Dec: StreamCipherDecryptor<KEY_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let iv = bytes::<BLOCK_LEN>(CFB_IV);
    let pt = bytes::<64>(CFB_PT);
    let ct = bytes::<64>(expected);

    // There is no API for supplying an IV, so pin the RNG to the vector's and check what came back.
    let (mut enc, got_iv) =
        Enc::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<BLOCK_LEN>::new(iv)).expect("enc init");
    assert_eq!(got_iv, iv, "{name}: the pinned RNG should produce the vector's IV");
    let mut data = pt;
    let written = enc.do_encrypt(&mut data).expect("encryption");
    assert_eq!(written, pt.len(), "{name}: a stream cipher writes exactly what it was given");
    assert_eq!(data, ct, "{name} encrypt, one call");

    let (mut enc, _) =
        Enc::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<BLOCK_LEN>::new(iv)).expect("enc init");
    let mut data = pt;
    for block in data.chunks_mut(BLOCK_LEN) {
        enc.do_encrypt(block).expect("encryption");
    }
    assert_eq!(data, ct, "{name} encrypt, one block at a time");

    let mut data = ct;
    Dec::decrypt(&key, &iv, &mut data).expect("decryption");
    assert_eq!(data, pt, "{name} decrypt, one shot");

    // Seven bytes at a time: a stream cipher must not care where the call boundaries fall.
    let mut dec = Dec::do_decrypt_init(&key, &iv).expect("dec init");
    let mut data = ct;
    for piece in data.chunks_mut(7) {
        dec.do_decrypt(piece).expect("decryption");
    }
    assert_eq!(data, pt, "{name} decrypt, seven bytes at a time");
}

#[test]
fn cfb128_camellia128_openssl_vectors() {
    check_cfb::<16, Camellia_CFB_128<Encrypting>, Camellia_CFB_128<Decrypting>>(
        "CFB128-CAMELLIA128", KEY_128, CFB_CT_128,
    );
}

#[test]
fn cfb128_camellia192_openssl_vectors() {
    check_cfb::<24, Camellia_CFB_192<Encrypting>, Camellia_CFB_192<Decrypting>>(
        "CFB128-CAMELLIA192", KEY_192, CFB_CT_192,
    );
}

#[test]
fn cfb128_camellia256_openssl_vectors() {
    check_cfb::<32, Camellia_CFB_256<Encrypting>, Camellia_CFB_256<Decrypting>>(
        "CFB128-CAMELLIA256", KEY_256, CFB_CT_256,
    );
}

// ---- CTR: RFC 5528's vectors, through a reference built from the equations ----------------------

/// CTR straight from SP 800-38A Sec 6.5, over an explicit initial counter block.
///
/// ```text
/// O_j = CIPH_K(T_j)
/// C_j = P_j XOR O_j                (j < n)
/// C*_n = P*_n XOR MSB_u(O_n)
/// ```
///
/// `t1` is `T_1` and each `T_{j+1}` is `T_j` incremented as a 128-bit big-endian integer, which is
/// what RFC 5528's "Counter Block (1) ... (2) ... (3)" listings show. Encryption and decryption are
/// the same operation, so one function serves both. `P` is the permutation, so the same body serves
/// all three key lengths.
fn reference_ctr<P, const KEY_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    t1: [u8; BLOCK_LEN],
    data: &mut [u8],
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let cipher = P::new(key).expect("a valid key");
    let mut t = t1;
    for chunk in data.chunks_mut(BLOCK_LEN) {
        // O_j = CIPH_K(T_j); a short final chunk takes MSB_u(O_n) by simply stopping early.
        let mut o = t;
        cipher.encrypt_block(&mut o);
        for (d, k) in chunk.iter_mut().zip(o.iter()) {
            *d ^= k;
        }
        // T_{j+1}: increment the whole block, carrying from the least significant byte.
        for b in t.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }
}

/// RFC 5528 Sec 4.1 TV #1..#9: `(key, initial counter block, plaintext, ciphertext)`, with the
/// counter block written out as `nonce || IV || 00000001` exactly as the RFC lists it.
type CtrVector = (&'static str, &'static str, &'static str, &'static str);

/// TV #1 to #3, 128-bit key.
const CTR_VECTORS_128: [CtrVector; 3] = [
    (
        "AE6852F8121067CC4BF7A5765577F39E",
        "00000030000000000000000000000001",
        "53696E676C6520626C6F636B206D7367",
        "D09DC29A8214619A20877C76DB1F0B3F",
    ),
    (
        "7E24067817FAE0D743D6CE1F32539163",
        "006CB6DBC0543B59DA48D90B00000001",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "DBF3C78DC08396D4DA7C907765BBCB442B8E8E0F31F0DCA72C7417E35360E048",
    ),
    (
        "7691BE035E5020A8AC6E618529F9A0DC",
        "00E0017B27777F3F4A1786F000000001",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223",
        "B19D1FCDCB75EB882F849CE24D85CF739CE64B2B5C9D73F14F2D5D9DCE9889CDDF508696",
    ),
];

/// TV #4 to #6, 192-bit key.
const CTR_VECTORS_192: [CtrVector; 3] = [
    (
        "16AF5B145FC9F579C175F93E3BFB0EED863D06CCFDB78515",
        "0000004836733C147D6D93CB00000001",
        "53696E676C6520626C6F636B206D7367",
        "2379399E8A8D2B2B16702FC78B9E9696",
    ),
    (
        "7C5CB2401B3DC33C19E7340819E0F69C678C3DB8E6F6A91A",
        "0096B03B020C6EADC2CB500D00000001",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "7DEF34F7A5D0E415674B7FFCAE67C75DD018B86FF23051E056392A99F35A4CED",
    ),
    (
        "02BF391EE8ECB159B959617B0965279BF59B60A786D3E0FE",
        "0007BDFD5CBD60278DCC091200000001",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223",
        "5710E556E1487A20B5AC0E73F19E4E7876F37FDC91B1EF4D4DADE8E666A64D0ED557AB57",
    ),
];

/// TV #7 to #9, 256-bit key.
const CTR_VECTORS_256: [CtrVector; 3] = [
    (
        "776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104",
        "00000060DB5672C97AA8F0B200000001",
        "53696E676C6520626C6F636B206D7367",
        "3401F9C8247EFFCEBD6994714C1BBB11",
    ),
    (
        "F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884",
        "00FAAC24C1585EF15A43D87500000001",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "D6C30392246F7808A83C2B22A8839E45E51CD48A1CDF406EBC9CC2D3AB834108",
    ),
    (
        "FF7A617CE69148E4F1726E2F43581DE2AA62D9F805532EDFF1EED687FB54153D",
        "001CC5B751A51D70A1C1114800000001",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223",
        "A4DA23FCE6A5FFAA6D64AE9A0652A42CD161A34B65F9679F75C01F101F71276F15EF0D8D",
    ),
];

/// The reference reproduces every RFC 5528 ciphertext, and is its own inverse. This is what pins
/// the reference; the aliases are then checked against it below.
fn check_ctr_vectors<P, const KEY_LEN: usize>(name: &str, vectors: &[CtrVector])
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    for (i, (key_hex, t1_hex, pt_hex, ct_hex)) in vectors.iter().enumerate() {
        let key = key_material::<KEY_LEN>(key_hex);
        let t1 = bytes::<BLOCK_LEN>(t1_hex);

        let mut data = hex_vec(pt_hex);
        reference_ctr::<P, KEY_LEN>(&key, t1, &mut data);
        assert_eq!(data, hex_vec(ct_hex), "{name} TV #{}: ciphertext", i + 1);

        reference_ctr::<P, KEY_LEN>(&key, t1, &mut data);
        assert_eq!(data, hex_vec(pt_hex), "{name} TV #{}: and back", i + 1);
    }
}

/// The RFC's values are 16, 32 and 36 bytes long, so they are decoded to a `Vec` rather than to the
/// fixed-size arrays `common::bytes` returns.
fn hex_vec(hex_str: &str) -> Vec<u8> {
    assert!(hex_str.len().is_multiple_of(2), "hex string must have even length");
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn rfc5528_ctr_vectors_pin_the_reference() {
    check_ctr_vectors::<Camellia_128, 16>("RFC 5528 Camellia-128-CTR", &CTR_VECTORS_128);
    check_ctr_vectors::<Camellia_192, 24>("RFC 5528 Camellia-192-CTR", &CTR_VECTORS_192);
    check_ctr_vectors::<Camellia_256, 32>("RFC 5528 Camellia-256-CTR", &CTR_VECTORS_256);
}

/// Each CTR alias agrees with the pinned reference on the counter blocks it does produce: the
/// 12-byte nonce followed by a four-byte counter starting at zero. Lengths cross the block boundary
/// and end on a short final block, which is where `MSB_u(O_n)` applies.
fn check_ctr_alias<P, const KEY_LEN: usize, Enc, Dec>(name: &str, key_hex: &str)
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
    Enc: StreamCipherEncryptor<KEY_LEN, CTR_NONCE_LEN>,
    Dec: StreamCipherDecryptor<KEY_LEN, CTR_NONCE_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let nonce = bytes::<CTR_NONCE_LEN>("000102030405060708090A0B");

    // The counter block the alias starts from: the nonce, then four zero bytes.
    let mut t1 = [0u8; BLOCK_LEN];
    t1[..CTR_NONCE_LEN].copy_from_slice(&nonce);

    let mut seed = 0xC0FFEEu32;
    for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 129] {
        let plaintext: Vec<u8> =
            (0..len).map(|_| common::pseudo_random::<1>(&mut seed)[0]).collect();

        let mut expected = plaintext.clone();
        reference_ctr::<P, KEY_LEN>(&key, t1, &mut expected);

        let mut data = plaintext.clone();
        let (mut enc, got) =
            Enc::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<CTR_NONCE_LEN>::new(nonce))
                .expect("enc init");
        assert_eq!(got, nonce, "{name}: the pinned RNG should produce the chosen nonce");
        enc.do_encrypt(&mut data).expect("encryption");
        assert_eq!(data, expected, "{name}, len {len}: should match the reference");

        Dec::decrypt(&key, &nonce, &mut data).expect("decryption");
        assert_eq!(data, plaintext, "{name}, len {len}: round trip");
    }
}

#[test]
fn the_ctr_aliases_agree_with_the_reference() {
    check_ctr_alias::<Camellia_128, 16, Camellia_CTR_128<Encrypting>, Camellia_CTR_128<Decrypting>>(
        "Camellia_CTR_128", KEY_128,
    );
    check_ctr_alias::<Camellia_192, 24, Camellia_CTR_192<Encrypting>, Camellia_CTR_192<Decrypting>>(
        "Camellia_CTR_192", KEY_192,
    );
    check_ctr_alias::<Camellia_256, 32, Camellia_CTR_256<Encrypting>, Camellia_CTR_256<Decrypting>>(
        "Camellia_CTR_256", KEY_256,
    );
}

// ---- CFB8: the Sec 6.3 equations at s = 8 -------------------------------------------------------

/// CFB straight from SP 800-38A Sec 6.3 with `s = 8`, one byte per forward cipher call.
///
/// ```text
/// I_1 = IV
/// I_j = LSB_{b-s}(I_{j-1}) | C#_{j-1}
/// O_j = CIPH_K(I_j)
/// C#_j = P#_j XOR MSB_s(O_j)
/// ```
///
/// `encrypting` selects which of the two byte streams feeds the shift register: the ciphertext
/// segment, which is the output when encrypting and the input when decrypting.
fn reference_cfb8<P, const KEY_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    iv: [u8; BLOCK_LEN],
    data: &mut [u8],
    encrypting: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let cipher = P::new(key).expect("a valid key");
    let mut i = iv;
    for byte in data.iter_mut() {
        let mut o = i;
        cipher.encrypt_block(&mut o);
        let input = *byte;
        // C#_j = P#_j XOR MSB_8(O_j), one byte of the output block.
        *byte ^= o[0];
        let feedback = if encrypting { *byte } else { input };
        // I_{j+1} = LSB_{b-8}(I_j) | C#_j: drop the top byte, append the ciphertext byte.
        i.rotate_left(1);
        i[BLOCK_LEN - 1] = feedback;
    }
}

/// Each CFB8 alias agrees with the equations, both directions, at lengths either side of a block.
fn check_cfb8<P, const KEY_LEN: usize, Enc, Dec>(name: &str, key_hex: &str)
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
    Enc: StreamCipherEncryptor<KEY_LEN, BLOCK_LEN>,
    Dec: StreamCipherDecryptor<KEY_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let iv = bytes::<BLOCK_LEN>(CFB_IV);

    let mut seed = 0x5EEDu32;
    for len in [0usize, 1, 2, 15, 16, 17, 33, 64] {
        let plaintext: Vec<u8> =
            (0..len).map(|_| common::pseudo_random::<1>(&mut seed)[0]).collect();

        let mut expected = plaintext.clone();
        reference_cfb8::<P, KEY_LEN>(&key, iv, &mut expected, true);

        let mut data = plaintext.clone();
        let (mut enc, got_iv) =
            Enc::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<BLOCK_LEN>::new(iv))
                .expect("enc init");
        assert_eq!(got_iv, iv);
        enc.do_encrypt(&mut data).expect("encryption");
        assert_eq!(data, expected, "{name}, len {len}: encrypt should match the equations");

        let mut back = data.clone();
        reference_cfb8::<P, KEY_LEN>(&key, iv, &mut back, false);
        assert_eq!(back, plaintext, "{name}, len {len}: the reference decrypts its own output");

        Dec::decrypt(&key, &iv, &mut data).expect("decryption");
        assert_eq!(data, plaintext, "{name}, len {len}: decrypt should match");
    }
}

#[test]
fn the_cfb8_aliases_agree_with_the_equations() {
    check_cfb8::<Camellia_128, 16, Camellia_CFB8_128<Encrypting>, Camellia_CFB8_128<Decrypting>>(
        "Camellia_CFB8_128", KEY_128,
    );
    check_cfb8::<Camellia_192, 24, Camellia_CFB8_192<Encrypting>, Camellia_CFB8_192<Decrypting>>(
        "Camellia_CFB8_192", KEY_192,
    );
    check_cfb8::<Camellia_256, 32, Camellia_CFB8_256<Encrypting>, Camellia_CFB8_256<Decrypting>>(
        "Camellia_CFB8_256", KEY_256,
    );
}
