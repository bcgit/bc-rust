//! XTS-AES through its public API: known answers at the data-unit lengths that matter -- one
//! block, the ciphertext-stealing edges, a sector and the 2^20-block maximum -- from OpenSSL, an
//! independent implementation; every block of a data unit against a reference written here from
//! the definition (IEEE 1619-2007 Sec 5.2 and 5.3), which pins the roles of the two key halves,
//! the byte order of the tweak and the multiplication by α; round trips at every length from one
//! block to eight and a half; the refusal of a data unit outside the bounds at both key sizes;
//! and the key constructor's refusals.
//!
//! The published vectors are in `aes_xts_acvp_tests.rs` and `aes_xts_wycheproof.rs`. The bounds on
//! the data-unit length are tested at both ends over a toy permutation in
//! `crypto/symmetric/tests/modes/xts_tests.rs`.

use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{BlockPermutation, KeyExpansion};
use bouncycastle_core::hex;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_symmetric::aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_symmetric::aes::{XTS_AES_128, XTS_AES_256};
use bouncycastle_symmetric::modes::{
    XTS_MAX_DATA_UNIT_LEN, XTS_MIN_DATA_UNIT_LEN, XTS_TWEAK_LEN, XTSKey,
};

/// The tweak of the known answers below.
const TWEAK: [u8; 16] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
];

/// `Key_1 | Key_2` of the known answers: 0x01, 0x02, .., so the halves differ.
fn key_bytes<const KEY_LEN: usize>() -> [u8; KEY_LEN] {
    core::array::from_fn(|i| i as u8 + 1)
}

/// The plaintext of the known answers: byte k of a data unit is k mod 251.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|k| (k % 251) as u8).collect()
}

fn material<const KEY_LEN: usize>(bytes: &[u8]) -> KeyMaterial<KEY_LEN> {
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn xts_key<P, const KEY_LEN: usize>(bytes: &[u8; KEY_LEN]) -> XTSKey<P>
where
    XTSKey<P>: FromKeyMaterial<KEY_LEN>,
{
    XTSKey::<P>::from_key_material(&material(bytes)).expect("a valid XTS key")
}

// ---- known answers from OpenSSL ----------------------------------------------------------------

/// The first n bytes of `pattern` under `key_bytes()` and `TWEAK` encrypt to `ct`, and back.
fn kat<P, const KEY_LEN: usize>(n: usize, ct: &str)
where
    P: BlockPermutation<16>,
    XTSKey<P>: FromKeyMaterial<KEY_LEN>,
{
    let key = xts_key::<P, KEY_LEN>(&key_bytes());
    let pt = pattern(n);
    let ct = hex::decode(ct).unwrap();
    assert_eq!(ct.len(), n, "the table's {n}-byte ciphertext");

    let mut data_unit = pt.clone();
    assert_eq!(key.encrypt_inplace(&TWEAK, &mut data_unit), Ok(n));
    assert_eq!(data_unit, ct, "{n}-byte data unit: encryption");
    let mut data_unit = ct;
    assert_eq!(key.decrypt_inplace(&TWEAK, &mut data_unit), Ok(n));
    assert_eq!(data_unit, pt, "{n}-byte data unit: decryption");
}

/// The lengths of the tables below: one block, one block and one byte, one byte short of two,
/// two, two and a byte, six and a quarter, one byte short of eight, and a 512-byte sector.
#[test]
fn xts_aes_128_matches_openssl() {
    for &(n, ct) in KATS_128 {
        kat::<AES128Internal, 32>(n, ct);
    }
}

#[test]
fn xts_aes_256_matches_openssl() {
    for &(n, ct) in KATS_256 {
        kat::<AES256Internal, 64>(n, ct);
    }
}

/// A long known answer: a 16-byte fold of the ciphertext (`fold[k % 16] ^= ct[k]` over every
/// byte, so any wrong block shows), its first block and its last 32 bytes.
struct LongKat {
    fold: &'static str,
    first: &'static str,
    last: &'static str,
}

/// The longest data units against OpenSSL: the mask chain runs to α^(2^20 - 1), and one byte
/// short of the limit a ciphertext block is stolen at the far end.
fn long_kat<P, const KEY_LEN: usize>(n: usize, expected: &LongKat)
where
    P: BlockPermutation<16>,
    XTSKey<P>: FromKeyMaterial<KEY_LEN>,
{
    let key = xts_key::<P, KEY_LEN>(&key_bytes());
    let pt = pattern(n);
    let mut data_unit = pt.clone();

    assert_eq!(key.encrypt_inplace(&TWEAK, &mut data_unit), Ok(n));
    let mut fold = [0u8; 16];
    for (k, byte) in data_unit.iter().enumerate() {
        fold[k % 16] ^= byte;
    }
    assert_eq!(hex::encode(fold), expected.fold, "{n} bytes: the fold of the ciphertext");
    assert_eq!(hex::encode(&data_unit[..16]), expected.first, "{n} bytes: the first block");
    assert_eq!(hex::encode(&data_unit[n - 32..]), expected.last, "{n} bytes: the last 32 bytes");

    assert_eq!(key.decrypt_inplace(&TWEAK, &mut data_unit), Ok(n));
    assert!(data_unit == pt, "{n} bytes: decryption restores the plaintext");
}

// The two longest data units, each key size and each end of a maximal data unit once, are two
// tests so that the test harness runs them in parallel: each takes several seconds in a debug
// build.

/// 2^20 blocks under XTS-AES-128: the longest data unit there is.
#[test]
fn the_longest_data_unit_matches_openssl() {
    long_kat::<AES128Internal, 32>(XTS_MAX_DATA_UNIT_LEN, &LONG_128_MAX);
}

/// One byte short of 2^20 blocks under XTS-AES-256: the last whole block is stolen from.
#[test]
fn one_byte_short_of_the_longest_data_unit_matches_openssl() {
    long_kat::<AES256Internal, 64>(XTS_MAX_DATA_UNIT_LEN - 1, &LONG_256_MAX_MINUS_1);
}

// ---- the definition, block by block ------------------------------------------------------------

/// `T ⊗ α` (IEEE 1619-2007 Sec 5.2) written independently of the implementation: the block as a
/// 128-bit little-endian integer, shifted left one bit, with x^128 reduced to x^7 + x^2 + x + 1
/// (0x87).
fn times_alpha(t: [u8; 16]) -> [u8; 16] {
    let x = u128::from_le_bytes(t);
    let reduction = if x >> 127 == 1 { 0x87 } else { 0 };
    ((x << 1) ^ reduction).to_le_bytes()
}

/// Every block of an aligned data unit is `C_j = E_K1(P_j ^ T_j) ^ T_j` with
/// `T_j = E_K2(i) ⊗ α^j` (IEEE 1619-2007 Sec 5.3.1), computed here through the raw permutation
/// from the halves of the key: the first half encrypts the data, the second the tweak, and the
/// tweak goes in as given.
fn follows_the_definition<P, const HALF: usize, const KEY_LEN: usize>()
where
    P: KeyExpansion<HALF> + BlockPermutation<16>,
    XTSKey<P>: FromKeyMaterial<KEY_LEN>,
{
    let key_bytes = key_bytes::<KEY_LEN>();
    let key1 = P::new(&material::<HALF>(&key_bytes[..HALF])).unwrap();
    let key2 = P::new(&material::<HALF>(&key_bytes[HALF..])).unwrap();

    let pt: [u8; 512] = pattern(512).try_into().unwrap();
    let mut expected = pt;
    let mut t = TWEAK;
    key2.encrypt_block(&mut t);
    for block in expected.as_chunks_mut::<16>().0 {
        for (b, m) in block.iter_mut().zip(&t) {
            *b ^= m;
        }
        key1.encrypt_block(block);
        for (b, m) in block.iter_mut().zip(&t) {
            *b ^= m;
        }
        t = times_alpha(t);
    }

    let key = xts_key::<P, KEY_LEN>(&key_bytes);
    let mut data_unit = pt;
    assert_eq!(key.encrypt_inplace(&TWEAK, &mut data_unit), Ok(512));
    assert_eq!(data_unit, expected);
}

#[test]
fn every_block_follows_the_definition() {
    follows_the_definition::<AES128Internal, 16, 32>();
    follows_the_definition::<AES256Internal, 32, 64>();
}

#[test]
fn the_reference_multiplication_reduces() {
    // x^127 * x = x^128 = x^7 + x^2 + x + 1, and the low bits shift up without a reduction.
    let mut top = [0u8; 16];
    top[15] = 0x80;
    let mut reduced = [0u8; 16];
    reduced[0] = 0x87;
    assert_eq!(times_alpha(top), reduced);
    let mut one = [0u8; 16];
    one[0] = 0x01;
    let mut two = [0u8; 16];
    two[0] = 0x02;
    assert_eq!(times_alpha(one), two);
}

// ---- round trips and tweaks --------------------------------------------------------------------

fn round_trip(n: usize) {
    let pt = pattern(n);
    let k128 = xts_key::<AES128Internal, 32>(&key_bytes());
    let k256 = xts_key::<AES256Internal, 64>(&key_bytes());

    let mut a = pt.clone();
    assert_eq!(k128.encrypt_inplace(&TWEAK, &mut a), Ok(n));
    assert_ne!(a, pt, "{n} bytes: XTS-AES-128 changed nothing");
    assert_eq!(k128.decrypt_inplace(&TWEAK, &mut a), Ok(n));
    assert_eq!(a, pt, "{n} bytes: XTS-AES-128 round trip");

    let mut b = pt.clone();
    assert_eq!(k256.encrypt_inplace(&TWEAK, &mut b), Ok(n));
    assert_ne!(b, pt, "{n} bytes: XTS-AES-256 changed nothing");
    assert_eq!(k256.decrypt_inplace(&TWEAK, &mut b), Ok(n));
    assert_eq!(b, pt, "{n} bytes: XTS-AES-256 round trip");
}

/// Every length from one block to one byte short of nine: every tail length, and every way the
/// blocks before it divide into fours, twos and ones, in both directions.
#[test]
fn round_trips_at_every_length_up_to_nine_blocks() {
    for n in 16..144 {
        round_trip(n);
    }
}

/// A tweak that differs in any one bit, the first or the last, gives a ciphertext that differs in
/// every block, including the stolen one.
fn every_tweak_bit_matters(n: usize) {
    let key = xts_key::<AES128Internal, 32>(&key_bytes());
    let pt = pattern(n);
    let mut base = pt.clone();
    key.encrypt_inplace(&TWEAK, &mut base).unwrap();
    for bit in [0, 127] {
        let mut tweak = TWEAK;
        tweak[bit / 8] ^= 1 << (bit % 8);
        let mut other = pt.clone();
        key.encrypt_inplace(&tweak, &mut other).unwrap();
        for (j, (a, b)) in base.chunks(16).zip(other.chunks(16)).enumerate() {
            assert_ne!(a, b, "{n} bytes, tweak bit {bit}: block {j} did not change");
        }
        // And it does not decrypt under the original tweak.
        key.decrypt_inplace(&TWEAK, &mut other).unwrap();
        assert_ne!(other, pt);
    }
}

#[test]
fn every_tweak_bit_matters_to_every_block() {
    for n in [16, 17, 47, 512] {
        every_tweak_bit_matters(n);
    }
}

/// Consecutive sequence numbers, `n.to_le_bytes()`, are distinct tweaks: equal sectors under
/// them encrypt differently, and each decrypts only under its own.
#[test]
fn consecutive_sequence_numbers_encrypt_equal_sectors_differently() {
    let key = xts_key::<AES256Internal, 64>(&key_bytes());
    let sector = [0x11u8; 512];
    let mut s0 = sector;
    let mut s1 = sector;
    key.encrypt_inplace(&0u128.to_le_bytes(), &mut s0).unwrap();
    key.encrypt_inplace(&1u128.to_le_bytes(), &mut s1).unwrap();
    assert_ne!(s0, s1);
    key.decrypt_inplace(&1u128.to_le_bytes(), &mut s1).unwrap();
    assert_eq!(s1, sector);
}

/// Equal plaintext blocks at different positions in one data unit encrypt differently: each
/// position has its own mask.
#[test]
fn equal_blocks_encrypt_differently_at_every_position() {
    let key = xts_key::<AES128Internal, 32>(&key_bytes());
    let mut data_unit = [0u8; 512];
    key.encrypt_inplace(&TWEAK, &mut data_unit).unwrap();
    let (blocks, _) = data_unit.as_chunks::<16>();
    for i in 0..blocks.len() {
        for j in i + 1..blocks.len() {
            assert_ne!(blocks[i], blocks[j], "blocks {i} and {j}");
        }
    }
}

// ---- the key -----------------------------------------------------------------------------------

/// The construction suite -- key type, strength and `generate` -- at both key sizes. Each half
/// carries the key's strength, capped at its own length, so XTS-AES-128 takes a key of 128 bits
/// and up and XTS-AES-256 only one of 256: a 192-bit key, whose halves alone would have been
/// credited 256 bits each, is refused.
#[test]
fn the_keys_enforce_the_material_policy() {
    let framework = TestFrameworkFromKeyMaterial::new();
    framework.test::<32, XTS_AES_128>("XTS_AES_128", SecurityStrength::_128bit);
    framework.test::<64, XTS_AES_256>("XTS_AES_256", SecurityStrength::_256bit);
}

// The refusals of the 32-byte key -- equal halves, a zero half, a short key -- are tested over
// the toy permutation in `crypto/symmetric/tests/modes/xts_tests.rs`, since that path is generic.
// The 64-byte key is a second impl, which only a permutation with a 32-byte key reaches.

fn refusal_256(key: &KeyMaterial<64>) -> KeyMaterialError {
    match XTS_AES_256::from_key_material(key) {
        Err(SymmetricCipherError::KeyMaterialError(e)) => e,
        Err(e) => panic!("refused, but not as a KeyMaterialError: {e:?}"),
        Ok(_) => panic!("accepted"),
    }
}

/// FIPS 140-3 IG C.I: Key_1 = Key_2 is refused; halves that differ in their last byte are not.
#[test]
fn xts_aes_256_refuses_equal_halves() {
    let mut bytes: [u8; 64] = core::array::from_fn(|i| (i % 32) as u8 + 0x40);
    assert!(matches!(refusal_256(&material(&bytes)), KeyMaterialError::GenericError(_)));
    bytes[63] ^= 0x01;
    XTS_AES_256::from_key_material(&material(&bytes)).expect("halves that differ");
}

/// A half that is all zeros is refused, as an all-zero AES key is; so is an all-zero key.
#[test]
fn xts_aes_256_refuses_zero_halves() {
    let mut low_zero = key_bytes::<64>();
    low_zero[..32].fill(0);
    let mut high_zero = key_bytes::<64>();
    high_zero[32..].fill(0);
    for bytes in [low_zero, high_zero, [0u8; 64]] {
        assert!(matches!(refusal_256(&material(&bytes)), KeyMaterialError::InvalidKeyType(_)));
    }
}

/// A `KeyMaterial<64>` holding fewer than 64 bytes is refused rather than split short.
#[test]
fn xts_aes_256_refuses_a_short_key() {
    for len in [32, 63] {
        let short = material::<64>(&key_bytes::<64>()[..len]);
        assert_eq!(short.key_len(), len);
        assert_eq!(refusal_256(&short), KeyMaterialError::InvalidLength);
    }
}

/// Swapping the halves gives another key: the order of `Key_1 | Key_2` matters.
#[test]
fn swapping_the_halves_changes_the_ciphertext() {
    let bytes = key_bytes::<32>();
    let mut swapped = [0u8; 32];
    swapped[..16].copy_from_slice(&bytes[16..]);
    swapped[16..].copy_from_slice(&bytes[..16]);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    xts_key::<AES128Internal, 32>(&bytes).encrypt_inplace(&TWEAK, &mut a).unwrap();
    xts_key::<AES128Internal, 32>(&swapped).encrypt_inplace(&TWEAK, &mut b).unwrap();
    assert_ne!(a, b);
}

// ---- the length of a data unit -----------------------------------------------------------------

/// Under either key, a data unit shorter than one block or longer than 2^20 blocks is refused in
/// both directions and left as it was. (That the bounds themselves are accepted is in the known
/// answers: 16 bytes in the tables, 2^20 blocks in the longest.)
fn refuses_out_of_bounds<P, const KEY_LEN: usize>()
where
    P: BlockPermutation<16>,
    XTSKey<P>: FromKeyMaterial<KEY_LEN>,
{
    let key = xts_key::<P, KEY_LEN>(&key_bytes());
    for len in [0, XTS_MIN_DATA_UNIT_LEN - 1, XTS_MAX_DATA_UNIT_LEN + 1] {
        let original = pattern(len);
        let mut data_unit = original.clone();
        let refusals = [
            key.encrypt_inplace(&TWEAK, &mut data_unit),
            key.decrypt_inplace(&TWEAK, &mut data_unit),
        ];
        for refusal in refusals {
            match refusal {
                Err(SymmetricCipherError::InvalidInputLength(_)) => {
                    assert!(len < XTS_MIN_DATA_UNIT_LEN)
                }
                Err(SymmetricCipherError::DataLimitExceeded) => {
                    assert!(len > XTS_MAX_DATA_UNIT_LEN)
                }
                other => panic!("{len} bytes: {other:?}"),
            }
        }
        assert!(data_unit == original, "{len} bytes: the refused data unit was changed");
    }
}

#[test]
fn data_units_outside_the_bounds_are_refused() {
    refuses_out_of_bounds::<AES128Internal, 32>();
    refuses_out_of_bounds::<AES256Internal, 64>();
}

#[test]
fn sizes() {
    assert_eq!(XTS_TWEAK_LEN, 16);
    assert_eq!(XTS_MIN_DATA_UNIT_LEN, 16);
    assert_eq!(XTS_MAX_DATA_UNIT_LEN, 1 << 24);
    // A key is its two schedules.
    assert_eq!(size_of::<XTS_AES_128>(), 2 * size_of::<AES128Internal>());
    assert_eq!(size_of::<XTS_AES_128>(), 352);
    assert_eq!(size_of::<XTS_AES_256>(), 2 * size_of::<AES256Internal>());
    assert_eq!(size_of::<XTS_AES_256>(), 480);
}

// ---- the known answers -------------------------------------------------------------------------

/// XTS-AES-128 under `key_bytes()` and `TWEAK`: the ciphertext of the first n bytes of the
/// plaintext pattern, from OpenSSL 3.5.0.
const KATS_128: &[(usize, &str)] = &[
    (16, "b9606f8b4bcb9a6990a511c8e0b07aa6"),
    (17, "600a1d04fddaccc03a7eb3687c450a2bb9"),
    (31, "8abf6bf2f845d0e8d197131cfe1a842fb9606f8b4bcb9a6990a511c8e0b07a"),
    (32, "b9606f8b4bcb9a6990a511c8e0b07aa651198810b01418fe0f857794c51ea98b"),
    (33, "b9606f8b4bcb9a6990a511c8e0b07aa60b714d7e049f4e0b43da3efbda03aa4751"),
    (
        100,
        "\
        b9606f8b4bcb9a6990a511c8e0b07aa651198810b01418fe0f857794c51ea98bc7e6973e0d79338c49e251f1\
        0d070cceabc1a661121126f5eec5383cdea365a3146e37b0240045b381065b471f9fdcab78418073ac951418\
        a9dc9566a7993aafb7612495",
    ),
    (
        127,
        "\
        b9606f8b4bcb9a6990a511c8e0b07aa651198810b01418fe0f857794c51ea98bc7e6973e0d79338c49e251f1\
        0d070cceabc1a661121126f5eec5383cdea365a3146e37b0240045b381065b471f9fdcabb761249542b8a235\
        2ed012acd8eea817edf246aa1eb3e666684e309ddf13d983ef5a745062853be226bd41f9405f5a",
    ),
    (
        512,
        "\
        b9606f8b4bcb9a6990a511c8e0b07aa651198810b01418fe0f857794c51ea98bc7e6973e0d79338c49e251f1\
        0d070cceabc1a661121126f5eec5383cdea365a3146e37b0240045b381065b471f9fdcabb761249542b8a235\
        2ed012acd8eea817ef5a745062853be226bd41f9405f5a4c7a10be827fbf65207ac6c2ec18f0a7e802e8b89a\
        6fdf1f2abcd8ba286a1d2a4682d1dc7a0a9883a5826b27e25e9434403d23eb94772498382c12ad7ec2af78ac\
        0b28f092ec6a006311876eaa9ccbb3c15546163aba18b425f7a69f327c2207f31f1d6fe8aa7e7af6a0d72904\
        db44f0a930079b3009b562a10d84b6b66bfbfc0858c55f3de1d03ca687977654f59d52761e8b0d05f241d465\
        c4a05d31de4267786f1e652b9076c855e24a0aebac08ae210d3fdc3d8d3665f7956bddd09492ba00e82cd3ca\
        f5afd5c3dc4301fbcc7c41beaee8c15c0a001bd4d91471debdba432edb58aa65b76c22151837166fa4026f96\
        edef9cb64e9bacd8fc50ac0bbf2e21de677e97e194550e82a94eb40b52079cc7a61eb62f41560ab5c10c3c8c\
        91bf50fc873dfced13548ef97cb7a0fb67d1cc676deb9d95c597c70cf31aa75305a19d0a5bb6bb5b1fbfe96d\
        1ff8fc1009fd005aa37700c7d392e116454ff9a63054e24ffe637ca825d002dcd6f8791ae09d1b1ff47d6467\
        859b134958f1504d4f19524687d16d4fe39d8f3c3c812695dcfbd91e",
    ),
];

/// XTS-AES-256 under `key_bytes()` and `TWEAK`: the ciphertext of the first n bytes of the
/// plaintext pattern, from OpenSSL 3.5.0.
const KATS_256: &[(usize, &str)] = &[
    (16, "965c8f85ac79930ac1e8b46eb069dbe9"),
    (17, "511ccdf0179233d1b03cd6e456946fb396"),
    (31, "21ddbfd72ea45ba2b73f3bdce151f185965c8f85ac79930ac1e8b46eb069db"),
    (32, "965c8f85ac79930ac1e8b46eb069dbe922edacc9dbfef62297d5914211e9ca91"),
    (33, "965c8f85ac79930ac1e8b46eb069dbe976c2f1565310895c5157328752138c0722"),
    (
        100,
        "\
        965c8f85ac79930ac1e8b46eb069dbe922edacc9dbfef62297d5914211e9ca91b9457eb11290a93c9b93e731\
        3b216008b5e4d99c52fe03c212f33964308ab8479fa6780a252c63c8b743c43d84a7539de8b3c26a9eaea33e\
        fea73210036bda48b466bdb7",
    ),
    (
        127,
        "\
        965c8f85ac79930ac1e8b46eb069dbe922edacc9dbfef62297d5914211e9ca91b9457eb11290a93c9b93e731\
        3b216008b5e4d99c52fe03c212f33964308ab8479fa6780a252c63c8b743c43d84a7539db466bdb79fd42757\
        f87fd0ed84ace41de0516f856e20c23269c7080dcb0d753834a93c3047f0edf9667a3673f42262",
    ),
    (
        512,
        "\
        965c8f85ac79930ac1e8b46eb069dbe922edacc9dbfef62297d5914211e9ca91b9457eb11290a93c9b93e731\
        3b216008b5e4d99c52fe03c212f33964308ab8479fa6780a252c63c8b743c43d84a7539db466bdb79fd42757\
        f87fd0ed84ace41d34a93c3047f0edf9667a3673f42262a4710cf8198821cff11d82c0388b9c5103cbf0a19f\
        9b5167dfde5f96d12dcd967fdcb8ab03ea121c2c38a73c7c3d76f528642729af955c56166e9ee33d258a389c\
        580d9b30945123718fdeef00abca17a80f102b67edce7221c154c4856ae81b0c477e8123e039b078bd0609a2\
        68be561fce28d44cf9b6603a8db1fd70e2c46bf9d055f82a3518a41d647ee247594018b8760751baa729648e\
        f327f2150d4aa3b2443de64e56005e08244206ad9d3b5e55b3e53f41923227759dc6dad27fe2fce5733b37f1\
        bac14a1984b7019e479c4f1886892ba062ce295e95c27694884b9943506a804c03e5cf020f168335b3b1f6af\
        2617de1dfb9debee13ef413c6c4fefcb718e4216201a923d8d7315a832797b226f79caec0a0df5e186ba800d\
        41ccefb8cbde407967a29c2f9ccccb2642243fee94b96b739ea11df9cf3c7dc10396ca0f270671f0d7312c50\
        06c52647b4cbddec2f00cea49f46978aab29e23285fb3d7c74e78589476552c44395b19739f900e161102f0e\
        9dbdcdd4821d60f2b3ea839cff6330cee358a6b8e3d8376df070295e",
    ),
];

/// XTS-AES-128, 2^24 bytes, from OpenSSL 3.5.0.
const LONG_128_MAX: LongKat = LongKat {
    fold: "f74540d435c8ba594a381d4687ffd9fb",
    first: "b9606f8b4bcb9a6990a511c8e0b07aa6",
    last: "64ccf3f477de47b98f4ad98fa299e0ac57ec5f4034d784657408ed62efb09ba5",
};

/// XTS-AES-256, 2^24 - 1 bytes, from OpenSSL 3.5.0.
const LONG_256_MAX_MINUS_1: LongKat = LongKat {
    fold: "d0f491c9ba261270a3b6e04b1fb47c6d",
    first: "965c8f85ac79930ac1e8b46eb069dbe9",
    last: "374c504dc69fa3f993be5c65153ac1e0a2b0dd68843f9d8bef7a4e52bfb4272c",
};
