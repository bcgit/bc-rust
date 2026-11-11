//! The concatenation KDF through the core KDF framework and its own contract: the counter and
//! truncation (SP 800-56C Rev. 2 Section 4.1 steps 3 to 7), the length bounds, the `_out` rule,
//! the entropy accounting, and `Z` as a concatenation.

use bouncycastle_concatkdf::{
    CONCAT_KDF_SHA3_256_NAME, CONCAT_KDF_SHA256_NAME, CONCAT_KDF_SHA512_256_NAME, ConcatKDF,
    ConcatKDF_SHA3_256, ConcatKDF_SHA256, ConcatKDF_SHA512, ConcatKDF_SHA512_256, ConcatKDFParams,
};
use bouncycastle_core::errors::KDFError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashOneShot, KDF};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};

/// ACVP KDA OneStep SP800-56Cr2 sample set, SHA2-512, tcId 126 (the file `concatkdf_acvp.rs`
/// reads from bc-test-data): FixedInfo is t || uPartyId || vPartyId || l, l = 1024 bits.
const Z: &str = "BFBFC3865A3656E9E88DBFC173C00A022B3F662D22B34C6F935552F50F79A4C8343D72BBE1781352C40A08F822824165FD400C14DA0EFA317BA4FE6E891BF3F086E143B52607433853403C1DE5C81491C3DC10036A2AAA78F298C325B067930027EDC0361405420E43763E8487EDC93FC9AED5";
const FIXED_INFO: &str = "1D1C1ADE471858BB681687AE92C4C30AEC97E754ABB2EFEC130831927011DABD8CAC0DFA1B9F2691160872C9B1B1DE4C00000400";
const DKM: &str = "1E4B837E62ED9851E986B6DCEBD0435FC693FFA72F630956EF6CA11D6C7E9DC1F430560F99E993864D4CC90D6DBE3AEB34A40867DBB65D8C5F093E9860F73A6BABBD3FF103E655BCCB744123465255A232331F5B726F2362667222572F081A6AD521F2D96B1FA5ECF1C056372795AD386C0B9129D77475538FFB3671AB2169AD";

fn z() -> KeyMaterial<128> {
    KeyMaterial::<128>::from_bytes_as_type(&hex_decode(Z).unwrap(), KeyType::SharedSecret).unwrap()
}

#[test]
fn acvp_vector() {
    let mut out = KeyMaterial::<128>::new();
    let info = hex_decode(FIXED_INFO).unwrap();
    assert_eq!(ConcatKDF_SHA512::derive_out(&z(), &info, 128, &mut out).unwrap(), 128);
    assert_eq!(out.ref_to_bytes(), hex_decode(DKM).unwrap().as_slice());
}

#[test]
fn core_framework_suites() {
    // The framework compares `derive_key` with a whole hash output, so the expected value is
    // the vector's first 64 bytes.
    let expected = KeyMaterial::<64>::from_bytes_as_type(
        &hex_decode(DKM).unwrap()[..64],
        KeyType::CryptographicRandom,
    )
    .unwrap();
    let info = hex_decode(FIXED_INFO).unwrap();
    let tf = TestFrameworkKDF::new();
    tf.test_kdf_single_key(&ConcatKDF_SHA512::new(), &z(), &info, &expected);

    // Z as two keys: the concatenation, so the same answer as one key of the joined bytes.
    let z_bytes = hex_decode(Z).unwrap();
    let a = KeyMaterial::<128>::from_bytes_as_type(&z_bytes[..40], KeyType::SharedSecret).unwrap();
    let b = KeyMaterial::<128>::from_bytes_as_type(&z_bytes[40..], KeyType::SharedSecret).unwrap();
    let keys: [&dyn KeyMaterialTrait; 2] = [&a, &b];
    tf.test_kdf_multiple_key(&ConcatKDF_SHA512::new(), &keys, &info, &expected);
}

/// Steps 3 to 7 by hand: K(i) = H(counter || Z || FixedInfo) with a 4-byte big-endian counter
/// from 1, and the output the leftmost L bits of K(1) || K(2) || ...
#[test]
fn matches_the_hash_of_counter_z_fixed_info() {
    let z = z();
    let info = b"fixed info";
    let mut by_hand = Vec::new();
    for counter in 1u32..=3 {
        let mut msg = counter.to_be_bytes().to_vec();
        msg.extend_from_slice(z.ref_to_bytes());
        msg.extend_from_slice(info);
        by_hand.extend_from_slice(&SHA256::hash(&msg));
    }
    for len in [1usize, 31, 32, 33, 64, 65, 96] {
        let mut out = KeyMaterial::<96>::new();
        assert_eq!(ConcatKDF_SHA256::derive_out(&z, info, len, &mut out).unwrap(), len);
        assert_eq!(out.key_len(), len);
        assert_eq!(out.ref_to_bytes(), &by_hand[..len], "L = {} bytes", len);
    }

    // and over SHA3-256, whose rate differs from its output length
    let mut msg = 1u32.to_be_bytes().to_vec();
    msg.extend_from_slice(z.ref_to_bytes());
    msg.extend_from_slice(info);
    let mut out = KeyMaterial::<32>::new();
    ConcatKDF_SHA3_256::derive_out(&z, info, 32, &mut out).unwrap();
    assert_eq!(out.ref_to_bytes(), SHA3_256::hash(&msg).as_slice());
}

/// Step 1 refuses L = 0, step 2 more than 2^32 - 1 blocks; and the buffer must hold L. Each
/// error leaves the buffer zeroized. The step 2 bound does not fit a 32-bit `usize`, so its
/// cases run on 64-bit only.
#[test]
fn length_bounds_are_refused_and_the_buffer_zeroized() {
    let z = z();
    let bound = usize::try_from(32u128 * 0xFFFF_FFFF).ok();
    let mut out = KeyMaterial::<64>::new();
    if let Some(bound) = bound {
        out.set_bytes_as_type(&[0xAA; 64], KeyType::CryptographicRandom).unwrap();
        assert!(matches!(
            ConcatKDF_SHA256::derive_out(&z, b"", bound + 1, &mut out),
            Err(KDFError::InvalidLength(m)) if m.contains("reps")
        ));
        assert_eq!(out.key_len(), 0);
        assert_eq!(out.key_type(), KeyType::Zeroized);
    }

    out.set_bytes_as_type(&[0xAA; 64], KeyType::CryptographicRandom).unwrap();
    assert!(matches!(
        ConcatKDF_SHA256::derive_out(&z, b"", 65, &mut out),
        Err(KDFError::InvalidLength(_))
    ));
    assert_eq!(out.key_len(), 0);

    out.set_bytes_as_type(&[0xAA; 64], KeyType::CryptographicRandom).unwrap();
    assert!(matches!(
        ConcatKDF_SHA256::derive_out(&z, b"", 0, &mut out),
        Err(KDFError::InvalidLength(_))
    ));
    assert_eq!(out.key_len(), 0);

    // exactly 2^32 - 1 blocks passes step 2, and the buffer check is what refuses it; where
    // the bound does not fit a usize, MAX_LEN saturates
    if let Some(bound) = bound {
        assert_eq!(ConcatKDF_SHA256::MAX_LEN, bound);
        assert!(matches!(
            ConcatKDF_SHA256::derive_out(&z, b"", bound, &mut out),
            Err(KDFError::InvalidLength(m)) if m.contains("buffer")
        ));
        assert_eq!(ConcatKDF::<SHA512>::MAX_LEN as u128, 64u128 * 0xFFFF_FFFF);
    } else {
        assert_eq!(ConcatKDF_SHA256::MAX_LEN, usize::MAX);
    }
}

/// The KDF trait's rule at the edge: a derivation from no keys is refused, while a key of
/// length zero is derived from, giving H(counter || FixedInfo) typed Unknown with no strength,
/// and beside a real key it adds nothing to the concatenation.
#[test]
fn no_keys_are_refused_and_an_empty_key_derives_unknown_output() {
    let none: [&dyn KeyMaterialTrait; 0] = [];
    let mut out = KeyMaterial::<32>::new();
    assert!(matches!(
        ConcatKDF_SHA256::new().derive_key_from_multiple_out(&none, b"", 32, &mut out),
        Err(KDFError::InvalidLength(m)) if m.contains("no keys")
    ));

    let empty = KeyMaterial::<32>::new();
    assert_eq!(ConcatKDF_SHA256::derive_out(&empty, b"", 32, &mut out).unwrap(), 32);
    assert_eq!(out.key_type(), KeyType::Unknown);
    assert_eq!(out.security_strength(), SecurityStrength::None);
    assert_eq!(out.ref_to_bytes(), &SHA256::hash(&1u32.to_be_bytes()));

    let z = z();
    let padded: [&dyn KeyMaterialTrait; 2] = [&empty, &z];
    assert_eq!(
        ConcatKDF_SHA256::new().derive_key_from_multiple_out(&padded, b"", 32, &mut out).unwrap(),
        32
    );
    assert!(out.equals(&*ConcatKDF_SHA256::new().derive_key(&z, b"", 32).unwrap()));
}

/// The output is credited only from typed full-entropy material of at least half a hash output,
/// at the least of Z's, the hash's and the length's strengths.
#[test]
fn entropy_accounting() {
    let info = b"";
    let mut out = KeyMaterial::<64>::new();

    // a 32-byte SharedSecret at 128 bits into SHA-256: CryptographicRandom at 128 bits
    let mut z =
        KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::SharedSecret).unwrap();
    bouncycastle_core::hazmat::do_hazardous_operations(&mut z, |z| {
        z.set_security_strength(SecurityStrength::_128bit)
    })
    .unwrap();
    ConcatKDF_SHA256::derive_out(&z, info, 32, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::CryptographicRandom);
    assert_eq!(out.security_strength(), SecurityStrength::_128bit);

    // the output length caps it: 8 bytes cannot carry 128 bits
    ConcatKDF_SHA256::derive_out(&z, info, 8, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::CryptographicRandom);
    assert_eq!(out.security_strength(), SecurityStrength::None);

    // a SharedSecret whose producer stated no strength credits nothing
    let unstated = z_unstated();
    ConcatKDF_SHA256::derive_out(&unstated, info, 32, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::Unknown);

    // the hash caps it: a 256-bit key into SHA-256 reports SHA-256's strength
    let strong =
        KeyMaterial::<64>::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::CryptographicRandom)
            .unwrap();
    ConcatKDF_SHA256::derive_out(&strong, info, 64, &mut out).unwrap();
    assert_eq!(out.security_strength(), SHA256::MAX_SECURITY_STRENGTH);
    ConcatKDF_SHA512::derive_out(&strong, info, 64, &mut out).unwrap();
    assert_eq!(out.security_strength(), SecurityStrength::_256bit);

    // below half a hash output of typed material: Unknown (32 bytes seed SHA-512, 31 do not)
    let short =
        KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..31], KeyType::CryptographicRandom)
            .unwrap();
    ConcatKDF_SHA512::derive_out(&short, info, 64, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::Unknown);
    assert_eq!(out.security_strength(), SecurityStrength::None);
    let just =
        KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::CryptographicRandom)
            .unwrap();
    ConcatKDF_SHA512::derive_out(&just, info, 64, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::CryptographicRandom);

    // two keys credit their sum: 16 + 16 bytes seed SHA-512 where neither does alone
    let half_a =
        KeyMaterial::<16>::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::CryptographicRandom)
            .unwrap();
    let half_b =
        KeyMaterial::<16>::from_bytes_as_type(&DUMMY_SEED[16..32], KeyType::CryptographicRandom)
            .unwrap();
    let keys: [&dyn KeyMaterialTrait; 2] = [&half_a, &half_b];
    ConcatKDF_SHA512::new().derive_key_from_multiple_out(&keys, info, 64, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::CryptographicRandom);
    ConcatKDF_SHA512::derive_out(&half_a, info, 64, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::Unknown);

    // Unknown-typed input is computed over but credits nothing
    let unknown =
        KeyMaterial::<64>::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::Unknown).unwrap();
    ConcatKDF_SHA256::derive_out(&unknown, info, 32, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::Unknown);
    assert_eq!(out.key_len(), 32);
}

fn z_unstated() -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::SharedSecret).unwrap()
}

/// The last block is truncated to what L leaves, into a buffer with no room beyond it.
#[test]
fn a_partial_last_block_fits_an_exact_buffer() {
    let z = z();
    let mut out = KeyMaterial::<33>::new();
    assert_eq!(ConcatKDF_SHA256::derive_out(&z, b"", 33, &mut out).unwrap(), 33);
    let mut longer = KeyMaterial::<64>::new();
    ConcatKDF_SHA256::derive_out(&z, b"", 64, &mut longer).unwrap();
    assert_eq!(out.ref_to_bytes(), &longer.ref_to_bytes()[..33]);
}

#[test]
fn fixed_info_selects_the_key() {
    let z = z();
    let a = ConcatKDF_SHA256::new().derive_key(&z, b"context a", 32).unwrap();
    let b = ConcatKDF_SHA256::new().derive_key(&z, b"context b", 32).unwrap();
    let none = ConcatKDF_SHA256::new().derive_key(&z, b"", 32).unwrap();
    assert_ne!(a.ref_to_bytes(), b.ref_to_bytes());
    assert_ne!(a.ref_to_bytes(), none.ref_to_bytes());
}

#[test]
fn names_strengths_and_output_lengths() {
    assert_eq!(ConcatKDF_SHA256::ALG_NAME, CONCAT_KDF_SHA256_NAME);
    assert_eq!(CONCAT_KDF_SHA256_NAME, "ConcatKDF-SHA256");
    assert_eq!(ConcatKDF_SHA512_256::ALG_NAME, CONCAT_KDF_SHA512_256_NAME);
    assert_eq!(ConcatKDF_SHA3_256::ALG_NAME, CONCAT_KDF_SHA3_256_NAME);
    assert_eq!(CONCAT_KDF_SHA3_256_NAME, "ConcatKDF-SHA3-256");
    assert_eq!(ConcatKDF_SHA256::MAX_SECURITY_STRENGTH, SHA256::MAX_SECURITY_STRENGTH);
    assert_eq!(ConcatKDF_SHA512::MAX_SECURITY_STRENGTH, SHA512::MAX_SECURITY_STRENGTH);
    one_block_is_one_hash::<SHA224>(28);
    one_block_is_one_hash::<SHA256>(32);
    one_block_is_one_hash::<SHA384>(48);
    one_block_is_one_hash::<SHA512>(64);
    one_block_is_one_hash::<SHA512_224>(28);
    one_block_is_one_hash::<SHA512_256>(32);
    one_block_is_one_hash::<SHA3_224>(28);
    one_block_is_one_hash::<SHA3_256>(32);
    one_block_is_one_hash::<SHA3_384>(48);
    one_block_is_one_hash::<SHA3_512>(64);
}

/// K(1) through the trait is `H(00000001 || Z)` with no FixedInfo, and the block is `len` long:
/// one byte more starts K(2), `H(00000002 || Z)`.
fn one_block_is_one_hash<H: ConcatKDFParams>(len: usize) {
    let z = z();
    let mut out = KeyMaterial::<128>::new();
    let kdf: &dyn KDF = &ConcatKDF::<H>::new();
    assert_eq!(kdf.derive_key_out(&z, b"", len + 1, &mut out).unwrap(), len + 1);
    let k = |counter: u32| {
        let mut msg = counter.to_be_bytes().to_vec();
        msg.extend_from_slice(z.ref_to_bytes());
        H::hash(&msg)
    };
    assert_eq!(&out.ref_to_bytes()[..len], k(1).as_slice(), "{}", kdf.alg_name());
    assert_eq!(out.ref_to_bytes()[len], k(2)[0], "{}", kdf.alg_name());
}
