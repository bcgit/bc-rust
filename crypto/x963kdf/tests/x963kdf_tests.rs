//! The X9.63 KDF through the core KDF framework and its own contract: the counter and
//! truncation (SEC 1 v2 Section 3.6.1 steps 3 to 5), the length bound, the `_out` rule, the
//! entropy accounting, and `Z` as a concatenation.

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial512, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashOneShot, KDF};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sha2::{SHA256, SHA512};
use bouncycastle_x963kdf::{
    X963KDF_SHA224, X963KDF_SHA256, X963KDF_SHA256_NAME, X963KDF_SHA384, X963KDF_SHA512,
    X963KDF_SHA512_NAME,
};

/// CAVP `ansx963_2001.rsp`, `[SHA-256]`, shared secret 192 bits, SharedInfo 128 bits, key data
/// 1024 bits, COUNT = 0 (the same vector `x963kdf_cavp.rs` reads from bc-test-data).
const Z: &str = "22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d";
const SHARED_INFO: &str = "75eef81aa3041e33b80971203d2c0c52";
const KEY_DATA: &str = "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21";

fn z() -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(&hex_decode(Z).unwrap(), KeyType::SharedSecret).unwrap()
}

#[test]
fn core_framework_suites() {
    // The framework compares `derive_key` with a whole hash output, so the expected value is
    // the vector's first 32 bytes; a 1024-bit vector has them.
    let expected = KeyMaterial::<32>::from_bytes_as_type(
        &hex_decode(KEY_DATA).unwrap()[..32],
        KeyType::CryptographicRandom,
    )
    .unwrap();
    let info = hex_decode(SHARED_INFO).unwrap();
    let tf = TestFrameworkKDF::new();
    tf.test_kdf_single_key(&X963KDF_SHA256::new(), &z(), &info, &expected);

    // Z as two keys: the concatenation, so the same answer as one key of the joined bytes.
    let z_bytes = hex_decode(Z).unwrap();
    let a = KeyMaterial::<32>::from_bytes_as_type(&z_bytes[..12], KeyType::SharedSecret).unwrap();
    let b = KeyMaterial::<32>::from_bytes_as_type(&z_bytes[12..], KeyType::SharedSecret).unwrap();
    let keys: [&dyn KeyMaterialTrait; 2] = [&a, &b];
    tf.test_kdf_multiple_key(&X963KDF_SHA256::new(), &keys, &info, &expected);
}

/// SEC 1 Section 3.6.1 steps 3 to 5 by hand: K_i = Hash(Z || Counter || SharedInfo) with a
/// 4-octet big-endian counter from 1, and K the leftmost keydatalen octets of K_1 || K_2 || ...
#[test]
fn matches_the_hash_of_z_counter_shared_info() {
    let z = z();
    let info = b"shared info";
    let mut by_hand = Vec::new();
    for counter in 1u32..=3 {
        let mut msg = z.ref_to_bytes().to_vec();
        msg.extend_from_slice(&counter.to_be_bytes());
        msg.extend_from_slice(info);
        by_hand.extend_from_slice(&SHA256::hash(&msg));
    }
    for len in [1usize, 31, 32, 33, 64, 65, 96] {
        let mut out = KeyMaterial::<96>::new();
        assert_eq!(X963KDF_SHA256::derive_out(&z, info, len, &mut out).unwrap(), len);
        assert_eq!(out.key_len(), len);
        assert_eq!(out.ref_to_bytes(), &by_hand[..len], "keydatalen {len}");
    }
}

/// Step 2: keydatalen below hashlen * (2^32 - 1), tested at the bound itself, which step 2
/// refuses before the buffer check would; and the buffer must hold it. Either error leaves the
/// buffer zeroized. The bound does not fit a 32-bit `usize`, so those cases run on 64-bit only.
#[test]
fn length_bounds_are_refused_and_the_buffer_zeroized() {
    let z = z();
    let bound = usize::try_from(32u128 * 0xFFFF_FFFF).ok();
    let mut out = KeyMaterial::<64>::new();
    if let Some(bound) = bound {
        out.set_bytes_as_type(&[0xAA; 64], KeyType::CryptographicRandom).unwrap();
        assert!(matches!(
            X963KDF_SHA256::derive_out(&z, b"", bound, &mut out),
            Err(KDFError::InvalidLength(m)) if m.contains("below hashlen")
        ));
        assert_eq!(out.key_len(), 0);
        assert_eq!(out.key_type(), KeyType::Zeroized);
    }

    out.set_bytes_as_type(&[0xAA; 64], KeyType::CryptographicRandom).unwrap();
    assert!(matches!(
        X963KDF_SHA256::derive_out(&z, b"", 65, &mut out),
        Err(KDFError::InvalidLength(_))
    ));
    assert_eq!(out.key_len(), 0);

    // a zero-length derivation is refused
    assert!(matches!(
        X963KDF_SHA256::derive_out(&z, b"", 0, &mut out),
        Err(KDFError::InvalidLength(_))
    ));

    // just below the bound the length check passes and the buffer check is what refuses it
    if let Some(bound) = bound {
        assert!(matches!(
            X963KDF_SHA256::derive_out(&z, b"", bound - 1, &mut out),
            Err(KDFError::InvalidLength(m)) if m.contains("buffer")
        ));
    }
}

/// The KDF trait's rule at the edge: a derivation from no keys is refused, while a key of
/// length zero is derived from, giving Hash(Counter || SharedInfo) typed Unknown with no
/// strength, and beside a real key it adds nothing to the concatenation.
#[test]
fn no_keys_are_refused_and_an_empty_key_derives_unknown_output() {
    let mut out = KeyMaterial::<32>::new();
    let none: [&dyn KeyMaterialTrait; 0] = [];
    assert!(matches!(
        X963KDF_SHA256::new().derive_key_from_multiple_out(&none, b"info", 32, &mut out),
        Err(KDFError::InvalidLength(m)) if m.contains("no keys")
    ));

    let empty = KeyMaterial::<32>::new();
    assert_eq!(empty.key_len(), 0);
    assert_eq!(X963KDF_SHA256::derive_out(&empty, b"info", 32, &mut out).unwrap(), 32);
    assert_eq!(out.key_type(), KeyType::Unknown);
    assert_eq!(out.security_strength(), SecurityStrength::None);
    let mut msg = 1u32.to_be_bytes().to_vec();
    msg.extend_from_slice(b"info");
    assert_eq!(out.ref_to_bytes(), &SHA256::hash(&msg));

    let z = z();
    let padded: [&dyn KeyMaterialTrait; 2] = [&empty, &z];
    assert_eq!(
        X963KDF_SHA256::new().derive_key_from_multiple_out(&padded, b"info", 32, &mut out).unwrap(),
        32
    );
    assert!(out.equals(&*X963KDF_SHA256::new().derive_key(&z, b"info", 32).unwrap()));
}

/// The output is credited only from typed full-entropy material of at least half a hash output,
/// at the least of Z's, the hash's and the length's strengths.
#[test]
fn entropy_accounting() {
    let info = b"";
    let mut out = KeyMaterial::<64>::new();

    // a 32-byte SharedSecret at 128 bits into SHA-256: CryptographicRandom at 128 bits
    let mut z = z();
    bouncycastle_core::hazmat::do_hazardous_operations(&mut z, |z| {
        z.set_security_strength(SecurityStrength::_128bit)
    })
    .unwrap();
    X963KDF_SHA256::derive_out(&z, info, 32, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::CryptographicRandom);
    assert_eq!(out.security_strength(), SecurityStrength::_128bit);

    // the output length caps it: 8 bytes cannot carry 128 bits
    X963KDF_SHA256::derive_out(&z, info, 8, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::CryptographicRandom);
    assert_eq!(out.security_strength(), SecurityStrength::None);

    // the hash caps it: a 256-bit Z into SHA-256 reports SHA-256's strength
    let strong =
        KeyMaterial::<64>::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::CryptographicRandom)
            .unwrap();
    X963KDF_SHA256::derive_out(&strong, info, 64, &mut out).unwrap();
    assert_eq!(out.security_strength(), SHA256::MAX_SECURITY_STRENGTH);
    X963KDF_SHA512::derive_out(&strong, info, 64, &mut out).unwrap();
    assert_eq!(out.security_strength(), SecurityStrength::_256bit);

    // below half a hash output of typed material: Unknown (32 bytes seed SHA-512, 31 do not)
    let short =
        KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..31], KeyType::CryptographicRandom)
            .unwrap();
    X963KDF_SHA512::derive_out(&short, info, 64, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::Unknown);
    assert_eq!(out.security_strength(), SecurityStrength::None);
    let just =
        KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::CryptographicRandom)
            .unwrap();
    X963KDF_SHA512::derive_out(&just, info, 64, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::CryptographicRandom);

    // Unknown-typed input is computed over but credits nothing
    let unknown =
        KeyMaterial::<64>::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::Unknown).unwrap();
    X963KDF_SHA256::derive_out(&unknown, info, 32, &mut out).unwrap();
    assert_eq!(out.key_type(), KeyType::Unknown);
    assert_eq!(out.key_len(), 32);
}

/// The last block is truncated to what keydatalen leaves, into a buffer with no room beyond it.
#[test]
fn a_partial_last_block_fits_an_exact_buffer() {
    let z = z();
    let mut out = KeyMaterial::<33>::new();
    assert_eq!(X963KDF_SHA256::derive_out(&z, b"", 33, &mut out).unwrap(), 33);
    let mut longer = KeyMaterial::<64>::new();
    X963KDF_SHA256::derive_out(&z, b"", 64, &mut longer).unwrap();
    assert_eq!(out.ref_to_bytes(), &longer.ref_to_bytes()[..33]);
}

#[test]
fn shared_info_selects_the_key() {
    let z = z();
    let a = X963KDF_SHA256::new().derive_key(&z, b"context a", 32).unwrap();
    let b = X963KDF_SHA256::new().derive_key(&z, b"context b", 32).unwrap();
    let none = X963KDF_SHA256::new().derive_key(&z, b"", 32).unwrap();
    assert_ne!(a.ref_to_bytes(), b.ref_to_bytes());
    assert_ne!(a.ref_to_bytes(), none.ref_to_bytes());
}

#[test]
fn names_strengths_and_output_lengths() {
    assert_eq!(X963KDF_SHA256::ALG_NAME, X963KDF_SHA256_NAME);
    assert_eq!(X963KDF_SHA256_NAME, "X963KDF-SHA256");
    assert_eq!(X963KDF_SHA512::ALG_NAME, X963KDF_SHA512_NAME);
    assert_eq!(X963KDF_SHA256::MAX_SECURITY_STRENGTH, SHA256::MAX_SECURITY_STRENGTH);
    assert_eq!(X963KDF_SHA512::MAX_SECURITY_STRENGTH, SHA512::MAX_SECURITY_STRENGTH);
    let z = z();
    assert_eq!(X963KDF_SHA224::new().derive_key(&z, b"", 28).unwrap().key_len(), 28);
    assert_eq!(X963KDF_SHA256::new().derive_key(&z, b"", 32).unwrap().key_len(), 32);
    assert_eq!(X963KDF_SHA384::new().derive_key(&z, b"", 48).unwrap().key_len(), 48);
    assert_eq!(X963KDF_SHA512::new().derive_key(&z, b"", 64).unwrap().key_len(), 64);
    let mut out = KeyMaterial512::new();
    assert_eq!(X963KDF_SHA256::new().derive_key_out(&z, b"", 64, &mut out).unwrap(), 64);
}
