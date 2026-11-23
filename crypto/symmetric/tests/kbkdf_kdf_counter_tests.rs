//! The counter-mode KDF's behaviour beyond the CAVP vectors: the [`KDF`] trait's shared suite,
//! Section 4.1's steps by hand, the limits, the guard against key control, and the typing of
//! the output.

#[path = "kbkdf_common/mod.rs"]
mod common;

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::hex::decode as hex_decode;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashOneShot, KDF};
use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
use bouncycastle_digest::sha2::{SHA256, SHA512};
use bouncycastle_symmetric::kbkdf::{
    CounterPosition, CounterSize, KDF_Counter, KDF_Counter_HMAC_SHA3_256, KDF_Counter_HMAC_SHA256,
    KDF_Counter_HMAC_SHA384, KDF_Counter_HMAC_SHA512, PRF_HMAC, Prf, fixed_input_out,
    fixed_input_out_len,
};
use common::{hmac_sha256, random};

// KDFCTR_gen.rsp, [PRF=HMAC_SHA256] [CTRLOCATION=BEFORE_FIXED] [RLEN=32_BITS], COUNT=0.
const KI: &str = "dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0";
const FIXED: &str = "01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac";
const KO: &str = "10621342bfb0fd40046c0e29f2cfdbf0";

fn ki() -> KeyMaterial<64> {
    KeyMaterial::<64>::from_bytes_as_type(&hex_decode(KI).unwrap(), KeyType::CryptographicRandom)
        .unwrap()
}

#[test]
fn kdf_trait_suite() {
    let expected = random(&hex_decode(KO).unwrap());
    let fixed = hex_decode(FIXED).unwrap();
    let tf = TestFrameworkKDF::new();
    tf.test_kdf_single_key(&KDF_Counter_HMAC_SHA256::new(), &ki(), &fixed, &expected);

    // K_IN as two keys: the concatenation, so the same answer as one key of the joined bytes.
    let bytes = hex_decode(KI).unwrap();
    let (a, b) = (random(&bytes[..10]), random(&bytes[10..]));
    let keys: [&dyn KeyMaterialTrait; 2] = [&a, &b];
    tf.test_kdf_multiple_key(&KDF_Counter_HMAC_SHA256::new(), &keys, &fixed, &expected);
}

/// Section 4.1 steps 3 to 5 by hand: K(i) = PRF(K_IN, [i]2 || fixed input data), the counter
/// r bits long and where the instance puts it, the output the leftmost L bits.
#[test]
fn matches_the_prf_of_counter_and_fixed_input() {
    let key = [0x5Au8; 32];
    let k_in = random(&key);
    let fixed = b"label\0context: sixteen bytes+";
    type Input = fn(u32, &[u8]) -> Vec<u8>;
    let cases: [(CounterSize, CounterPosition, Input); 5] = [
        (CounterSize::_32bit, CounterPosition::BeforeFixedInput, |i, f| {
            [&i.to_be_bytes()[..], f].concat()
        }),
        (CounterSize::_8bit, CounterPosition::BeforeFixedInput, |i, f| {
            [&[i as u8][..], f].concat()
        }),
        (CounterSize::_16bit, CounterPosition::AfterFixedInput, |i, f| {
            [f, &(i as u16).to_be_bytes()[..]].concat()
        }),
        (CounterSize::_24bit, CounterPosition::InFixedInput(6), |i, f| {
            [&f[..6], &i.to_be_bytes()[1..], &f[6..]].concat()
        }),
        (CounterSize::_8bit, CounterPosition::InFixedInput(0), |i, f| [&[i as u8][..], f].concat()),
    ];
    for (r, position, input) in cases {
        let mut expected = Vec::new();
        for i in 1..=3u32 {
            expected.extend_from_slice(&hmac_sha256(&key, &[&input(i, fixed)]));
        }
        // 80 bytes: two whole blocks and half of a third.
        let kdf = KDF_Counter_HMAC_SHA256::with_counter(r, position);
        let out = kdf.derive_key(&k_in, fixed, 80).unwrap();
        assert_eq!(out.ref_to_bytes(), &expected[..80], "{r:?} {position:?}");
    }
    // The counter at the end of the fixed input data is the counter after it.
    let at_end = KDF_Counter_HMAC_SHA256::with_counter(
        CounterSize::_16bit,
        CounterPosition::InFixedInput(fixed.len()),
    );
    let after = KDF_Counter_HMAC_SHA256::with_counter(
        CounterSize::_16bit,
        CounterPosition::AfterFixedInput,
    );
    assert_eq!(
        at_end.derive_key(&k_in, fixed, 80).unwrap().ref_to_bytes(),
        after.derive_key(&k_in, fixed, 80).unwrap().ref_to_bytes()
    );
}

/// Section 4.1's guard: the fixed input data is followed by K(0) = PRF(K_IN, fixed input data)
/// in every iteration.
#[test]
fn key_control_guard_appends_k0() {
    let key = [0x77u8; 32];
    let k_in = random(&key);
    let fixed = b"fixed input data";
    let k0 = hmac_sha256(&key, &[fixed]);

    let mut expected = Vec::new();
    for i in 1..=2u32 {
        expected.extend_from_slice(&hmac_sha256(&key, &[&i.to_be_bytes(), fixed, &k0]));
    }
    let guarded = KDF_Counter_HMAC_SHA256::new().with_key_control_guard();
    assert!(guarded.key_control_guard());
    assert_eq!(guarded.derive_key(&k_in, fixed, 64).unwrap().ref_to_bytes(), &expected[..]);

    // With the counter inside the fixed input data, K(0) is over the whole of it and still last.
    let mut expected = Vec::new();
    for i in 1..=2u32 {
        expected
            .extend_from_slice(&hmac_sha256(&key, &[&fixed[..5], &[i as u8], &fixed[5..], &k0]));
    }
    let guarded =
        KDF_Counter_HMAC_SHA256::with_counter(CounterSize::_8bit, CounterPosition::InFixedInput(5))
            .with_key_control_guard();
    assert_eq!(guarded.derive_key(&k_in, fixed, 64).unwrap().ref_to_bytes(), &expected[..]);

    let plain = KDF_Counter_HMAC_SHA256::new();
    assert!(!plain.key_control_guard());
    assert_eq!(
        plain.derive_key(&k_in, fixed, 32).unwrap().ref_to_bytes(),
        &hmac_sha256(&key, &[&1u32.to_be_bytes(), fixed])[..]
    );
}

/// Section 4.1 step 2: n must not exceed 2^r - 1.
#[test]
fn the_counter_bounds_the_length() {
    let sizes = [CounterSize::_8bit, CounterSize::_16bit, CounterSize::_24bit, CounterSize::_32bit];
    assert_eq!([8, 16, 24, 32].map(CounterSize::from_bits), sizes.map(Some));
    assert_eq!(sizes.map(|r| r.byte_len()), [1, 2, 3, 4]);
    for bits in [0, 1, 7, 9, 12, 31, 33, 64] {
        assert_eq!(CounterSize::from_bits(bits), None, "{bits} bits");
    }

    let kdf = KDF_Counter_HMAC_SHA256::with_counter(
        CounterSize::_8bit,
        CounterPosition::BeforeFixedInput,
    );
    assert_eq!(kdf.max_len(), 255 * 32);
    assert_eq!(
        KDF_Counter_HMAC_SHA512::with_counter(
            CounterSize::_16bit,
            CounterPosition::AfterFixedInput
        )
        .max_len(),
        65_535 * 64
    );
    assert_eq!(
        KDF_Counter_HMAC_SHA256::with_counter(
            CounterSize::_24bit,
            CounterPosition::AfterFixedInput
        )
        .max_len(),
        16_777_215 * 32
    );
    assert_eq!(KDF_Counter_HMAC_SHA256::new().max_len() as u128, 32 * u32::MAX as u128);

    let k_in = ki();
    let mut out = KeyMaterial::<8192>::new();
    // 255 blocks exactly: the last counter value is 0xFF.
    assert_eq!(kdf.derive_key_out(&k_in, b"f", 255 * 32, &mut out), Ok(255 * 32));
    let last = hmac_sha256(&hex_decode(KI).unwrap(), &[&[0xFF], b"f"]);
    assert_eq!(&out.ref_to_bytes()[254 * 32..], &last[..]);
    // One byte more needs a 256th block.
    assert!(matches!(
        kdf.derive_key_out(&k_in, b"f", 255 * 32 + 1, &mut out),
        Err(KDFError::InvalidLength(_))
    ));
    assert_eq!(out.key_type(), KeyType::Zeroized);
    assert_eq!(out.key_len(), 0);
}

#[test]
fn bad_requests_are_refused_with_the_buffer_zeroized() {
    let k_in = ki();
    let kdf = KDF_Counter_HMAC_SHA256::new();
    let stale = || {
        let mut out = KeyMaterial::<32>::new();
        out.set_bytes_as_type(&[0xAA; 32], KeyType::CryptographicRandom).unwrap();
        out
    };
    let refused = |r: Result<usize, KDFError>, out: &KeyMaterial<32>, what: &str| {
        assert!(matches!(r, Err(KDFError::InvalidLength(_))), "{what}");
        assert_eq!(out.key_type(), KeyType::Zeroized, "{what}");
        assert_eq!(out.key_len(), 0, "{what}");
    };

    let mut out = stale();
    refused(kdf.derive_key_out(&k_in, b"f", 0, &mut out), &out, "a zero length");
    let mut out = stale();
    refused(kdf.derive_key_out(&k_in, b"f", 33, &mut out), &out, "more than the buffer holds");
    let mut out = stale();
    refused(kdf.derive_key_from_multiple_out(&[], b"f", 16, &mut out), &out, "no keys");

    // The buffer's whole capacity is fine.
    let mut out = stale();
    assert_eq!(kdf.derive_key_out(&k_in, b"f", 32, &mut out), Ok(32));

    // A counter placed past the end of the fixed input data.
    let past =
        KDF_Counter_HMAC_SHA256::with_counter(CounterSize::_8bit, CounterPosition::InFixedInput(2));
    let mut out = stale();
    refused(past.derive_key_out(&k_in, b"f", 16, &mut out), &out, "a counter past the end");
    let mut out = stale();
    assert_eq!(past.derive_key_out(&k_in, b"ff", 16, &mut out), Ok(16));
}

/// The output's type and strength follow the key-derivation key's: the least of the key's,
/// the PRF's and the length's.
#[test]
fn the_output_is_typed_from_the_key() {
    let typed = |len: usize, strength: SecurityStrength| {
        let mut k =
            KeyMaterial::<64>::from_bytes_as_type(&[0x33; 64][..len], KeyType::SharedSecret)
                .unwrap();
        do_hazardous_operations(&mut k, |k| k.set_security_strength(strength)).unwrap();
        k
    };
    let label = |kdf: &dyn KDF, k: &KeyMaterial<64>, len: usize| {
        let out = kdf.derive_key(k, b"f", len).unwrap();
        (out.key_type(), out.security_strength())
    };
    let sha256 = KDF_Counter_HMAC_SHA256::new();
    let sha512 = KDF_Counter_HMAC_SHA512::new();
    let random = KeyType::CryptographicRandom;
    let unknown = (KeyType::Unknown, SecurityStrength::None);

    // Capped by the PRF: HMAC-SHA256 claims 128 bits, HMAC-SHA512 256.
    let k = typed(64, SecurityStrength::_256bit);
    assert_eq!(label(&sha256, &k, 64), (random, SecurityStrength::_128bit));
    assert_eq!(label(&sha512, &k, 64), (random, SecurityStrength::_256bit));
    // Capped by the key.
    let k = typed(64, SecurityStrength::_112bit);
    assert_eq!(label(&sha512, &k, 64), (random, SecurityStrength::_112bit));
    // Capped by the length: 16 bytes carry 128 bits.
    let k = typed(64, SecurityStrength::_256bit);
    assert_eq!(label(&sha512, &k, 16), (random, SecurityStrength::_128bit));

    // Half a hash output of full-entropy key seeds the KDF; one byte less does not.
    assert_eq!(
        label(&sha256, &typed(16, SecurityStrength::_128bit), 32),
        (random, SecurityStrength::_128bit)
    );
    assert_eq!(label(&sha256, &typed(15, SecurityStrength::_112bit), 32), unknown);
    assert_eq!(
        label(&sha512, &typed(32, SecurityStrength::_256bit), 32),
        (random, SecurityStrength::_256bit)
    );
    assert_eq!(label(&sha512, &typed(31, SecurityStrength::_192bit), 32), unknown);

    // Two keys are credited together, at the stronger's strength.
    let a = typed(14, SecurityStrength::_112bit);
    let b = typed(16, SecurityStrength::_128bit);
    let out = sha256.derive_key_from_multiple(&[&a, &b], b"f", 32).unwrap();
    assert_eq!((out.key_type(), out.security_strength()), (random, SecurityStrength::_128bit));
    let out = sha256.derive_key_from_multiple(&[&a], b"f", 32).unwrap();
    assert_eq!((out.key_type(), out.security_strength()), unknown);
}

/// RFC 2104 Section 3 through the KDF: a key-derivation key longer than the hash's block keys
/// HMAC as its hash does, whether it arrives as one key or several; one of exactly a block
/// does not.
#[test]
fn a_long_key_is_hashed_as_hmac_does() {
    let kdf = KDF_Counter_HMAC_SHA256::new();
    let long = [0x42u8; 65];
    let expected = kdf.derive_key(&random(&SHA256::hash(&long)), b"f", 48).unwrap();
    assert_eq!(
        kdf.derive_key(&random(&long), b"f", 48).unwrap().ref_to_bytes(),
        expected.ref_to_bytes()
    );
    let (a, b) = (random(&long[..40]), random(&long[40..]));
    assert_eq!(
        kdf.derive_key_from_multiple(&[&a, &b], b"f", 48).unwrap().ref_to_bytes(),
        expected.ref_to_bytes()
    );

    let block = [0x42u8; 64];
    let k1 = hmac_sha256(&block, &[&1u32.to_be_bytes(), b"f"]);
    assert_eq!(kdf.derive_key(&random(&block), b"f", 32).unwrap().ref_to_bytes(), &k1[..]);
    let (a, b) = (random(&block[..1]), random(&block[1..]));
    assert_eq!(kdf.derive_key_from_multiple(&[&a, &b], b"f", 32).unwrap().ref_to_bytes(), &k1[..]);

    // SHA-512's block is 128 bytes: a 65-byte key is used as it is.
    let sha512 = KDF_Counter_HMAC_SHA512::new();
    assert_ne!(
        sha512.derive_key(&random(&long), b"f", 48).unwrap().ref_to_bytes(),
        sha512.derive_key(&random(&SHA512::hash(&long)), b"f", 48).unwrap().ref_to_bytes()
    );
}

#[test]
fn fixed_input_is_label_separator_context_length() {
    let mut out = [0xEEu8; 32];
    assert_eq!(fixed_input_out_len(b"label", b"context"), 17);
    // 0x0020_4060 bytes are 0x0102_0300 bits.
    assert_eq!(fixed_input_out(b"label", b"context", 0x0020_4060, &mut out), Ok(17));
    assert_eq!(&out[..17], b"label\0context\x01\x02\x03\x00");
    assert_eq!(&out[17..], &[0u8; 15], "the rest of the buffer is cleared");

    // Empty fields leave the separator and the length; a buffer of exactly that fits.
    let mut out = [0xEEu8; 5];
    assert_eq!(fixed_input_out_len(b"", b""), 5);
    assert_eq!(fixed_input_out(b"", b"", 32, &mut out), Ok(5));
    assert_eq!(out, [0, 0, 0, 1, 0]);

    // One byte short: refused, and cleared.
    let mut out = [0xEEu8; 16];
    assert!(matches!(
        fixed_input_out(b"label", b"context", 32, &mut out),
        Err(KDFError::InvalidLength(_))
    ));
    assert_eq!(out, [0u8; 16]);

    // [L]2 is 32 bits: the largest length that fits is 2^29 - 1 bytes, and one more is refused.
    let mut out = [0xEEu8; 32];
    assert_eq!(fixed_input_out(b"", b"", (1 << 29) - 1, &mut out), Ok(5));
    assert_eq!(&out[..5], &[0, 0xFF, 0xFF, 0xFF, 0xF8]);
    let mut out = [0xEEu8; 32];
    assert!(matches!(
        fixed_input_out(b"", b"", 1 << 29, &mut out),
        Err(KDFError::InvalidLength(_))
    ));
    assert_eq!(out, [0u8; 32]);
}

#[test]
fn names_strengths_and_description() {
    assert_eq!(KDF_Counter_HMAC_SHA256::ALG_NAME, "KDF-Counter-HMAC-SHA256");
    assert_eq!(KDF_Counter_HMAC_SHA3_256::ALG_NAME, "KDF-Counter-HMAC-SHA3-256");
    assert_eq!(KDF_Counter_HMAC_SHA256::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(KDF_Counter_HMAC_SHA384::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(KDF_Counter_HMAC_SHA512::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);
    assert_eq!(<PRF_HMAC<SHA512> as Prf>::H_LEN, 64);

    // The default is Section 4.1's layout with a 32-bit counter.
    let kdf = KDF_Counter_HMAC_SHA256::default();
    assert_eq!(kdf.r(), CounterSize::_32bit);
    assert_eq!(kdf.position(), CounterPosition::BeforeFixedInput);
    assert!(!kdf.key_control_guard());

    // The description's engine is the KDF it describes, parameters included.
    let described = KDF_Counter::<PRF_HMAC<SHA512>>::with_counter(
        CounterSize::_16bit,
        CounterPosition::InFixedInput(3),
    )
    .with_key_control_guard();
    let engine = described.engine().unwrap();
    assert_eq!(engine.r(), CounterSize::_16bit);
    assert_eq!(engine.position(), CounterPosition::InFixedInput(3));
    assert!(engine.key_control_guard());
    let k_in = ki();
    assert_eq!(
        engine.derive_key(&k_in, b"fixed", 40).unwrap().ref_to_bytes(),
        described.derive_key(&k_in, b"fixed", 40).unwrap().ref_to_bytes()
    );
}

/// A copy keeps its parameters, and nothing is written past `L` bytes: the last block is cut
/// to what is left, whether the buffer is exactly `L` long or longer.
#[test]
fn a_partial_last_block_and_a_copy() {
    let kdf = KDF_Counter_HMAC_SHA256::with_counter(
        CounterSize::_16bit,
        CounterPosition::InFixedInput(3),
    )
    .with_key_control_guard();
    #[allow(clippy::clone_on_copy)]
    let copy = kdf.clone();
    assert_eq!(copy.r(), CounterSize::_16bit);
    assert_eq!(copy.position(), CounterPosition::InFixedInput(3));
    assert!(copy.key_control_guard());

    let k_in = ki();
    let whole = kdf.derive_key(&k_in, b"fixed", 64).unwrap();
    let mut exact = KeyMaterial::<40>::new();
    assert_eq!(kdf.derive_key_out(&k_in, b"fixed", 40, &mut exact), Ok(40));
    assert_eq!(exact.ref_to_bytes(), &whole.ref_to_bytes()[..40]);

    let mut roomy = KeyMaterial::<128>::new();
    assert_eq!(kdf.derive_key_out(&k_in, b"fixed", 40, &mut roomy), Ok(40));
    assert_eq!(roomy.ref_to_bytes(), &whole.ref_to_bytes()[..40]);
    let mut capacity = Vec::new();
    do_hazardous_operations(&mut roomy, |k| {
        capacity = k.ref_to_bytes_mut()?.to_vec();
        Ok(())
    })
    .unwrap();
    assert_eq!(&capacity[40..], &[0u8; 88], "nothing of the last block is left past L");
}
