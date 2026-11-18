//! The feedback and double-pipeline KDFs' behaviour beyond the CAVP vectors: the [`KDF`]
//! trait's shared suite, Sections 4.2 and 4.3 by hand, HKDF-Expand as an instance of the
//! feedback mode, the limits and the guard against key control; and what is particular to
//! CMAC as the PRF, in all three modes.

use bouncycastle_aes::AES128Key;
use bouncycastle_cipher::modes::CMAC;
use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, FromKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::{Algorithm, KDF};
use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
use bouncycastle_hkdf::HKDF;
use bouncycastle_hmac::HmacKey;
use bouncycastle_kbkdf::{
    CounterPosition, CounterSize, IterationCounterPosition as Position, KDF_Counter_CMAC_AES128,
    KDF_Counter_CMAC_AES192, KDF_Counter_CMAC_AES256, KDF_Counter_HMAC_SHA256,
    KDF_DoublePipeline_CMAC_AES128, KDF_DoublePipeline_HMAC_SHA256, KDF_DoublePipeline_HMAC_SHA512,
    KDF_Feedback_CMAC_AES128, KDF_Feedback_CMAC_AES256, KDF_Feedback_HMAC_SHA3_512,
    KDF_Feedback_HMAC_SHA256, KDF_Feedback_HMAC_SHA512, PRF_CMAC, Prf,
};
use bouncycastle_sha2::SHA256;

const KEY: [u8; 32] = [0x5A; 32];
const FIXED: &[u8] = b"label\0context: sixteen bytes+";

fn random(bytes: &[u8]) -> KeyMaterial<128> {
    KeyMaterial::<128>::from_bytes_as_type(bytes, KeyType::CryptographicRandom).unwrap()
}

/// HMAC-SHA256 under `key` over `parts`, through the key object.
fn hmac(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let key = KeyMaterial::<144>::from_bytes_as_type(key, KeyType::MACKey).unwrap();
    HmacKey::<SHA256>::from_key_material_allow_weak(&key).unwrap().mac(&parts.concat()).to_vec()
}

/// AES-128 CMAC under `key` over `parts`, through the key object.
fn cmac(key: &[u8; 16], parts: &[&[u8]]) -> Vec<u8> {
    let key = KeyMaterial::<16>::from_bytes_as_type(key, KeyType::MACKey).unwrap();
    AES128Key::<CMAC>::from_key_material(&key).unwrap().mac(&parts.concat()).to_vec()
}

/// One PRF input with the counter where `counter` puts it.
fn input(counter: Option<(CounterSize, Position)>, i: u32, var: &[u8], fixed: &[u8]) -> Vec<u8> {
    match counter {
        None => [var, fixed].concat(),
        Some((r, position)) => {
            let c = &i.to_be_bytes()[4 - r.byte_len()..];
            match position {
                Position::BeforeIterationVariable => [c, var, fixed].concat(),
                Position::AfterIterationVariable => [var, c, fixed].concat(),
                Position::AfterFixedInput => [var, fixed, c].concat(),
            }
        }
    }
}

const COUNTERS: [Option<(CounterSize, Position)>; 5] = [
    None,
    Some((CounterSize::_8bit, Position::BeforeIterationVariable)),
    Some((CounterSize::_16bit, Position::AfterIterationVariable)),
    Some((CounterSize::_24bit, Position::AfterFixedInput)),
    Some((CounterSize::_32bit, Position::AfterIterationVariable)),
];

/// Section 4.2 steps 3 to 5 by hand: K(0) = IV, K(i) = PRF(K_IN, K(i-1) {|| [i]2} || fixed).
#[test]
fn feedback_matches_the_prf_of_the_previous_block() {
    let k_in = random(&KEY);
    for iv in [&b""[..], b"an IV of any length at all"] {
        for counter in COUNTERS {
            let mut expected = Vec::new();
            let mut previous = iv.to_vec();
            for i in 1..=3u32 {
                previous = hmac(&KEY, &[&input(counter, i, &previous, FIXED)]);
                expected.extend_from_slice(&previous);
            }
            let kdf = match counter {
                None => KDF_Feedback_HMAC_SHA256::new(iv),
                Some((r, position)) => KDF_Feedback_HMAC_SHA256::with_counter(iv, r, position),
            };
            assert_eq!(kdf.iv(), Some(iv));
            assert_eq!(kdf.counter(), counter);
            assert!(!kdf.key_control_guard());
            // 80 bytes: two whole blocks and half of a third.
            let out = kdf.derive_key(&k_in, FIXED, 80).unwrap();
            assert_eq!(out.ref_to_bytes(), &expected[..80], "{counter:?}, IV of {}", iv.len());
        }
    }
}

/// Section 4.3 steps 4 and 5 by hand: A(0) = fixed, A(i) = PRF(K_IN, A(i-1)),
/// K(i) = PRF(K_IN, A(i) {|| [i]2} || fixed).
#[test]
fn double_pipeline_matches_the_two_pipelines() {
    let k_in = random(&KEY);
    for counter in COUNTERS {
        let mut expected = Vec::new();
        let mut a = FIXED.to_vec();
        for i in 1..=3u32 {
            a = hmac(&KEY, &[&a]);
            expected.extend_from_slice(&hmac(&KEY, &[&input(counter, i, &a, FIXED)]));
        }
        let kdf = match counter {
            None => KDF_DoublePipeline_HMAC_SHA256::new(),
            Some((r, position)) => KDF_DoublePipeline_HMAC_SHA256::with_counter(r, position),
        };
        assert_eq!(kdf.counter(), counter);
        let out = kdf.derive_key(&k_in, FIXED, 80).unwrap();
        assert_eq!(out.ref_to_bytes(), &expected[..80], "{counter:?}");
    }
    assert_eq!(KDF_DoublePipeline_HMAC_SHA256::default().counter(), None);
}

/// RFC 5869 Section 2.3's HKDF-Expand, `T(i) = HMAC(PRK, T(i-1) | info | i)` with a one-octet
/// counter, is the feedback mode with an empty IV and an 8-bit counter after the fixed input
/// data.
#[test]
fn hkdf_expand_is_the_feedback_mode() {
    let prk = random(&[0xC3; 32]);
    let info = b"hkdf info";
    let kdf =
        KDF_Feedback_HMAC_SHA256::with_counter(b"", CounterSize::_8bit, Position::AfterFixedInput);
    for len in [1usize, 32, 33, 100] {
        let mut okm = KeyMaterial::<128>::new();
        HKDF::<SHA256>::expand_out(&prk, info, len, &mut okm).unwrap();
        assert_eq!(kdf.derive_key(&prk, info, len).unwrap().ref_to_bytes(), okm.ref_to_bytes());
    }
}

/// Section 4.2's note: "when L <= h, IV = empty, and the counter is used, the feedback mode
/// will generate an output that is identical to the output of the counter mode".
#[test]
fn one_block_of_feedback_is_one_block_of_counter_mode() {
    let k_in = random(&KEY);
    let feedback = KDF_Feedback_HMAC_SHA256::with_counter(
        b"",
        CounterSize::_32bit,
        Position::AfterIterationVariable,
    );
    let counter = KDF_Counter_HMAC_SHA256::new();
    assert_eq!(
        feedback.derive_key(&k_in, FIXED, 32).unwrap().ref_to_bytes(),
        counter.derive_key(&k_in, FIXED, 32).unwrap().ref_to_bytes()
    );
    // A second block differs: the feedback mode feeds the first back in.
    assert_ne!(
        &feedback.derive_key(&k_in, FIXED, 64).unwrap().ref_to_bytes()[32..],
        &counter.derive_key(&k_in, FIXED, 64).unwrap().ref_to_bytes()[32..]
    );
}

/// Section 4.2's guard: "IV = PRF (K_IN, Label || 0x00 || Context || [L]2)", with the counter.
#[test]
fn feedback_key_control_guard_derives_the_iv() {
    let k_in = random(&KEY);
    let guarded = KDF_Feedback_HMAC_SHA256::with_key_control_guard(
        CounterSize::_16bit,
        Position::AfterIterationVariable,
    );
    assert!(guarded.key_control_guard());
    assert_eq!(guarded.iv(), None);
    assert_eq!(guarded.counter(), Some((CounterSize::_16bit, Position::AfterIterationVariable)));

    let iv = hmac(&KEY, &[FIXED]);
    let given = KDF_Feedback_HMAC_SHA256::with_counter(
        &iv,
        CounterSize::_16bit,
        Position::AfterIterationVariable,
    );
    assert_eq!(
        guarded.derive_key(&k_in, FIXED, 80).unwrap().ref_to_bytes(),
        given.derive_key(&k_in, FIXED, 80).unwrap().ref_to_bytes()
    );
    // The engine of a description is the same KDF, the guard included.
    assert_eq!(
        guarded.engine().unwrap().derive_key(&k_in, FIXED, 80).unwrap().ref_to_bytes(),
        guarded.derive_key(&k_in, FIXED, 80).unwrap().ref_to_bytes()
    );
    let described =
        KDF_DoublePipeline_HMAC_SHA256::with_counter(CounterSize::_8bit, Position::AfterFixedInput);
    assert_eq!(described.engine().unwrap().counter(), described.counter());
}

/// Step 2 of Sections 4.2 and 4.3, and the counter's range where one is used.
#[test]
fn the_limits_of_the_iterated_modes() {
    let k_in = random(&KEY);
    let with_8 = Some((CounterSize::_8bit, Position::AfterIterationVariable));
    let feedback = KDF_Feedback_HMAC_SHA256::with_counter(
        b"",
        CounterSize::_8bit,
        Position::AfterIterationVariable,
    );
    let pipeline = KDF_DoublePipeline_HMAC_SHA256::with_counter(
        CounterSize::_8bit,
        Position::AfterIterationVariable,
    );
    assert_eq!(feedback.counter(), with_8);
    assert_eq!(feedback.max_len(), 255 * 32);
    assert_eq!(pipeline.max_len(), 255 * 32);
    assert_eq!(
        KDF_Feedback_HMAC_SHA512::with_counter(b"", CounterSize::_16bit, Position::AfterFixedInput)
            .max_len(),
        65_535 * 64
    );
    // Without a counter the bound is 2^32 - 1 blocks.
    assert_eq!(KDF_Feedback_HMAC_SHA256::new(b"").max_len() as u128, 32 * u32::MAX as u128);
    assert_eq!(KDF_DoublePipeline_HMAC_SHA512::new().max_len() as u128, 64 * u32::MAX as u128);

    let mut out = KeyMaterial::<8192>::new();
    for kdf in [&feedback as &dyn KDF, &pipeline] {
        assert_eq!(kdf.derive_key_out(&k_in, b"f", 255 * 32, &mut out), Ok(255 * 32));
        assert!(matches!(
            kdf.derive_key_out(&k_in, b"f", 255 * 32 + 1, &mut out),
            Err(KDFError::InvalidLength(_))
        ));
        assert_eq!((out.key_type(), out.key_len()), (KeyType::Zeroized, 0));
        // The trait's own refusals, with the buffer cleared.
        for (len, keys) in [(0usize, 1usize), (16, 0)] {
            out.set_bytes_as_type(&[0xAA; 32], KeyType::CryptographicRandom).unwrap();
            let keys: &[&dyn KeyMaterialTrait] = if keys == 0 { &[] } else { &[&k_in] };
            assert!(matches!(
                kdf.derive_key_from_multiple_out(keys, b"f", len, &mut out),
                Err(KDFError::InvalidLength(_))
            ));
            assert_eq!((out.key_type(), out.key_len()), (KeyType::Zeroized, 0));
        }
        let mut small = KeyMaterial::<16>::new();
        small.set_bytes_as_type(&[0xAA; 16], KeyType::CryptographicRandom).unwrap();
        assert!(matches!(
            kdf.derive_key_out(&k_in, b"f", 17, &mut small),
            Err(KDFError::InvalidLength(_))
        ));
        assert_eq!((small.key_type(), small.key_len()), (KeyType::Zeroized, 0));
        assert_eq!(kdf.derive_key_out(&k_in, b"f", 16, &mut small), Ok(16));
    }
    // Without a counter, the same length is fine.
    assert_eq!(
        KDF_Feedback_HMAC_SHA256::new(b"").derive_key_out(&k_in, b"f", 255 * 32 + 1, &mut out),
        Ok(255 * 32 + 1)
    );
    assert_eq!(
        KDF_DoublePipeline_HMAC_SHA256::new().derive_key_out(&k_in, b"f", 255 * 32 + 1, &mut out),
        Ok(255 * 32 + 1)
    );
}

#[test]
fn kdf_trait_suite_over_hmac() {
    let key = random(&KEY);
    let tf = TestFrameworkKDF::new();
    let (a, b) = (random(&KEY[..10]), random(&KEY[10..]));
    let keys: [&dyn KeyMaterialTrait; 2] = [&a, &b];

    let feedback = KDF_Feedback_HMAC_SHA256::new(b"iv");
    let mut expected = hmac(&KEY, &[b"iv", FIXED]);
    let second = hmac(&KEY, &[&expected, FIXED]);
    expected.extend_from_slice(&second[..8]);
    let expected = random(&expected);
    tf.test_kdf_single_key(&feedback, &key, FIXED, &expected);
    tf.test_kdf_multiple_key(&feedback, &keys, FIXED, &expected);

    let pipeline = KDF_DoublePipeline_HMAC_SHA256::new();
    let a1 = hmac(&KEY, &[FIXED]);
    let a2 = hmac(&KEY, &[&a1]);
    let mut expected = hmac(&KEY, &[&a1, FIXED]);
    expected.extend_from_slice(&hmac(&KEY, &[&a2, FIXED])[..8]);
    let expected = random(&expected);
    tf.test_kdf_single_key(&pipeline, &key, FIXED, &expected);
    tf.test_kdf_multiple_key(&pipeline, &keys, FIXED, &expected);
}

/// CMAC as the PRF, in each mode, by hand over AES-128: the output block is 16 bytes.
#[test]
fn cmac_modes_match_the_prf() {
    let key = [0x2Bu8; 16];
    let k_in = random(&key);

    let mut expected = Vec::new();
    for i in 1..=3u8 {
        expected.extend_from_slice(&cmac(&key, &[&[i], FIXED]));
    }
    let counter = KDF_Counter_CMAC_AES128::with_counter(
        CounterSize::_8bit,
        CounterPosition::BeforeFixedInput,
    );
    assert_eq!(counter.derive_key(&k_in, FIXED, 40).unwrap().ref_to_bytes(), &expected[..40]);

    // Section 4.1's guard, which is what CMAC is offered it for.
    let k0 = cmac(&key, &[FIXED]);
    let mut expected = Vec::new();
    for i in 1..=3u8 {
        expected.extend_from_slice(&cmac(&key, &[&[i], FIXED, &k0]));
    }
    assert_eq!(
        counter.with_key_control_guard().derive_key(&k_in, FIXED, 40).unwrap().ref_to_bytes(),
        &expected[..40]
    );

    let mut expected = Vec::new();
    let mut previous = b"iv".to_vec();
    for _ in 0..3 {
        previous = cmac(&key, &[&previous, FIXED]);
        expected.extend_from_slice(&previous);
    }
    let feedback = KDF_Feedback_CMAC_AES128::new(b"iv");
    assert_eq!(feedback.derive_key(&k_in, FIXED, 40).unwrap().ref_to_bytes(), &expected[..40]);

    let mut expected = Vec::new();
    let mut a = FIXED.to_vec();
    for _ in 0..3 {
        a = cmac(&key, &[&a]);
        expected.extend_from_slice(&cmac(&key, &[&a, FIXED]));
    }
    let pipeline = KDF_DoublePipeline_CMAC_AES128::new();
    assert_eq!(pipeline.derive_key(&k_in, FIXED, 40).unwrap().ref_to_bytes(), &expected[..40]);

    // K_IN as two keys is their concatenation.
    let (a, b) = (random(&key[..7]), random(&key[7..]));
    assert_eq!(
        feedback.derive_key_from_multiple(&[&a, &b], FIXED, 40).unwrap().ref_to_bytes(),
        feedback.derive_key(&k_in, FIXED, 40).unwrap().ref_to_bytes()
    );
}

/// Section 6.2: with CMAC "an implementation should check whether the key-derivation key
/// length is consistent with the length required by the PRF".
#[test]
fn cmac_refuses_a_key_of_the_wrong_length() {
    let mut out = KeyMaterial::<64>::new();
    let kdfs: [(&dyn KDF, usize); 5] = [
        (&KDF_Counter_CMAC_AES128::new(), 16),
        (&KDF_Counter_CMAC_AES192::new(), 24),
        (&KDF_Counter_CMAC_AES256::new(), 32),
        (&KDF_Feedback_CMAC_AES256::new(b""), 32),
        (&KDF_DoublePipeline_CMAC_AES128::new(), 16),
    ];
    for (kdf, key_len) in kdfs {
        for len in [0usize, key_len - 1, key_len + 1, 16, 24, 32] {
            out.set_bytes_as_type(&[0xAA; 32], KeyType::CryptographicRandom).unwrap();
            let result = kdf.derive_key_out(&random(&[0x11; 64][..len]), b"f", 32, &mut out);
            if len == key_len {
                assert_eq!(result, Ok(32), "{} with {len} bytes", kdf.alg_name());
            } else {
                assert!(
                    matches!(result, Err(KDFError::InvalidLength(_))),
                    "{} with {len} bytes",
                    kdf.alg_name()
                );
                assert_eq!((out.key_type(), out.key_len()), (KeyType::Zeroized, 0));
            }
        }
        // Two keys that together are the right length.
        let (a, b) = (random(&[0x11; 64][..5]), random(&[0x11; 64][..key_len - 5]));
        assert_eq!(kdf.derive_key_from_multiple_out(&[&a, &b], b"f", 32, &mut out), Ok(32));
        assert!(matches!(
            kdf.derive_key_from_multiple_out(&[&a, &a], b"f", 32, &mut out),
            Err(KDFError::InvalidLength(_))
        ));
    }
}

/// With CMAC the whole key must be full-entropy material for the output to be typed
/// `CryptographicRandom`, at the least of the key's, the cipher's and the length's strengths.
#[test]
fn cmac_output_is_typed_from_the_key() {
    let typed = |len: usize, key_type: KeyType, strength: SecurityStrength| {
        let mut k = KeyMaterial::<64>::from_bytes_as_type(&[0x33; 64][..len], key_type).unwrap();
        do_hazardous_operations(&mut k, |k| k.set_security_strength(strength)).unwrap();
        k
    };
    let label = |kdf: &dyn KDF, keys: &[&dyn KeyMaterialTrait], len: usize| {
        let out = kdf.derive_key_from_multiple(keys, b"f", len).unwrap();
        (out.key_type(), out.security_strength())
    };
    let random = KeyType::CryptographicRandom;
    let unknown = (KeyType::Unknown, SecurityStrength::None);
    let aes128 = KDF_Counter_CMAC_AES128::new();
    let aes256 = KDF_Feedback_CMAC_AES256::new(b"");

    let k = typed(16, KeyType::SharedSecret, SecurityStrength::_128bit);
    assert_eq!(label(&aes128, &[&k], 32), (random, SecurityStrength::_128bit));
    let k = typed(16, KeyType::SharedSecret, SecurityStrength::_112bit);
    assert_eq!(label(&aes128, &[&k], 32), (random, SecurityStrength::_112bit));
    let k = typed(32, KeyType::SharedSecret, SecurityStrength::_256bit);
    assert_eq!(label(&aes256, &[&k], 32), (random, SecurityStrength::_256bit));
    assert_eq!(label(&aes256, &[&k], 16), (random, SecurityStrength::_128bit));

    // A key that is not full-entropy material, or carries no strength, credits nothing.
    let k = typed(16, KeyType::Unknown, SecurityStrength::None);
    assert_eq!(label(&aes128, &[&k], 32), unknown);
    // Half the key full-entropy and half not: one byte short of the whole key is not enough.
    let good = typed(16, KeyType::SharedSecret, SecurityStrength::_128bit);
    let bad = typed(16, KeyType::Unknown, SecurityStrength::None);
    assert_eq!(label(&aes256, &[&good, &bad], 32), unknown);
    assert_eq!(label(&aes256, &[&good, &good], 32), (random, SecurityStrength::_128bit));
}

#[test]
fn names_and_strengths() {
    // The name constants are the instantiations' names.
    use bouncycastle_kbkdf::{
        KDF_COUNTER_CMAC_AES256_NAME, KDF_COUNTER_HMAC_SHA256_NAME, KDF_COUNTER_HMAC_SHA384_NAME,
        KDF_COUNTER_HMAC_SHA512_NAME, KDF_Counter_HMAC_SHA384, KDF_Counter_HMAC_SHA512,
        KDF_KMAC128, KDF_KMAC128_NAME, KDF_KMAC256, KDF_KMAC256_NAME,
    };
    assert_eq!(KDF_Counter_HMAC_SHA256::ALG_NAME, KDF_COUNTER_HMAC_SHA256_NAME);
    assert_eq!(KDF_Counter_HMAC_SHA384::ALG_NAME, KDF_COUNTER_HMAC_SHA384_NAME);
    assert_eq!(KDF_Counter_HMAC_SHA512::ALG_NAME, KDF_COUNTER_HMAC_SHA512_NAME);
    assert_eq!(KDF_Counter_CMAC_AES256::ALG_NAME, KDF_COUNTER_CMAC_AES256_NAME);
    assert_eq!(KDF_KMAC128::ALG_NAME, KDF_KMAC128_NAME);
    assert_eq!(KDF_KMAC256::ALG_NAME, KDF_KMAC256_NAME);
    assert_eq!(KDF_Feedback_HMAC_SHA256::ALG_NAME, "KDF-Feedback-HMAC-SHA256");
    assert_eq!(KDF_Feedback_HMAC_SHA3_512::ALG_NAME, "KDF-Feedback-HMAC-SHA3-512");
    assert_eq!(KDF_DoublePipeline_HMAC_SHA512::ALG_NAME, "KDF-DoublePipeline-HMAC-SHA512");
    assert_eq!(KDF_Counter_CMAC_AES128::ALG_NAME, "KDF-Counter-CMAC-AES128");
    assert_eq!(KDF_Counter_CMAC_AES192::ALG_NAME, "KDF-Counter-CMAC-AES192");
    assert_eq!(KDF_Feedback_CMAC_AES256::ALG_NAME, "KDF-Feedback-CMAC-AES256");
    assert_eq!(KDF_DoublePipeline_CMAC_AES128::ALG_NAME, "KDF-DoublePipeline-CMAC-AES128");
    assert_eq!(KDF_Feedback_HMAC_SHA512::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);
    assert_eq!(KDF_DoublePipeline_HMAC_SHA256::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(KDF_Counter_CMAC_AES128::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(KDF_Counter_CMAC_AES192::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(KDF_Feedback_CMAC_AES256::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);
    type Aes<P> = PRF_CMAC<P>;
    use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
    assert_eq!(
        [
            (<Aes<AES128Internal> as Prf>::H_LEN, <Aes<AES128Internal> as Prf>::SEED_LEN),
            (<Aes<AES192Internal> as Prf>::H_LEN, <Aes<AES192Internal> as Prf>::SEED_LEN),
            (<Aes<AES256Internal> as Prf>::H_LEN, <Aes<AES256Internal> as Prf>::SEED_LEN),
        ],
        [(16, 16), (16, 24), (16, 32)]
    );
}

/// A copy keeps its parameters, and nothing is written past `L` bytes: the last block is cut
/// to what is left, whether the buffer is exactly `L` long or longer.
#[test]
fn a_partial_last_block_and_a_copy() {
    let k_in = random(&KEY);
    let pipeline = KDF_DoublePipeline_HMAC_SHA256::with_counter(
        CounterSize::_24bit,
        Position::AfterFixedInput,
    );
    #[allow(clippy::clone_on_copy)]
    let copy = pipeline.clone();
    assert_eq!(copy.counter(), Some((CounterSize::_24bit, Position::AfterFixedInput)));
    let feedback = KDF_Feedback_HMAC_SHA256::with_counter(
        b"iv",
        CounterSize::_8bit,
        Position::BeforeIterationVariable,
    );
    #[allow(clippy::clone_on_copy)]
    let copy = feedback.clone();
    assert_eq!(copy.iv(), Some(&b"iv"[..]));
    assert_eq!(copy.counter(), Some((CounterSize::_8bit, Position::BeforeIterationVariable)));

    for kdf in [&feedback as &dyn KDF, &pipeline] {
        let whole = kdf.derive_key(&k_in, FIXED, 64).unwrap();
        let mut exact = KeyMaterial::<40>::new();
        assert_eq!(kdf.derive_key_out(&k_in, FIXED, 40, &mut exact), Ok(40));
        assert_eq!(exact.ref_to_bytes(), &whole.ref_to_bytes()[..40]);

        let mut roomy = KeyMaterial::<128>::new();
        assert_eq!(kdf.derive_key_out(&k_in, FIXED, 40, &mut roomy), Ok(40));
        let mut capacity = Vec::new();
        do_hazardous_operations(&mut roomy, |k| {
            capacity = k.ref_to_bytes_mut()?.to_vec();
            Ok(())
        })
        .unwrap();
        assert_eq!(&capacity[..40], &whole.ref_to_bytes()[..40]);
        assert_eq!(&capacity[40..], &[0u8; 88], "nothing of the last block is left past L");
    }
}

/// An all-zero key of the cipher's length derives, as the trait says of a `Zeroized` key, and
/// the output is typed `Unknown`.
#[test]
fn cmac_derives_from_an_all_zero_key() {
    let zero =
        KeyMaterial::<32>::from_bytes_as_type(&[0u8; 32], KeyType::CryptographicRandom).unwrap();
    assert_eq!(zero.key_type(), KeyType::Zeroized);
    let out = KDF_Feedback_CMAC_AES256::new(b"").derive_key(&zero, FIXED, 16).unwrap();
    assert_eq!(
        (out.key_type(), out.security_strength()),
        (KeyType::Unknown, SecurityStrength::None)
    );

    let zero =
        KeyMaterial::<16>::from_bytes_as_type(&[0u8; 16], KeyType::CryptographicRandom).unwrap();
    let out = KDF_Counter_CMAC_AES128::with_counter(
        CounterSize::_8bit,
        CounterPosition::BeforeFixedInput,
    )
    .derive_key(&zero, FIXED, 16)
    .unwrap();
    assert_eq!(out.key_type(), KeyType::Unknown);
    // The key object refuses an all-zero MAC key, so there is no by-hand value to compare with
    // here; the output is a function of the key all the same.
    let other = KDF_Counter_CMAC_AES128::new().derive_key(&random(&[1u8; 16]), FIXED, 16).unwrap();
    let again = KDF_Counter_CMAC_AES128::new().derive_key(&zero, FIXED, 16).unwrap();
    assert_ne!(again.ref_to_bytes(), other.ref_to_bytes());
    assert_ne!(again.ref_to_bytes(), out.ref_to_bytes(), "the counter's size is part of the input");
}
