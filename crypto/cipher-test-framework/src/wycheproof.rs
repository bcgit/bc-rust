//! The Project Wycheproof sets through the key, one key length per call: a cipher crate calls a
//! runner once per key length it has and sums the counts. Each runner returns `None` when the
//! Wycheproof checkout is absent (`core-test-framework`'s loader warns and the test passes), so a
//! caller writes `let Some(counts) = ... else { return };`.
//!
//! Only the cases of the call's key length are run; the others are left to the other calls, and
//! a case no call can take -- an `InvalidKeySize` CMAC key -- is counted through
//! [`cases_with_other_key_lengths`].

use crate::Permutation;
use crate::material::{cipher_key, mac_key};
use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::{CBC, CCM, CMAC, GCM, GCM_NONCE_LEN, GMAC};
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_core::errors::{PaddingError, SymmetricCipherError};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, AeadDecryptionKey, AeadEncryptionKey,
    FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey, MacGenerationKey, MacVerificationKey,
    NonceMacGenerationKey, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    MACGenerator, MACVerifier, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};
use bouncycastle_rng::FixedSeedRNG;
use core::ops::Add;

const BLOCK_LEN: usize = 16;

/// What a run did: the cases it ran, split by the file's verdict, and the cases it could not
/// dispatch because their parameters have no instantiation (an IV length `Gcm` does not take, a
/// CCM nonce or tag size outside SP 800-38C A.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// `result: "valid"` cases run.
    pub valid: usize,
    /// `result: "invalid"` cases run.
    pub invalid: usize,
    /// Cases whose shape has no instantiation to dispatch to.
    pub unsupported: usize,
}

impl Counts {
    /// The cases run.
    pub fn run(&self) -> usize {
        self.valid + self.invalid
    }
}

impl Add for Counts {
    type Output = Counts;
    fn add(self, o: Counts) -> Counts {
        Counts {
            valid: self.valid + o.valid,
            invalid: self.invalid + o.invalid,
            unsupported: self.unsupported + o.unsupported,
        }
    }
}

fn groups(doc: &Value) -> &Vec<Value> {
    doc.get("testGroups").and_then(Value::as_array).expect("testGroups")
}

fn tests(group: &Value) -> &Vec<Value> {
    group.get("tests").and_then(Value::as_array).expect("tests")
}

fn tc_id(test: &Value) -> u64 {
    test.get("tcId").and_then(Value::as_u64).expect("tcId")
}

fn result(test: &Value, tc_id: u64) -> bool {
    match test.get("result").and_then(Value::as_str).expect("result") {
        "valid" => true,
        "invalid" => false,
        other => panic!("tcId {tc_id}: unexpected result {other}"),
    }
}

fn flags(test: &Value) -> Vec<&str> {
    test.get("flags")
        .and_then(Value::as_array)
        .expect("flags")
        .iter()
        .map(|f| f.as_str().expect("flag"))
        .collect()
}

fn check_algorithm(doc: &Value, algorithm: &str) {
    assert_eq!(
        doc.get("algorithm").and_then(Value::as_str),
        Some(algorithm),
        "this is the {algorithm} vector file"
    );
}

/// What a CBC-PKCS5 run did: the valid cases, and the invalid ones by what their flags say is
/// wrong -- a final block that does not unpad (`BadPadding`), or no final block at all
/// (`NoPadding`, an empty ciphertext).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CbcCounts {
    /// `result: "valid"` cases run.
    pub valid: usize,
    /// `BadPadding` cases run.
    pub bad_padding: usize,
    /// `NoPadding` cases run.
    pub no_final_block: usize,
}

impl Add for CbcCounts {
    type Output = CbcCounts;
    fn add(self, o: CbcCounts) -> CbcCounts {
        CbcCounts {
            valid: self.valid + o.valid,
            bad_padding: self.bad_padding + o.bad_padding,
            no_final_block: self.no_final_block + o.no_final_block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CbcExpected {
    Valid,
    BadPadding,
    NoFinalBlock,
}

/// One CBC-PKCS5 case through `BlockCipherKey<P, CBC<PKCS7>>`. A valid case must encrypt to
/// exactly `expected_ct` under the vector's IV and decrypt back; an invalid case is checked on
/// the decrypt side only and must fail with the error its flags predict, leaving the output
/// buffer zeroized.
fn cbc_case<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(
    tc_id: u64,
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    msg: &[u8],
    expected_ct: &[u8],
    expected: CbcExpected,
) {
    type K<P> = BlockCipherKey<P, CBC<PKCS7>>;
    let key = K::<P>::from_key_material(&cipher_key::<KEY_LEN>(key_bytes))
        .unwrap_or_else(|e| panic!("tcId {tc_id}: the key should be accepted: {e:?}"));

    if expected == CbcExpected::Valid {
        let ct_len = <<K<P> as SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>>::Encryptor<
            '_,
        > as SymmetricCipherEncryptor<BLOCK_LEN, BLOCK_LEN>>::encrypt_out_len(msg.len());
        let mut ct = vec![0u8; ct_len];
        let (written, got_iv) = key
            .encrypt_out(&mut FixedSeedRNG::new(iv), msg, &mut ct)
            .unwrap_or_else(|e| panic!("tcId {tc_id}: valid case failed to encrypt: {e:?}"));
        assert_eq!(got_iv, iv, "tcId {tc_id}: the seeded RNG must reproduce the vector's IV");
        ct.truncate(written);
        assert_eq!(ct, expected_ct, "tcId {tc_id}: ciphertext mismatch");
    }

    // Pre-filled with a non-zero byte, so a buffer the decryptor never wrote is not mistaken for
    // one it zeroized.
    let pt_len = <<K<P> as SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>>::Decryptor<
        '_,
    > as SymmetricCipherDecryptor<BLOCK_LEN, BLOCK_LEN>>::decrypt_out_len(expected_ct.len());
    let mut plaintext = vec![0xEEu8; pt_len];
    let outcome = key.decrypt_out(&iv, expected_ct, &mut plaintext);
    if outcome.is_err() {
        assert!(
            plaintext.iter().all(|&b| b == 0),
            "tcId {tc_id}: a failed decrypt must leave the output buffer zeroized"
        );
    }
    match (expected, outcome) {
        (CbcExpected::Valid, Ok(n)) => {
            plaintext.truncate(n);
            assert_eq!(plaintext, msg, "tcId {tc_id}: decrypted plaintext mismatch");
        }
        (CbcExpected::BadPadding, Err(SymmetricCipherError::PaddingError(e))) => {
            assert_eq!(
                e,
                PaddingError::InvalidPadding,
                "tcId {tc_id}: bad padding must be refused"
            );
        }
        (CbcExpected::NoFinalBlock, Err(SymmetricCipherError::DecryptionFailed)) => {}
        (expected, outcome) => panic!("tcId {tc_id}: expected {expected:?}, got {outcome:?}"),
    }
}

/// A `*_cbc_pkcs5_test.json` set through `BlockCipherKey<P, CBC<PKCS7>>` at one key length. The
/// file's "PKCS #5" is PKCS #7 at a 16-byte block; two thirds of it is `invalid`, each case
/// failing with the error its flags predict.
pub fn cbc_pkcs7<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(
    file: &str,
    algorithm: &str,
) -> Option<CbcCounts> {
    let doc = wycheproof_json(file)?;
    check_algorithm(&doc, algorithm);
    let mut counts = CbcCounts::default();
    for group in groups(&doc) {
        let iv_size_bits = group.get("ivSize").and_then(Value::as_u64).expect("ivSize");
        assert_eq!(iv_size_bits as usize, 8 * BLOCK_LEN, "CBC's IV is one block");
        for test in tests(group) {
            let tc_id = tc_id(test);
            let key_bytes = hex_field(test, "key", tc_id);
            if key_bytes.len() != KEY_LEN {
                continue;
            }
            let iv: [u8; BLOCK_LEN] = hex_field(test, "iv", tc_id)
                .try_into()
                .unwrap_or_else(|_| panic!("tcId {tc_id}: the IV must be one block"));
            let msg = hex_field(test, "msg", tc_id);
            let ct = hex_field(test, "ct", tc_id);
            let flags = flags(test);
            // The flags say *how* an invalid case is invalid, and so which error it must produce.
            let expected = match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => CbcExpected::Valid,
                "invalid" if flags.contains(&"BadPadding") => CbcExpected::BadPadding,
                "invalid" if flags.contains(&"NoPadding") => CbcExpected::NoFinalBlock,
                other => panic!("tcId {tc_id}: unexpected result/flags {other} {flags:?}"),
            };
            cbc_case::<P, KEY_LEN>(tc_id, &key_bytes, iv, &msg, &ct, expected);
            match expected {
                CbcExpected::Valid => counts.valid += 1,
                CbcExpected::BadPadding => counts.bad_padding += 1,
                CbcExpected::NoFinalBlock => counts.no_final_block += 1,
            }
        }
    }
    println!(
        "Wycheproof {algorithm} at {KEY_LEN} bytes: {} valid, {} bad-padding and {} \
         empty-ciphertext cases run",
        counts.valid, counts.bad_padding, counts.no_final_block
    );
    Some(counts)
}

/// One CCM case at a fully-instantiated `(KEY_LEN, NONCE_LEN, TAG_LEN)`, through the key's
/// detached in-place one-shots. A valid case must encrypt to exactly the vector's ciphertext and
/// tag and decrypt back; an invalid case is checked on the decrypt side only and must fail the
/// tag check, leaving the buffer zeroized.
#[allow(clippy::too_many_arguments)]
fn ccm_case<P, const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>(
    tc_id: u64,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad: &[u8],
    msg: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8],
    valid: bool,
) where
    P: Permutation<KEY_LEN>,
    BlockCipherKey<P, CCM<NONCE_LEN, TAG_LEN>>: AeadDeclaredEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>
        + AeadDeclaredDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>,
{
    let key = BlockCipherKey::<P, CCM<NONCE_LEN, TAG_LEN>>::from_key_material(
        &cipher_key::<KEY_LEN>(key_bytes),
    )
    .expect("a wycheproof key");
    let nonce: [u8; NONCE_LEN] =
        nonce_bytes.try_into().unwrap_or_else(|_| panic!("tcId {tc_id}: bad nonce length"));
    let tag: [u8; TAG_LEN] =
        expected_tag.try_into().unwrap_or_else(|_| panic!("tcId {tc_id}: bad tag length"));

    if valid {
        let mut ct = msg.to_vec();
        let got_tag = key
            .encrypt_detached_in_place_nonce(&nonce, aad, &mut ct)
            .unwrap_or_else(|e| panic!("tcId {tc_id}: valid case failed to encrypt: {e:?}"));
        assert_eq!(ct, expected_ct, "tcId {tc_id}: ciphertext mismatch");
        assert_eq!(got_tag, tag, "tcId {tc_id}: tag mismatch");
    }

    let mut plaintext = expected_ct.to_vec();
    match key.decrypt_detached_in_place(&nonce, aad, &mut plaintext, &tag) {
        Ok(()) => {
            assert!(valid, "tcId {tc_id}: an invalid vector decrypted and verified anyway");
            assert_eq!(plaintext, msg, "tcId {tc_id}: decrypted plaintext mismatch");
        }
        Err(SymmetricCipherError::AEADTagCheckFailed) => {
            assert!(!valid, "tcId {tc_id}: a valid vector failed its tag check");
            assert!(
                plaintext.iter().all(|&b| b == 0),
                "tcId {tc_id}: a failed tag check must leave the output buffer zeroized"
            );
        }
        Err(e) => panic!("tcId {tc_id}: unexpected CCM error: {e:?}"),
    }
}

/// Dispatches a CCM case to one of the 7 (nonce) x 7 (tag) instantiations SP 800-38C A.1 permits,
/// or reports that its sizes have none.
#[allow(clippy::too_many_arguments)]
fn ccm_dispatch<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(
    tc_id: u64,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad: &[u8],
    msg: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8],
    valid: bool,
) -> bool {
    macro_rules! with_tag_len {
        ($n:literal) => {
            match expected_tag.len() {
                4 => ccm_case::<P, KEY_LEN, $n, 4>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                6 => ccm_case::<P, KEY_LEN, $n, 6>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                8 => ccm_case::<P, KEY_LEN, $n, 8>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                10 => ccm_case::<P, KEY_LEN, $n, 10>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                12 => ccm_case::<P, KEY_LEN, $n, 12>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                14 => ccm_case::<P, KEY_LEN, $n, 14>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                16 => ccm_case::<P, KEY_LEN, $n, 16>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                _ => return false,
            }
        };
    }
    match nonce_bytes.len() {
        7 => with_tag_len!(7),
        8 => with_tag_len!(8),
        9 => with_tag_len!(9),
        10 => with_tag_len!(10),
        11 => with_tag_len!(11),
        12 => with_tag_len!(12),
        13 => with_tag_len!(13),
        _ => return false,
    }
    true
}

/// A `*_ccm_test.json` set through `BlockCipherKey<P, CCM<N, T>>` at one key length. The set is
/// adversarial: most of its nonce and tag sizes are outside A.1's sets, so most of it has no
/// instantiation and is counted as unsupported; the cases within them must encrypt, decrypt or
/// fail the tag check as the file says.
pub fn ccm<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(file: &str) -> Option<Counts> {
    let doc = wycheproof_json(file)?;
    let mut counts = Counts::default();
    for group in groups(&doc) {
        for test in tests(group) {
            let tc_id = tc_id(test);
            let key_bytes = hex_field(test, "key", tc_id);
            if key_bytes.len() != KEY_LEN {
                continue;
            }
            let nonce_bytes = hex_field(test, "iv", tc_id);
            let aad = hex_field(test, "aad", tc_id);
            let msg = hex_field(test, "msg", tc_id);
            let ct = hex_field(test, "ct", tc_id);
            let tag = hex_field(test, "tag", tc_id);
            let valid = result(test, tc_id);
            // Each case is dispatched on its own actual field lengths, not the group's declared
            // sizes: a `Pseudorandom` group's whole point is varying them per test.
            if ccm_dispatch::<P, KEY_LEN>(
                tc_id, &key_bytes, &nonce_bytes, &aad, &msg, &ct, &tag, valid,
            ) {
                if valid { counts.valid += 1 } else { counts.invalid += 1 }
            } else {
                counts.unsupported += 1;
            }
        }
    }
    println!(
        "Wycheproof {file} at {KEY_LEN} bytes: {} cases run ({} valid, {} invalid), {} not \
         supported (no A.1 instantiation)",
        counts.run(),
        counts.valid,
        counts.invalid,
        counts.unsupported
    );
    Some(counts)
}

/// One GCM case through the key's detached pair at the 96-bit nonce and 128-bit tag. A valid
/// case must encrypt to exactly the vector's ciphertext and tag under its IV, supplied through a
/// `FixedSeedRNG` and checked, and decrypt back; an invalid case is checked on the decrypt side
/// only and must fail the tag check, leaving the buffer zeroized.
#[allow(clippy::too_many_arguments)]
fn gcm_case<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(
    tc_id: u64,
    key_bytes: &[u8],
    iv: [u8; GCM_NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8],
    valid: bool,
) {
    let key = BlockCipherKey::<P, GCM>::from_key_material(&cipher_key::<KEY_LEN>(key_bytes))
        .expect("a wycheproof key");
    let tag: [u8; 16] =
        expected_tag.try_into().unwrap_or_else(|_| panic!("tcId {tc_id}: bad tag length"));

    if valid {
        let mut ct = vec![0u8; msg.len()];
        let (written, got_iv, got_tag) = key
            .encrypt_detached_out(&mut FixedSeedRNG::new(iv), aad, msg, &mut ct)
            .unwrap_or_else(|e| panic!("tcId {tc_id}: valid case failed to encrypt: {e:?}"));
        assert_eq!(got_iv, iv, "tcId {tc_id}: the seeded RNG must reproduce the vector's IV");
        assert_eq!(written, msg.len(), "tcId {tc_id}: encrypt_detached writes exactly msg.len()");
        assert_eq!(ct, expected_ct, "tcId {tc_id}: ciphertext mismatch");
        assert_eq!(got_tag, tag, "tcId {tc_id}: tag mismatch");
    }

    let mut plaintext = vec![0xEEu8; expected_ct.len()];
    match key.decrypt_detached_out(&iv, aad, expected_ct, &tag, &mut plaintext) {
        Ok(n) => {
            assert!(valid, "tcId {tc_id}: an invalid vector decrypted and verified anyway");
            plaintext.truncate(n);
            assert_eq!(plaintext, msg, "tcId {tc_id}: decrypted plaintext mismatch");
        }
        Err(SymmetricCipherError::AEADTagCheckFailed) => {
            assert!(!valid, "tcId {tc_id}: a valid vector failed its tag check");
            assert!(
                plaintext.iter().all(|&b| b == 0),
                "tcId {tc_id}: a failed tag check must leave the output buffer zeroized"
            );
        }
        Err(e) => panic!("tcId {tc_id}: unexpected GCM error: {e:?}"),
    }
}

/// A `*_gcm_test.json` set through `BlockCipherKey<P, GCM>` at one key length. `Gcm` fixes the
/// nonce at 96 bits and every group in these files uses a 128-bit tag, so a case with any other
/// IV length -- most of the file, which probes exactly that boundary -- has no instantiation and
/// is counted as unsupported.
pub fn gcm<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(
    file: &str,
    algorithm: &str,
) -> Option<Counts> {
    let doc = wycheproof_json(file)?;
    check_algorithm(&doc, algorithm);
    let mut counts = Counts::default();
    for group in groups(&doc) {
        for test in tests(group) {
            let tc_id = tc_id(test);
            let key_bytes = hex_field(test, "key", tc_id);
            if key_bytes.len() != KEY_LEN {
                continue;
            }
            let iv_bytes = hex_field(test, "iv", tc_id);
            let aad = hex_field(test, "aad", tc_id);
            let msg = hex_field(test, "msg", tc_id);
            let ct = hex_field(test, "ct", tc_id);
            let tag = hex_field(test, "tag", tc_id);
            let valid = result(test, tc_id);
            // The nonce length is fixed by the type, so a case is dispatched on its actual `iv`.
            match <[u8; GCM_NONCE_LEN]>::try_from(iv_bytes.as_slice()) {
                Ok(iv) if tag.len() == 16 => {
                    gcm_case::<P, KEY_LEN>(tc_id, &key_bytes, iv, &aad, &msg, &ct, &tag, valid);
                    if valid { counts.valid += 1 } else { counts.invalid += 1 }
                }
                _ => counts.unsupported += 1,
            }
        }
    }
    println!(
        "Wycheproof {algorithm} at {KEY_LEN} bytes: {} cases run ({} valid, {} invalid), {} not \
         supported (no 96-bit-IV instantiation)",
        counts.run(),
        counts.valid,
        counts.invalid,
        counts.unsupported
    );
    Some(counts)
}

/// GCM over AAD alone is GMAC, so a `*_gcm_test.json` file's valid empty-message cases with a
/// 96-bit IV and a 128-bit tag are GMAC known answers; they run through
/// `BlockCipherKey<P, GMAC>`'s generator under the vector's IV. Returns the cases run.
pub fn gmac_from_empty_gcm_cases<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(
    file: &str,
) -> Option<usize> {
    let doc = wycheproof_json(file)?;
    let mut run = 0usize;
    for group in groups(&doc) {
        for test in tests(group) {
            let tc_id = tc_id(test);
            let key_bytes = hex_field(test, "key", tc_id);
            let msg = hex_field(test, "msg", tc_id);
            let iv = hex_field(test, "iv", tc_id);
            let tag = hex_field(test, "tag", tc_id);
            if key_bytes.len() != KEY_LEN
                || !result(test, tc_id)
                || !msg.is_empty()
                || iv.len() != GCM_NONCE_LEN
                || tag.len() != 16
            {
                continue;
            }
            let aad = hex_field(test, "aad", tc_id);
            let iv: [u8; GCM_NONCE_LEN] = iv.try_into().unwrap();
            let got: [u8; 16] =
                BlockCipherKey::<P, GMAC>::from_key_material(&mac_key::<KEY_LEN>(&key_bytes))
                    .unwrap()
                    .mac_nonce(&iv, &aad);
            assert_eq!(got.as_slice(), tag.as_slice(), "tcId {tc_id}: GMAC tag mismatch");
            run += 1;
        }
    }
    println!("Wycheproof {file} at {KEY_LEN} bytes: {run} empty-message cases run as GMAC");
    Some(run)
}

/// One CMAC case through the key's one-shots and its workers: every group is a 128-bit tag,
/// the block, so the tag goes straight into the array the roles take.
fn cmac_case<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(
    tc_id: u64,
    key: &[u8],
    msg: &[u8],
    tag: &[u8],
    valid: bool,
) {
    let key = BlockCipherKey::<P, CMAC>::from_key_material(&mac_key::<KEY_LEN>(key))
        .unwrap_or_else(|e| panic!("tcId {tc_id}: {e:?}"));
    let tag: [u8; 16] = tag.try_into().unwrap_or_else(|_| panic!("tcId {tc_id}: a 16-byte tag"));
    let full = key.mac(msg);
    assert_eq!(full == tag, valid, "tcId {tc_id}");
    assert_eq!(key.verify(msg, &tag).is_ok(), valid, "tcId {tc_id}: via the key's one-shot");
    let mut verifier = key.create_verifier();
    verifier.do_update(msg);
    assert_eq!(verifier.do_verify_final(&tag).is_ok(), valid, "tcId {tc_id}: via the worker");
    if valid {
        let mut generator = key.create_generator();
        generator.do_update(msg);
        assert_eq!(generator.do_final(), tag, "tcId {tc_id}: via the worker");
    }
}

/// A `*_cmac_test.json` set through `BlockCipherKey<P, CMAC>` at one key length; every group is
/// a 128-bit tag. `unsupported` stays zero: the file's `InvalidKeySize` cases have no key length
/// to run at, and [`cases_with_other_key_lengths`] counts them.
pub fn cmac<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(file: &str) -> Option<Counts> {
    let doc = wycheproof_json(file)?;
    let mut counts = Counts::default();
    for group in groups(&doc) {
        assert_eq!(group["tagSize"].as_u64(), Some(128));
        for test in tests(group) {
            let tc_id = tc_id(test);
            let key = hex_field(test, "key", tc_id);
            if key.len() != KEY_LEN {
                continue;
            }
            let msg = hex_field(test, "msg", tc_id);
            let tag = hex_field(test, "tag", tc_id);
            let valid = result(test, tc_id);
            cmac_case::<P, KEY_LEN>(tc_id, &key, &msg, &tag, valid);
            if valid { counts.valid += 1 } else { counts.invalid += 1 }
        }
    }
    println!(
        "Wycheproof {file} at {KEY_LEN} bytes: {} valid, {} invalid tags",
        counts.valid, counts.invalid
    );
    Some(counts)
}

/// The cases of `file` whose key length is none of `supported`, each asserted `invalid`: the
/// `InvalidKeySize` cases, which no key type takes since the length is in the type.
pub fn cases_with_other_key_lengths(file: &str, supported: &[usize]) -> Option<usize> {
    let doc = wycheproof_json(file)?;
    let mut count = 0usize;
    for group in groups(&doc) {
        for test in tests(group) {
            let tc_id = tc_id(test);
            let key = hex_field(test, "key", tc_id);
            if supported.contains(&key.len()) {
                continue;
            }
            assert!(!result(test, tc_id), "tcId {tc_id}: a key of {} bytes", key.len());
            count += 1;
        }
    }
    Some(count)
}

/// One key-wrap case: a `valid` case must wrap to the given ciphertext and unwrap back; an
/// `invalid` or `acceptable` case's ciphertext must not unwrap, and where its plaintext is one
/// the algorithm is not defined on (`WrongDataSize`, `EmptyKey`, `ShortKey`) wrapping must refuse
/// it as well.
fn kw_case<K, const KEY_LEN: usize>(tc_id: u64, key: &[u8], msg: &[u8], ct: &[u8], test: &Value)
where
    K: FromKeyMaterial<KEY_LEN> + KeyWrappingKey<KEY_LEN> + KeyUnwrappingKey<KEY_LEN>,
{
    let material = KeyMaterial::<KEY_LEN>::from_bytes_as_type(key, KeyType::SymmetricCipherKey)
        .expect("a symmetric cipher key of the group's length");
    let kek = K::from_key_material(&material).unwrap();
    let flags = flags(test);
    match test["result"].as_str().unwrap() {
        "valid" => {
            assert_eq!(kek.wrap(msg).unwrap(), ct, "tcId {tc_id}: wrap");
            assert_eq!(kek.unwrap(ct).unwrap(), msg, "tcId {tc_id}: unwrap");
        }
        "invalid" | "acceptable" => {
            assert!(kek.unwrap(ct).is_err(), "tcId {tc_id}: the ciphertext must not unwrap");
            if flags.iter().any(|f| ["WrongDataSize", "EmptyKey", "ShortKey"].contains(f)) {
                assert!(
                    matches!(kek.wrap(msg), Err(SymmetricCipherError::InvalidInputLength(_))),
                    "tcId {tc_id}: a plaintext of {} bytes is not a key-wrap input",
                    msg.len()
                );
            }
        }
        other => panic!("tcId {tc_id}: unexpected result {other}"),
    }
}

/// A `*_wrap_test.json` (KW) or `*_kwp_test.json` (KWP) set through `BlockCipherKey<P, M>` at
/// one key length. The `ShortKey` cases, an 8-byte key wrapped as the one block RFC 3394 allows
/// and SP 800-38F does not, are `acceptable`: this library follows SP 800-38F and rejects them,
/// which the suite permits. Returns the cases run.
pub fn key_wrap<P, M, const KEY_LEN: usize>(file: &str) -> Option<usize>
where
    P: Permutation<KEY_LEN>,
    M: Mode<P>,
    BlockCipherKey<P, M>: KeyWrappingKey<KEY_LEN> + KeyUnwrappingKey<KEY_LEN>,
{
    let doc = wycheproof_json(file)?;
    let mut count = 0usize;
    for group in groups(&doc) {
        for test in tests(group) {
            let tc_id = tc_id(test);
            let key = hex_field(test, "key", tc_id);
            if key.len() != KEY_LEN {
                continue;
            }
            let msg = hex_field(test, "msg", tc_id);
            let ct = hex_field(test, "ct", tc_id);
            kw_case::<BlockCipherKey<P, M>, KEY_LEN>(tc_id, &key, &msg, &ct, test);
            count += 1;
        }
    }
    println!("Wycheproof {file} at {KEY_LEN} bytes: {count} cases");
    Some(count)
}
