//! Project Wycheproof's `aes_gcm_siv_test.json` through `AES128Key<GCM_SIV>` and
//! `AES256Key<GCM_SIV>`, via the shared runner: the valid cases in both directions, and the
//! modified-tag cases failing the tag check with the buffer zeroized. Requires the Wycheproof
//! repository at `../wycheproof`; absent, the test warns and passes.

use bouncycastle_aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_cipher_test_framework::wycheproof;

#[test]
fn wycheproof_aes_gcm_siv_known_answer_tests() {
    const FILE: &str = "aes_gcm_siv_test.json";
    let Some(aes128) = wycheproof::gcm_siv::<AES128Internal, 16>(FILE) else { return };
    let aes256 = wycheproof::gcm_siv::<AES256Internal, 32>(FILE).expect("the file was found above");
    // As of Wycheproof 0.9rc5 the file is 99 cases at 128 bits (67 valid, 32 invalid) and 103 at
    // 256 (69 valid, 34 invalid), every one a 12-byte nonce and a 16-byte tag.
    for counts in [aes128, aes256] {
        assert!(counts.valid > 0, "expected at least some valid cases to be run");
        assert!(counts.invalid > 0, "expected at least some invalid (tag-failure) cases to be run");
    }
    // No valid case is left to a key length the mode does not have.
    wycheproof::cases_with_other_key_lengths(FILE, &[16, 32]).expect("the file was found above");
}
