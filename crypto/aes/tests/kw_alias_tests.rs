//! Tests for the AES-KW and AES-KWP aliases.
//!
//! These are only type aliases, so what is worth testing here is that each names the right
//! permutation and key length -- a 16-byte KEK for `AES_KW_128` and so on -- and that they run
//! the shared key-wrap framework. The algorithms themselves, and the RFC 3394 / RFC 5649 / ACVP
//! vectors, are tested in `bouncycastle-modes`.

use bouncycastle_aes::aes_internal::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_aes::{AES_KW_128, AES_KW_192, AES_KW_256, AES_KWP_128, AES_KWP_192, AES_KWP_256};
use bouncycastle_core::traits::Algorithm;
use bouncycastle_core_test_framework::key_wrap::TestFrameworkKeyWrap;

/// The alias carries its permutation's name and strength, as the other mode aliases do.
#[test]
fn the_aliases_name_the_expected_permutation() {
    assert_eq!(AES_KW_128::ALG_NAME, AES128Internal::ALG_NAME);
    assert_eq!(AES_KW_192::ALG_NAME, AES192Internal::ALG_NAME);
    assert_eq!(AES_KW_256::ALG_NAME, AES256Internal::ALG_NAME);
    assert_eq!(AES_KWP_128::ALG_NAME, AES128Internal::ALG_NAME);
    assert_eq!(AES_KWP_192::ALG_NAME, AES192Internal::ALG_NAME);
    assert_eq!(AES_KWP_256::ALG_NAME, AES256Internal::ALG_NAME);

    assert_eq!(AES_KW_128::MAX_SECURITY_STRENGTH, AES128Internal::MAX_SECURITY_STRENGTH);
    assert_eq!(AES_KW_256::MAX_SECURITY_STRENGTH, AES256Internal::MAX_SECURITY_STRENGTH);
    assert_eq!(AES_KWP_192::MAX_SECURITY_STRENGTH, AES192Internal::MAX_SECURITY_STRENGTH);
}

/// Each alias conforms to the shared framework under its own KEK length, wrapping a 256-bit key.
#[test]
fn the_aliases_conform_to_the_key_wrap_framework() {
    let tf = TestFrameworkKeyWrap::new();
    tf.test::<16, 32, 40, AES_KW_128>();
    tf.test::<24, 32, 40, AES_KW_192>();
    tf.test::<32, 32, 40, AES_KW_256>();
    tf.test::<16, 32, 40, AES_KWP_128>();
    tf.test::<24, 32, 40, AES_KWP_192>();
    tf.test::<32, 32, 40, AES_KWP_256>();
    // ... and KWP something that is not a whole number of semiblocks.
    tf.test::<16, 33, 48, AES_KWP_128>();
    tf.test::<32, 7, 16, AES_KWP_256>();
}
