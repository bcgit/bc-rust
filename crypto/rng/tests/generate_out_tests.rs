//! [`Sp80090ADrbg::generate_out`] over a DRBG seeded by the caller: its output buffer contract,
//! SP 800-90A Rev. 1's limit on one request, and its agreement with `generate` where the `alloc`
//! feature provides that. Nothing here draws from the operating system, so the suite runs
//! without the crate's `std` feature.

use bouncycastle_core::errors::RNGError;
use bouncycastle_core::key_material::{KeyMaterial0, KeyMaterial256, KeyMaterial512, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_rng::hazmat::NewUninitialized;
use bouncycastle_rng::{HashDRBG_SHA256, HashDRBG_SHA512, Sp80090ADrbg};

fn sha256_instance() -> HashDRBG_SHA256 {
    let mut drbg = HashDRBG_SHA256::new_uninitialized();
    let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
    drbg.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();
    drbg
}

fn sha512_instance() -> HashDRBG_SHA512 {
    let mut drbg = HashDRBG_SHA512::new_uninitialized();
    let seed = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::Seed).unwrap();
    drbg.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_256bit).unwrap();
    drbg
}

/// Lengths below, at and above one hash block of either hash, with the empty request.
const LENS: [usize; 9] = [0, 1, 31, 32, 33, 64, 65, 200, 1024];

/// `generate` is `generate_out` into a fresh buffer: two instances from one seed, driven through
/// the same requests, return the same bytes, with and without additional input.
#[cfg(feature = "alloc")]
#[test]
fn generate_and_generate_out_agree() {
    fn check<D: Sp80090ADrbg>(mut a: D, mut b: D) {
        for additional_input in [&[][..], &b"additional input"[..]] {
            for len in LENS {
                let returned = a.generate(additional_input, len).unwrap();
                let mut out = [0u8; 1024];
                assert_eq!(b.generate_out(additional_input, &mut out[..len]).unwrap(), len);
                assert_eq!(returned.len(), len);
                assert_eq!(returned, &out[..len]);
                assert!(len < 32 || returned.iter().any(|&byte| byte != 0));
            }
        }
    }
    check(sha256_instance(), sha256_instance());
    check(sha512_instance(), sha512_instance());
}

/// The whole buffer is the output: what it held before the call has no effect on it, and the
/// count returned is the buffer's length.
#[test]
fn stale_buffer_contents_do_not_reach_the_output() {
    for len in LENS {
        let (mut a, mut b) = (sha256_instance(), sha256_instance());
        let (mut clean, mut stale) = ([0u8; 1024], [0xAAu8; 1024]);
        assert_eq!(a.generate_out(&[], &mut clean[..len]).unwrap(), len);
        assert_eq!(b.generate_out(&[], &mut stale[..len]).unwrap(), len);
        assert_eq!(clean[..len], stale[..len]);
        // Nothing past the slice handed in is written.
        assert!(stale[len..].iter().all(|&byte| byte == 0xAA));
    }
}

/// An error leaves the buffer zeroized: Section 9.3.1 returns "a Null string" with any status
/// other than SUCCESS.
#[test]
fn an_error_leaves_the_buffer_zeroized() {
    // Before instantiation.
    let mut drbg = HashDRBG_SHA256::new_uninitialized();
    let mut out = [0xAAu8; 48];
    assert_eq!(drbg.generate_out(&[], &mut out), Err(RNGError::Uninitialized));
    assert_eq!(out, [0u8; 48]);

    // Over the limit on one request.
    let mut drbg = sha512_instance();
    let mut out = vec![0xAAu8; 65537];
    assert!(matches!(drbg.generate_out(&[], &mut out), Err(RNGError::GenericError(_))));
    assert!(out.iter().all(|&byte| byte == 0));
}

/// Table 2: `max_number_of_bits_per_request` is 2^19 bits, 65536 bytes, for both hashes. A
/// request at the limit is served in full; one byte more is refused and draws nothing, so the
/// instance goes on as one that was never asked.
#[test]
fn the_per_request_limit_is_on_the_buffer_length() {
    fn check<D: Sp80090ADrbg>(mut a: D, mut b: D) {
        let mut out = vec![0u8; 65537];
        assert_eq!(a.generate_out(&[], &mut out[..65536]).unwrap(), 65536);
        // The last hash block of the request was written.
        assert!(out[65536 - 32..65536].iter().any(|&byte| byte != 0));

        assert!(matches!(a.generate_out(&[], &mut out), Err(RNGError::GenericError(_))));
        let mut after_refusal = [0u8; 32];
        a.generate_out(&[], &mut after_refusal).unwrap();

        let mut expected = [0u8; 32];
        b.generate_out(&[], &mut out[..65536]).unwrap();
        b.generate_out(&[], &mut expected).unwrap();
        assert_eq!(after_refusal, expected);
    }
    check(sha256_instance(), sha256_instance());
    check(sha512_instance(), sha512_instance());
}

/// A request for no bytes is still a request (Section 10.1.1.4 steps 4 to 6 run): the stream
/// that follows it differs from the stream without it.
#[test]
fn an_empty_request_advances_the_state() {
    let (mut a, mut b) = (sha256_instance(), sha256_instance());
    assert_eq!(a.generate_out(&[], &mut []).unwrap(), 0);
    let (mut after_empty, mut first) = ([0u8; 32], [0u8; 32]);
    a.generate_out(&[], &mut after_empty).unwrap();
    b.generate_out(&[], &mut first).unwrap();
    assert_ne!(after_empty, first);
}
