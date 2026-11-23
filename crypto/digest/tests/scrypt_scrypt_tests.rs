//! scrypt against RFC 7914 Section 12's vectors, with the parameter rules of Section 2, the
//! working memory, the limits and the typing of the output.

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::hex::decode as hex_decode;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KDF};
use bouncycastle_digest::scrypt::{DEFAULT_MAX_WORK_LEN, SCRYPT_NAME, SCrypt, ScryptParams};

#[path = "scrypt_common/mod.rs"]
mod common;
use common::{RFC_7914, password};

fn check(index: usize) {
    let (p, s, log2_n, r, par, dk) = RFC_7914[index];
    let expected = hex_decode(dk).unwrap();
    let params = ScryptParams::new(log2_n, r, par).unwrap();
    let kdf = SCrypt::new(s, params);

    // With the caller's working memory, one byte more than needed and dirty.
    let mut work = vec![0xEEu8; params.work_len() + 1];
    let mut out = KeyMaterial::<64>::new();
    assert_eq!(kdf.derive_with_memory_out(&password(p), 64, &mut work, &mut out), Ok(64));
    assert_eq!(out.ref_to_bytes(), &expected[..], "vector {index}");
    // What was used is wiped; what was not is left alone.
    assert!(work[..params.work_len()].iter().all(|b| *b == 0), "vector {index}");
    assert_eq!(work[params.work_len()], 0xEE);

    // Through the trait, which allocates.
    let kdf = kdf.with_max_work_len(params.work_len());
    assert_eq!(kdf.derive_key(&password(p), &[], 64).unwrap().ref_to_bytes(), &expected[..]);
}

#[test]
fn rfc_7914_section_12() {
    check(0);
    check(1);
    check(2);
}

/// The fourth vector needs 1 GiB of working memory and a minute or more unoptimised.
#[test]
#[ignore]
fn rfc_7914_section_12_n_1048576() {
    check(3);
}

/// Section 2: N "must be larger than 1, a power of 2, and less than 2^(128 * r / 8)"; p is "a
/// positive integer less than or equal to ((2^32-1) * 32) / (128 * r)".
#[test]
fn the_parameter_rules() {
    let bad = |log2_n: u8, r: u32, p: u32, what: &str| {
        assert!(
            matches!(ScryptParams::new(log2_n, r, p), Err(KDFError::InvalidLength(_))),
            "{what}"
        );
    };
    bad(0, 8, 1, "N = 1");
    bad(14, 0, 1, "r = 0");
    bad(14, 8, 0, "p = 0");
    // N < 2^(16 * r): with r = 1, N = 2^15 is the largest.
    assert!(ScryptParams::new(15, 1, 1).is_ok());
    bad(16, 1, 1, "N = 2^16 with r = 1");
    // p <= ((2^32 - 1) * 32) / (128 * r): 1073741823 for r = 1 and 134217727 for r = 8.
    assert!(ScryptParams::new(1, 1, 1_073_741_823).is_ok());
    bad(1, 1, 1_073_741_824, "p past its bound for r = 1");
    assert!(ScryptParams::new(1, 8, 134_217_727).is_ok());
    bad(1, 8, 134_217_728, "p past its bound for r = 8");
    // Working memory that does not fit the platform.
    bad(63, 8, 1, "N = 2^63");

    let params = ScryptParams::new(14, 8, 2).unwrap();
    assert_eq!((params.log2_n(), params.r(), params.p()), (14, 8, 2));
    // 128 * r * (N + p + 1).
    assert_eq!(params.work_len(), 128 * 8 * (16384 + 2 + 1));
    assert_eq!(ScryptParams::new(4, 1, 1).unwrap().work_len(), 128 * (16 + 1 + 1));
    assert_eq!(params, ScryptParams::new(14, 8, 2).unwrap());
    assert_ne!(params, ScryptParams::new(14, 8, 1).unwrap());
}

#[test]
fn bad_requests_are_refused_with_the_buffer_zeroized() {
    let p = password(b"password");
    let params = ScryptParams::new(4, 1, 1).unwrap();
    let kdf = SCrypt::new(b"salt", params);
    let stale = || {
        let mut out = KeyMaterial::<32>::new();
        out.set_bytes_as_type(&[0xAA; 32], KeyType::CryptographicRandom).unwrap();
        out
    };
    let refused = |r: Result<usize, KDFError>, out: &KeyMaterial<32>, what: &str| {
        assert!(matches!(r, Err(KDFError::InvalidLength(_))), "{what}");
        assert_eq!((out.key_type(), out.key_len()), (KeyType::Zeroized, 0), "{what}");
    };
    let mut work = vec![0u8; params.work_len()];

    // Working memory one byte short.
    let mut out = stale();
    let short = params.work_len() - 1;
    refused(kdf.derive_with_memory_out(&p, 16, &mut work[..short], &mut out), &out, "short work");
    // Exactly enough.
    let mut out = stale();
    assert_eq!(kdf.derive_with_memory_out(&p, 32, &mut work, &mut out), Ok(32));
    let good = out.ref_to_bytes().to_vec();

    let mut out = stale();
    work.fill(0xEE);
    refused(kdf.derive_with_memory_out(&p, 0, &mut work, &mut out), &out, "a zero length");
    assert!(work.iter().all(|b| *b == 0), "the working memory is wiped on a refusal too");
    let mut out = stale();
    refused(kdf.derive_with_memory_out(&p, 33, &mut work, &mut out), &out, "past the buffer");
    let mut out = stale();
    assert_eq!(
        kdf.derive_with_memory_out(&p, 32 * 0xFFFF_FFFF + 1, &mut work, &mut out),
        Err(KDFError::InvalidLength("derived key too long"))
    );
    assert_eq!(
        kdf.derive_with_memory_out(&p, 32 * 0xFFFF_FFFF, &mut work, &mut out),
        Err(KDFError::InvalidLength("the output buffer cannot hold dkLen bytes"))
    );

    // The trait: the same, and no keys, fixed info and the memory limit besides.
    let mut out = stale();
    refused(kdf.derive_key_out(&p, &[], 0, &mut out), &out, "zero, trait");
    let mut out = stale();
    refused(kdf.derive_key_from_multiple_out(&[], &[], 16, &mut out), &out, "no keys");
    let mut out = stale();
    refused(kdf.derive_key_out(&p, b"info", 16, &mut out), &out, "fixed info");
    let mut out = stale();
    refused(kdf.derive_key_from_multiple_out(&[&p], b"i", 16, &mut out), &out, "fixed info");
    let limited = kdf.with_max_work_len(params.work_len() - 1);
    assert_eq!(limited.max_work_len(), params.work_len() - 1);
    let mut out = stale();
    refused(limited.derive_key_out(&p, &[], 16, &mut out), &out, "over the memory limit");
    // The limit does not bound memory the caller supplies.
    let mut out = stale();
    assert_eq!(limited.derive_with_memory_out(&p, 32, &mut work, &mut out), Ok(32));
    assert_eq!(out.ref_to_bytes(), &good[..]);
    // Working memory that cannot be allocated is an error, not an abort: these parameters need
    // more than `isize::MAX` bytes, which no allocation can be. The length is checked first, so
    // a request that would be refused anyway does not reach the allocation.
    #[cfg(target_pointer_width = "64")]
    {
        let huge = ScryptParams::new(36, 1 << 20, 1).unwrap();
        assert!(huge.work_len() > isize::MAX as usize);
        let unlimited = SCrypt::new(b"salt", huge).with_max_work_len(usize::MAX);
        let mut out = stale();
        assert_eq!(
            unlimited.derive_key_out(&p, &[], 16, &mut out),
            Err(KDFError::GenericError("the working memory could not be allocated"))
        );
        assert_eq!(out.key_len(), 0, "the buffer is cleared when the allocation fails");
        let mut out = stale();
        refused(unlimited.derive_key_out(&p, &[], 0, &mut out), &out, "zero, before allocating");
        let mut out = stale();
        assert_eq!(
            unlimited.derive_key_from_multiple_out(&[], &[], 16, &mut out),
            Err(KDFError::InvalidLength("a derivation from no keys is refused"))
        );
        assert_eq!(out.key_len(), 0);
        let mut small = KeyMaterial::<8>::new();
        assert_eq!(
            unlimited.derive_key_out(&p, &[], 16, &mut small),
            Err(KDFError::InvalidLength("the output buffer cannot hold dkLen bytes"))
        );
    }
    // At the limit, the trait derives the same key, and as a trait object.
    let at_limit = kdf.with_max_work_len(params.work_len());
    let dyn_kdf: &dyn KDF = &at_limit;
    assert_eq!(dyn_kdf.derive_key(&p, &[], 32).unwrap().ref_to_bytes(), &good[..]);
    // The password as two keys is their concatenation.
    let (a, b) = (password(b"pass"), password(b"word"));
    assert_eq!(kdf.derive_key_from_multiple(&[&a, &b], &[], 32).unwrap().ref_to_bytes(), &good[..]);
}

/// The salt and each parameter change the key, and p blocks are each mixed.
#[test]
fn every_input_counts() {
    let p = password(b"password");
    let derive = |salt: &[u8], log2_n: u8, r: u32, par: u32| {
        SCrypt::new(salt, ScryptParams::new(log2_n, r, par).unwrap())
            .derive_key(&p, &[], 32)
            .unwrap()
            .ref_to_bytes()
            .to_vec()
    };
    let base = derive(b"salt", 4, 2, 2);
    assert_ne!(base, derive(b"salT", 4, 2, 2));
    assert_ne!(base, derive(b"salt", 5, 2, 2));
    assert_ne!(base, derive(b"salt", 4, 3, 2));
    assert_ne!(base, derive(b"salt", 4, 2, 3));
    assert_ne!(base, derive(b"salt", 4, 2, 1));
    assert_eq!(base, derive(b"salt", 4, 2, 2));
}

/// A password credits nothing, so its key is `Unknown`; full-entropy keying material gives
/// `CryptographicRandom`, capped by HMAC-SHA256's strength and the length's.
#[test]
fn the_output_is_typed_from_the_input() {
    let kdf = SCrypt::new(b"salt", ScryptParams::new(4, 1, 1).unwrap());
    let out = kdf.derive_key(&password(b"correct horse battery staple"), &[], 32).unwrap();
    assert_eq!(
        (out.key_type(), out.security_strength()),
        (KeyType::Unknown, SecurityStrength::None)
    );

    let mut k = KeyMaterial::<64>::from_bytes_as_type(&[0x33; 64], KeyType::SharedSecret).unwrap();
    do_hazardous_operations(&mut k, |k| k.set_security_strength(SecurityStrength::_256bit))
        .unwrap();
    let out = kdf.derive_key(&k, &[], 64).unwrap();
    assert_eq!(
        (out.key_type(), out.security_strength()),
        (KeyType::CryptographicRandom, SecurityStrength::_128bit)
    );
}

#[test]
fn names_parameters_and_description() {
    assert_eq!(SCrypt::ALG_NAME, "scrypt");
    assert_eq!(SCRYPT_NAME, "scrypt");
    assert_eq!(SCrypt::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(DEFAULT_MAX_WORK_LEN, 256 * 1024 * 1024);

    let params = ScryptParams::new(5, 2, 3).unwrap();
    let kdf = SCrypt::new(b"the salt", params);
    assert_eq!(kdf.salt(), b"the salt");
    assert_eq!(kdf.params(), params);
    assert_eq!(kdf.max_work_len(), DEFAULT_MAX_WORK_LEN);
    let engine = kdf.with_max_work_len(1 << 20).engine().unwrap();
    assert_eq!(
        (engine.salt(), engine.params(), engine.max_work_len()),
        (&b"the salt"[..], params, 1 << 20)
    );
    let p = password(b"pw");
    assert_eq!(
        engine.derive_key(&p, &[], 40).unwrap().ref_to_bytes(),
        kdf.derive_key(&p, &[], 40).unwrap().ref_to_bytes()
    );
}
