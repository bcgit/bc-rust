//! scrypt over working memory the caller supplies: the part of the crate that exists with and
//! without the `std` feature, so this file runs in both configurations.

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_scrypt::{SCrypt, ScryptParams};

mod common;
use common::{RFC_7914, password};

/// RFC 7914 Section 12, the three vectors that fit a test run, with memory one byte longer
/// than needed and dirty: what is used is wiped, what is not is left alone.
#[test]
fn rfc_7914_section_12_in_caller_memory() {
    for (index, (p, s, log2_n, r, par, dk)) in RFC_7914.iter().take(3).enumerate() {
        let expected = hex_decode(dk).unwrap();
        let params = ScryptParams::new(*log2_n, *r, *par).unwrap();
        let mut work = vec![0xEEu8; params.work_len() + 1];
        let mut out = KeyMaterial::<64>::new();
        let written =
            SCrypt::new(s, params).derive_with_memory_out(&password(p), 64, &mut work, &mut out);
        assert_eq!(written, Ok(64), "vector {index}");
        assert_eq!(out.ref_to_bytes(), &expected[..], "vector {index}");
        assert!(work[..params.work_len()].iter().all(|b| *b == 0), "vector {index}");
        assert_eq!(work[params.work_len()], 0xEE, "vector {index}");
    }
}

#[test]
fn bad_requests_are_refused_in_caller_memory() {
    let p = password(b"password");
    let params = ScryptParams::new(4, 1, 1).unwrap();
    let kdf = SCrypt::new(b"salt", params);
    let stale = || {
        let mut out = KeyMaterial::<32>::new();
        out.set_bytes_as_type(&[0xAA; 32], KeyType::CryptographicRandom).unwrap();
        out
    };
    let mut work = vec![0xEEu8; params.work_len()];

    let short = params.work_len() - 1;
    let mut out = stale();
    assert_eq!(
        kdf.derive_with_memory_out(&p, 16, &mut work[..short], &mut out),
        Err(KDFError::InvalidLength("the working memory is shorter than work_len"))
    );
    assert_eq!(out.key_len(), 0);

    let mut out = stale();
    assert_eq!(
        kdf.derive_with_memory_out(&p, 0, &mut work, &mut out),
        Err(KDFError::InvalidLength("a zero-length derivation is refused"))
    );
    assert_eq!(out.key_len(), 0);
    assert!(work.iter().all(|b| *b == 0), "the working memory is wiped on a refusal too");

    let mut out = stale();
    assert_eq!(
        kdf.derive_with_memory_out(&p, 33, &mut work, &mut out),
        Err(KDFError::InvalidLength("the output buffer cannot hold dkLen bytes"))
    );
    assert_eq!(out.key_len(), 0);

    // The memory limit is the allocating path's: it does not bound memory the caller supplies.
    let mut out = stale();
    assert_eq!(
        kdf.with_max_work_len(1).derive_with_memory_out(&p, 32, &mut work, &mut out),
        Ok(32)
    );
}
