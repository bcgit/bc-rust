//! NIST CAVP "SP800-108 - KDF" counter-mode vectors (`KDFCTR_gen.rsp` in
//! `bc-test-data/crypto/cavp`): every HMAC-SHA224, -SHA256, -SHA384 and -SHA512 record and
//! every CMAC-AES128, -AES192 and -AES256 record, at counter sizes of 8, 16, 24 and 32 bits
//! with the counter before, after and in the middle of the fixed input data. The other PRFs'
//! records are counted, so that a change in what is skipped is noticed: HMAC-SHA1 (the
//! library's release has no SHA-1) and CMAC over TDEA (not a PRF this crate has).

mod common;

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::KDF;
use bouncycastle_kbkdf::{CounterPosition, KDF_Counter, PRF_CMAC, PRF_HMAC, Prf};
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};
use common::Record;

fn check<P: Prf>(r: &Record) {
    let (fixed, position) = match r.ctr_location.as_str() {
        "BEFORE_FIXED" => (r.fixed.clone(), CounterPosition::BeforeFixedInput),
        "AFTER_FIXED" => (r.fixed.clone(), CounterPosition::AfterFixedInput),
        "MIDDLE_FIXED" => (
            [r.fixed.as_slice(), &r.fixed_after].concat(),
            CounterPosition::InFixedInput(r.fixed.len()),
        ),
        other => panic!("unexpected counter location {other}"),
    };
    let kdf = KDF_Counter::<P>::with_counter(r.r.unwrap(), position);
    let ki = KeyMaterial::<64>::from_bytes_as_type(&r.ki, KeyType::CryptographicRandom).unwrap();
    let mut out = KeyMaterial::<64>::new();
    let written = kdf
        .derive_key_out(&ki, &fixed, r.len, &mut out)
        .unwrap_or_else(|e| panic!("{}: {e:?}", r.name()));
    assert_eq!(written, r.len, "{}", r.name());
    assert_eq!(out.ref_to_bytes(), r.ko.as_slice(), "{}", r.name());
}

#[test]
fn cavp_counter_mode() {
    let records = common::load("KDFCTR_gen.rsp");
    let (mut checked, mut sha1, mut tdea) = (0usize, 0usize, 0usize);
    for r in &records {
        match r.prf.as_str() {
            "HMAC_SHA224" => check::<PRF_HMAC<SHA224>>(r),
            "HMAC_SHA256" => check::<PRF_HMAC<SHA256>>(r),
            "HMAC_SHA384" => check::<PRF_HMAC<SHA384>>(r),
            "HMAC_SHA512" => check::<PRF_HMAC<SHA512>>(r),
            "HMAC_SHA1" => {
                sha1 += 1;
                continue;
            }
            "CMAC_AES128" => check::<PRF_CMAC<AES128Internal>>(r),
            "CMAC_AES192" => check::<PRF_CMAC<AES192Internal>>(r),
            "CMAC_AES256" => check::<PRF_CMAC<AES256Internal>>(r),
            "CMAC_TDES2" | "CMAC_TDES3" => {
                tdea += 1;
                continue;
            }
            other => panic!("unexpected PRF {other}"),
        }
        checked += 1;
    }
    // Ten PRFs, each with three counter locations, four counter sizes and forty records.
    assert_eq!((checked, sha1, tdea), (3360, 480, 960));
}
