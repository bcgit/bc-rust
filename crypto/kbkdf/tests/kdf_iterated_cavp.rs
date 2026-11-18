//! NIST CAVP "SP800-108 - KDF" feedback and double-pipeline vectors (in
//! `bc-test-data/crypto/cavp`): `KDFFeedbackCounter_gen.rsp`, `KDFFeedbackNoIV_gen.rsp` and
//! `KDFFeedbackNoCounter_gen.rsp` for Section 4.2, `KDFDblPipelineCounter_gen.rsp` and
//! `KDFDblPipelineNoCounter_gen.rsp` for Section 4.3. Every HMAC-SHA224, -SHA256, -SHA384 and
//! -SHA512 record and every CMAC-AES128, -AES192 and -AES256 record is run; the HMAC-SHA1 and
//! CMAC-TDEA records are counted, so that a change in what is skipped is noticed.

mod common;

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::KDF;
use bouncycastle_kbkdf::{
    CounterSize, IterationCounterPosition, KDF_DoublePipeline, KDF_Feedback, PRF_CMAC, PRF_HMAC,
    Prf,
};
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};
use common::Record;

#[derive(Clone, Copy)]
enum Mode {
    Feedback,
    DoublePipeline,
}

fn counter(r: &Record) -> Option<(CounterSize, IterationCounterPosition)> {
    let position = match r.ctr_location.as_str() {
        "" => return None,
        "BEFORE_ITER" => IterationCounterPosition::BeforeIterationVariable,
        "AFTER_ITER" => IterationCounterPosition::AfterIterationVariable,
        "AFTER_FIXED" => IterationCounterPosition::AfterFixedInput,
        other => panic!("unexpected counter location {other}"),
    };
    Some((r.r.unwrap(), position))
}

fn check<P: Prf>(mode: Mode, r: &Record) {
    let ki = KeyMaterial::<64>::from_bytes_as_type(&r.ki, KeyType::CryptographicRandom).unwrap();
    let mut out = KeyMaterial::<512>::new();
    let written = match (mode, counter(r)) {
        (Mode::Feedback, None) => {
            KDF_Feedback::<P>::new(&r.iv).derive_key_out(&ki, &r.fixed, r.len, &mut out)
        }
        (Mode::Feedback, Some((size, position))) => {
            KDF_Feedback::<P>::with_counter(&r.iv, size, position)
                .derive_key_out(&ki, &r.fixed, r.len, &mut out)
        }
        (Mode::DoublePipeline, None) => {
            KDF_DoublePipeline::<P>::new().derive_key_out(&ki, &r.fixed, r.len, &mut out)
        }
        (Mode::DoublePipeline, Some((size, position))) => {
            KDF_DoublePipeline::<P>::with_counter(size, position)
                .derive_key_out(&ki, &r.fixed, r.len, &mut out)
        }
    }
    .unwrap_or_else(|e| panic!("{}: {e:?}", r.name()));
    assert_eq!(written, r.len, "{}", r.name());
    assert_eq!(out.ref_to_bytes(), r.ko.as_slice(), "{}", r.name());
}

/// Runs a file and returns (checked, HMAC-SHA1 records, CMAC-TDEA records, records with an IV).
fn run(mode: Mode, filename: &str) -> (usize, usize, usize, usize) {
    let (mut checked, mut sha1, mut tdea, mut with_iv) = (0, 0, 0, 0);
    for r in &common::load(filename) {
        assert!(r.fixed_after.is_empty(), "no file here splits the fixed input data");
        with_iv += usize::from(!r.iv.is_empty());
        match r.prf.as_str() {
            "HMAC_SHA224" => check::<PRF_HMAC<SHA224>>(mode, r),
            "HMAC_SHA256" => check::<PRF_HMAC<SHA256>>(mode, r),
            "HMAC_SHA384" => check::<PRF_HMAC<SHA384>>(mode, r),
            "HMAC_SHA512" => check::<PRF_HMAC<SHA512>>(mode, r),
            "CMAC_AES128" => check::<PRF_CMAC<AES128Internal>>(mode, r),
            "CMAC_AES192" => check::<PRF_CMAC<AES192Internal>>(mode, r),
            "CMAC_AES256" => check::<PRF_CMAC<AES256Internal>>(mode, r),
            "HMAC_SHA1" => {
                sha1 += 1;
                continue;
            }
            "CMAC_TDES2" | "CMAC_TDES3" => {
                tdea += 1;
                continue;
            }
            other => panic!("unexpected PRF {other}"),
        }
        checked += 1;
    }
    (checked, sha1, tdea, with_iv)
}

// In each file every PRF has the same number of records; seven PRFs are run, HMAC-SHA1 is one
// and CMAC-TDEA two. The last figure is the records with a non-empty IV.

#[test]
fn cavp_feedback_mode() {
    assert_eq!(run(Mode::Feedback, "KDFFeedbackCounter_gen.rsp"), (3360, 480, 960, 2400));
    assert_eq!(run(Mode::Feedback, "KDFFeedbackNoIV_gen.rsp"), (3360, 480, 960, 4800));
    assert_eq!(run(Mode::Feedback, "KDFFeedbackNoCounter_gen.rsp"), (280, 40, 80, 200));
}

#[test]
fn cavp_double_pipeline_mode() {
    assert_eq!(run(Mode::DoublePipeline, "KDFDblPipelineCounter_gen.rsp"), (3360, 480, 960, 0));
    assert_eq!(run(Mode::DoublePipeline, "KDFDblPipelineNoCounter_gen.rsp"), (280, 40, 80, 0));
}
