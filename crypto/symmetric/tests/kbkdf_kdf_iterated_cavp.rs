//! NIST CAVP "SP800-108 - KDF" feedback and double-pipeline vectors (in
//! `bc-test-data/crypto/cavp`): `KDFFeedbackCounter_gen.rsp`, `KDFFeedbackNoIV_gen.rsp` and
//! `KDFFeedbackNoCounter_gen.rsp` for Section 4.2, `KDFDblPipelineCounter_gen.rsp` and
//! `KDFDblPipelineNoCounter_gen.rsp` for Section 4.3. Every HMAC-SHA224, -SHA256, -SHA384 and
//! -SHA512 record and every CMAC-AES128, -AES192 and -AES256 record is run; the HMAC-SHA1 and
//! CMAC-TDEA records are counted, so that a change in what is skipped is noticed.

#[path = "kbkdf_common/mod.rs"]
mod common;

use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::KDF;
use bouncycastle_symmetric::kbkdf::{
    CounterSize, IterationCounterPosition, KDF_DoublePipeline, KDF_Feedback, Prf,
};
use common::{Check, Record};

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

impl Check for Mode {
    fn check<P: Prf>(&self, r: &Record) {
        let ki =
            KeyMaterial::<64>::from_bytes_as_type(&r.ki, KeyType::CryptographicRandom).unwrap();
        let mut out = KeyMaterial::<512>::new();
        let written = match (self, counter(r)) {
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
}

/// Runs a file and returns (checked, HMAC-SHA1 records, CMAC-TDEA records, records with an IV).
fn run(mode: Mode, filename: &str) -> (usize, usize, usize, usize) {
    let records = common::load(filename);
    assert!(
        records.iter().all(|r| r.fixed_after.is_empty()),
        "no file here splits the fixed input data"
    );
    let with_iv = records.iter().filter(|r| !r.iv.is_empty()).count();
    let (checked, sha1, tdea) = common::check_each(&records, &mode);
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
