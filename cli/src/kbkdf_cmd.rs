//! The `kbkdf-*` subcommands: key derivation using pseudorandom functions, SP 800-108r1. Each
//! builds its KDF from the mode's flags and hands it to [`kdf_cmd`], so the key-derivation key
//! (`--ikm`), the fixed input data or Context (`--additional-input`), `--len` and the output
//! are the `concatkdf-*` commands'.

use crate::helpers::{SecretBytes, decode_hex_arg, decode_hex_secret, read_secret_file};
use crate::kdf_cmd::kdf_cmd;
use bouncycastle::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::kbkdf::{
    CounterPosition, CounterSize, IterationCounterPosition, KDF_Counter, KDF_DoublePipeline,
    KDF_Feedback, KDF_KMAC128, KDF_KMAC256, PRF_CMAC, PRF_HMAC, Prf,
};
use bouncycastle::sha2::{SHA224, SHA256, SHA384, SHA512};
use bouncycastle::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use clap::ValueEnum;
use std::process::exit;

/// The PRF of an iterated mode (SP 800-108r1 Section 3).
#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum KbkdfPrf {
    #[value(name = "hmac-sha224")]
    HmacSha224,
    #[value(name = "hmac-sha256")]
    HmacSha256,
    #[value(name = "hmac-sha384")]
    HmacSha384,
    #[value(name = "hmac-sha512")]
    HmacSha512,
    #[value(name = "hmac-sha3-224")]
    HmacSha3_224,
    #[value(name = "hmac-sha3-256")]
    HmacSha3_256,
    #[value(name = "hmac-sha3-384")]
    HmacSha3_384,
    #[value(name = "hmac-sha3-512")]
    HmacSha3_512,
    #[value(name = "cmac-aes128")]
    CmacAes128,
    #[value(name = "cmac-aes192")]
    CmacAes192,
    #[value(name = "cmac-aes256")]
    CmacAes256,
}

/// `--counter-position` of `kbkdf-counter`.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq)]
pub(crate) enum CounterPositionArg {
    #[value(name = "before-fixed")]
    Before,
    #[value(name = "after-fixed")]
    After,
    #[value(name = "in-fixed")]
    In,
}

/// `--counter-position` of `kbkdf-feedback` and `kbkdf-double-pipeline`.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum IterationCounterPositionArg {
    BeforeIteration,
    AfterIteration,
    AfterFixed,
}

/// The flags every KDF command shares, as `main` parsed them.
pub(crate) struct KdfInputs<'a> {
    pub(crate) ikm: &'a Option<String>,
    pub(crate) ikm_file: &'a Option<String>,
    pub(crate) additional_input: &'a Option<String>,
    pub(crate) additional_input_file: &'a Option<String>,
    pub(crate) len: usize,
    pub(crate) output_hex: bool,
}

fn usage_error(message: &str) -> ! {
    eprintln!("Error: {message}");
    exit(-1);
}

fn counter_size(bits: u32) -> CounterSize {
    match bits {
        8 => CounterSize::_8bit,
        16 => CounterSize::_16bit,
        24 => CounterSize::_24bit,
        32 => CounterSize::_32bit,
        _ => usage_error("`--counter-bits` must be 8, 16, 24 or 32."),
    }
}

/// The optional counter of the feedback and double-pipeline modes: a position needs a counter,
/// and without one the position is Sections 4.2 and 4.3's, after the iteration variable.
fn iteration_counter(
    counter_bits: Option<u32>,
    counter_position: Option<IterationCounterPositionArg>,
) -> Option<(CounterSize, IterationCounterPosition)> {
    let Some(bits) = counter_bits else {
        if counter_position.is_some() {
            usage_error("`--counter-position` needs `--counter-bits`.");
        }
        return None;
    };
    let position = match counter_position {
        Some(IterationCounterPositionArg::BeforeIteration) => {
            IterationCounterPosition::BeforeIterationVariable
        }
        Some(IterationCounterPositionArg::AfterIteration) | None => {
            IterationCounterPosition::AfterIterationVariable
        }
        Some(IterationCounterPositionArg::AfterFixed) => IterationCounterPosition::AfterFixedInput,
    };
    Some((counter_size(bits), position))
}

fn run(kdf: &dyn bouncycastle::core::traits::KDF, inputs: &KdfInputs) {
    kdf_cmd(
        kdf,
        inputs.ikm,
        inputs.ikm_file,
        inputs.additional_input,
        inputs.additional_input_file,
        inputs.len,
        inputs.output_hex,
    );
}

fn run_counter<P: Prf>(
    r: CounterSize,
    position: CounterPosition,
    key_control_guard: bool,
    inputs: &KdfInputs,
) {
    let kdf = KDF_Counter::<P>::with_counter(r, position);
    let kdf = if key_control_guard { kdf.with_key_control_guard() } else { kdf };
    run(&kdf, inputs);
}

pub(crate) fn kbkdf_counter_cmd(
    prf: KbkdfPrf,
    counter_bits: u32,
    counter_position: CounterPositionArg,
    counter_offset: Option<usize>,
    key_control_guard: bool,
    inputs: &KdfInputs,
) {
    let r = counter_size(counter_bits);
    let position = match (counter_position, counter_offset) {
        (CounterPositionArg::Before, None) => CounterPosition::BeforeFixedInput,
        (CounterPositionArg::After, None) => CounterPosition::AfterFixedInput,
        (CounterPositionArg::In, Some(offset)) => CounterPosition::InFixedInput(offset),
        (CounterPositionArg::In, None) => {
            usage_error("`--counter-position in-fixed` needs `--counter-offset`.")
        }
        (_, Some(_)) => usage_error("`--counter-offset` needs `--counter-position in-fixed`."),
    };
    let guard = key_control_guard;
    match prf {
        KbkdfPrf::HmacSha224 => run_counter::<PRF_HMAC<SHA224>>(r, position, guard, inputs),
        KbkdfPrf::HmacSha256 => run_counter::<PRF_HMAC<SHA256>>(r, position, guard, inputs),
        KbkdfPrf::HmacSha384 => run_counter::<PRF_HMAC<SHA384>>(r, position, guard, inputs),
        KbkdfPrf::HmacSha512 => run_counter::<PRF_HMAC<SHA512>>(r, position, guard, inputs),
        KbkdfPrf::HmacSha3_224 => run_counter::<PRF_HMAC<SHA3_224>>(r, position, guard, inputs),
        KbkdfPrf::HmacSha3_256 => run_counter::<PRF_HMAC<SHA3_256>>(r, position, guard, inputs),
        KbkdfPrf::HmacSha3_384 => run_counter::<PRF_HMAC<SHA3_384>>(r, position, guard, inputs),
        KbkdfPrf::HmacSha3_512 => run_counter::<PRF_HMAC<SHA3_512>>(r, position, guard, inputs),
        KbkdfPrf::CmacAes128 => run_counter::<PRF_CMAC<AES128Internal>>(r, position, guard, inputs),
        KbkdfPrf::CmacAes192 => run_counter::<PRF_CMAC<AES192Internal>>(r, position, guard, inputs),
        KbkdfPrf::CmacAes256 => run_counter::<PRF_CMAC<AES256Internal>>(r, position, guard, inputs),
    }
}

/// `iv` is `None` for Section 4.2's guard against key control, which derives the IV.
fn run_feedback<P: Prf>(
    iv: Option<&[u8]>,
    counter: Option<(CounterSize, IterationCounterPosition)>,
    inputs: &KdfInputs,
) {
    let kdf = match (iv, counter) {
        (Some(iv), None) => KDF_Feedback::<P>::new(iv),
        (Some(iv), Some((r, position))) => KDF_Feedback::<P>::with_counter(iv, r, position),
        (None, Some((r, position))) => KDF_Feedback::<P>::with_key_control_guard(r, position),
        (None, None) => usage_error("`--key-control-guard` needs `--counter-bits`."),
    };
    run(&kdf, inputs);
}

pub(crate) fn kbkdf_feedback_cmd(
    prf: KbkdfPrf,
    iv: &Option<String>,
    iv_file: &Option<String>,
    counter_bits: Option<u32>,
    counter_position: Option<IterationCounterPositionArg>,
    key_control_guard: bool,
    inputs: &KdfInputs,
) {
    let counter = iteration_counter(counter_bits, counter_position);
    if key_control_guard && (iv.is_some() || iv_file.is_some()) {
        usage_error(
            "`--key-control-guard` derives the IV and cannot be used with `--iv` or `--iv-file`.",
        );
    }
    if key_control_guard && counter.is_none() {
        usage_error("`--key-control-guard` needs `--counter-bits`.");
    }
    // Section 4: the IV "can be either public or secret", so it is held in the wiped container
    // the key is, from the file when one is named.
    let iv_bytes = match (iv_file, iv) {
        (Some(file), _) => read_secret_file(file),
        (None, Some(hex_str)) => decode_hex_secret(hex_str, "iv"),
        (None, None) => SecretBytes::new(),
    };
    let iv = if key_control_guard { None } else { Some(iv_bytes.ref_to_bytes()) };
    match prf {
        KbkdfPrf::HmacSha224 => run_feedback::<PRF_HMAC<SHA224>>(iv, counter, inputs),
        KbkdfPrf::HmacSha256 => run_feedback::<PRF_HMAC<SHA256>>(iv, counter, inputs),
        KbkdfPrf::HmacSha384 => run_feedback::<PRF_HMAC<SHA384>>(iv, counter, inputs),
        KbkdfPrf::HmacSha512 => run_feedback::<PRF_HMAC<SHA512>>(iv, counter, inputs),
        KbkdfPrf::HmacSha3_224 => run_feedback::<PRF_HMAC<SHA3_224>>(iv, counter, inputs),
        KbkdfPrf::HmacSha3_256 => run_feedback::<PRF_HMAC<SHA3_256>>(iv, counter, inputs),
        KbkdfPrf::HmacSha3_384 => run_feedback::<PRF_HMAC<SHA3_384>>(iv, counter, inputs),
        KbkdfPrf::HmacSha3_512 => run_feedback::<PRF_HMAC<SHA3_512>>(iv, counter, inputs),
        KbkdfPrf::CmacAes128 => run_feedback::<PRF_CMAC<AES128Internal>>(iv, counter, inputs),
        KbkdfPrf::CmacAes192 => run_feedback::<PRF_CMAC<AES192Internal>>(iv, counter, inputs),
        KbkdfPrf::CmacAes256 => run_feedback::<PRF_CMAC<AES256Internal>>(iv, counter, inputs),
    }
}

fn run_double_pipeline<P: Prf>(
    counter: Option<(CounterSize, IterationCounterPosition)>,
    inputs: &KdfInputs,
) {
    let kdf = match counter {
        Some((r, position)) => KDF_DoublePipeline::<P>::with_counter(r, position),
        None => KDF_DoublePipeline::<P>::new(),
    };
    run(&kdf, inputs);
}

pub(crate) fn kbkdf_double_pipeline_cmd(
    prf: KbkdfPrf,
    counter_bits: Option<u32>,
    counter_position: Option<IterationCounterPositionArg>,
    inputs: &KdfInputs,
) {
    let counter = iteration_counter(counter_bits, counter_position);
    match prf {
        KbkdfPrf::HmacSha224 => run_double_pipeline::<PRF_HMAC<SHA224>>(counter, inputs),
        KbkdfPrf::HmacSha256 => run_double_pipeline::<PRF_HMAC<SHA256>>(counter, inputs),
        KbkdfPrf::HmacSha384 => run_double_pipeline::<PRF_HMAC<SHA384>>(counter, inputs),
        KbkdfPrf::HmacSha512 => run_double_pipeline::<PRF_HMAC<SHA512>>(counter, inputs),
        KbkdfPrf::HmacSha3_224 => run_double_pipeline::<PRF_HMAC<SHA3_224>>(counter, inputs),
        KbkdfPrf::HmacSha3_256 => run_double_pipeline::<PRF_HMAC<SHA3_256>>(counter, inputs),
        KbkdfPrf::HmacSha3_384 => run_double_pipeline::<PRF_HMAC<SHA3_384>>(counter, inputs),
        KbkdfPrf::HmacSha3_512 => run_double_pipeline::<PRF_HMAC<SHA3_512>>(counter, inputs),
        KbkdfPrf::CmacAes128 => run_double_pipeline::<PRF_CMAC<AES128Internal>>(counter, inputs),
        KbkdfPrf::CmacAes192 => run_double_pipeline::<PRF_CMAC<AES192Internal>>(counter, inputs),
        KbkdfPrf::CmacAes256 => run_double_pipeline::<PRF_CMAC<AES256Internal>>(counter, inputs),
    }
}

/// The two KMAC functions of Section 4.4.
pub(crate) enum KbkdfKmac {
    KMAC128,
    KMAC256,
}

pub(crate) fn kbkdf_kmac_cmd(
    variant: KbkdfKmac,
    label: &Option<String>,
    label_hex: &Option<String>,
    inputs: &KdfInputs,
) {
    let label = match (label, label_hex) {
        (Some(_), Some(_)) => usage_error("`--label` and `--label-hex` cannot both be given."),
        (Some(text), None) => text.as_bytes().to_vec(),
        (None, Some(hex_str)) => decode_hex_arg(hex_str, "label-hex"),
        (None, None) => Vec::new(),
    };
    match variant {
        KbkdfKmac::KMAC128 => run(&KDF_KMAC128::new(&label), inputs),
        KbkdfKmac::KMAC256 => run(&KDF_KMAC256::new(&label), inputs),
    }
}
