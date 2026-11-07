//! SM4 key wrap and key wrap with padding: `sm4-kw` and `sm4-kwp`, `-d encrypt|decrypt`, stdin
//! to stdout.
//!
//! They are the `aes128-kw` and `aes128-kwp` commands over the SM4 permutation (GM/T 0006's
//! `sms4_wrap` and `sms4_wrap_pad`), so everything in [`crate::aes_kw_cmd`] -- the whole-input
//! reading, the absence of an IV, the input-length rules and the fail-closed unwrap -- applies
//! unchanged; only the key type differs.

use crate::aes_kw_cmd::run;
use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use bouncycastle::cipher::modes::{KW, KWP};
use bouncycastle::sm4::{KEY_LEN, SM4Key};

pub(crate) fn sm4_kw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, KEY_LEN>(
        direction,
        &load_key_object::<SM4Key<KW>, KEY_LEN>(key, key_file, "SM4-KW"),
        None,
        output_hex,
        "SM4-KW",
    );
}

pub(crate) fn sm4_kwp_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, KEY_LEN>(
        direction,
        &load_key_object::<SM4Key<KWP>, KEY_LEN>(key, key_file, "SM4-KWP"),
        None,
        output_hex,
        "SM4-KWP",
    );
}
