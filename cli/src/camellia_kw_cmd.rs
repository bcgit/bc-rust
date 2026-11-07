//! Camellia key wrap: `camellia{128,192,256}-kw -d encrypt|decrypt`, stdin to stdout.
//!
//! They are the `aes*-kw` commands over the Camellia permutation (RFC 3657 Sec 3, the
//! `id-camellia*-wrap` algorithms), so everything in [`crate::aes_kw_cmd`] -- the whole-input
//! reading, the absence of an IV, the input-length rules and the fail-closed unwrap -- applies
//! unchanged; only the key type differs. RFC 3657 specifies no padded form, so there is no
//! `camellia*-kwp`.

use crate::aes_kw_cmd::run;
use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use bouncycastle::camellia::{Camellia128Key, Camellia192Key, Camellia256Key};
use bouncycastle::cipher::modes::KW;

pub(crate) fn camellia128_kw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        direction,
        &load_key_object::<Camellia128Key<KW>, 16>(key, key_file, "Camellia-128-KW"),
        output_hex,
        "Camellia-128-KW",
    );
}

pub(crate) fn camellia192_kw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        direction,
        &load_key_object::<Camellia192Key<KW>, 24>(key, key_file, "Camellia-192-KW"),
        output_hex,
        "Camellia-192-KW",
    );
}

pub(crate) fn camellia256_kw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        direction,
        &load_key_object::<Camellia256Key<KW>, 32>(key, key_file, "Camellia-256-KW"),
        output_hex,
        "Camellia-256-KW",
    );
}
