//! ARIA key wrap and key wrap with padding: `aria{128,192,256}-{kw,kwp} -d encrypt|decrypt`,
//! stdin to stdout.
//!
//! They are the `aes*-kw` and `aes*-kwp` commands over the ARIA permutation (RFC 5794; the
//! `id-aria*-kw` and `id-aria*-kwp` algorithms of its Appendix B), so everything in
//! [`crate::aes_kw_cmd`] -- the whole-input reading, the absence of an IV, the input-length rules
//! and the fail-closed unwrap -- applies unchanged; only the key type differs.

use crate::aes_kw_cmd::run;
use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use bouncycastle::aria::{ARIA128Key, ARIA192Key, ARIA256Key};
use bouncycastle::cipher::modes::{KW, KWP};

pub(crate) fn aria128_kw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        direction,
        &load_key_object::<ARIA128Key<KW>, 16>(key, key_file, "ARIA-128-KW"),
        None,
        output_hex,
        "ARIA-128-KW",
    );
}

pub(crate) fn aria192_kw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        direction,
        &load_key_object::<ARIA192Key<KW>, 24>(key, key_file, "ARIA-192-KW"),
        None,
        output_hex,
        "ARIA-192-KW",
    );
}

pub(crate) fn aria256_kw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        direction,
        &load_key_object::<ARIA256Key<KW>, 32>(key, key_file, "ARIA-256-KW"),
        None,
        output_hex,
        "ARIA-256-KW",
    );
}

pub(crate) fn aria128_kwp_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        direction,
        &load_key_object::<ARIA128Key<KWP>, 16>(key, key_file, "ARIA-128-KWP"),
        None,
        output_hex,
        "ARIA-128-KWP",
    );
}

pub(crate) fn aria192_kwp_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        direction,
        &load_key_object::<ARIA192Key<KWP>, 24>(key, key_file, "ARIA-192-KWP"),
        None,
        output_hex,
        "ARIA-192-KWP",
    );
}

pub(crate) fn aria256_kwp_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        direction,
        &load_key_object::<ARIA256Key<KWP>, 32>(key, key_file, "ARIA-256-KWP"),
        None,
        output_hex,
        "ARIA-256-KWP",
    );
}
