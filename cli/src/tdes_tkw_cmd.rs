//! TDEA key wrap: `tdes-tkw -d encrypt|decrypt` (three-key, both directions) and
//! `tdes2-tkw -d decrypt` (two-key, unwrapping only), stdin to stdout.
//!
//! They are the `aes*-kw` command over TDEA (NIST SP 800-38F Sec 7, TKW), so everything in
//! [`crate::kw_cmd`] -- the whole-input reading, the absence of an IV, the fail-closed unwrap
//! -- applies unchanged, at half the width: the input is a whole number of 4-byte semiblocks, at
//! least 8 bytes, and the output is 4 bytes longer. `encrypt` has the SP 800-67 Rev 2 Sec 3.4
//! bound the other `tdes-*` encrypting commands have, counted as blocks TDEA processes: TW makes
//! six calls per 4-byte semiblock, so the input may be at most 699,048 bytes
//! ([`TDEA_LIMIT_TKW`]). TKW is approved for legacy systems only (SP 800-38F Sec 8), and two-key
//! TDEA may not wrap at all (SP 800-131A Rev 2 Table 6), so `tdes2-tkw` has no `encrypt`, as the
//! other `tdes2-*` commands have none.

use crate::helpers::block_mode_helpers::{
    CipherDirection, DecryptOnlyAction, TDEA_LIMIT_TKW, load_key_object,
};
use crate::kw_cmd::{run, run_with};
use bouncycastle::cipher::modes::TKW;
use bouncycastle::core::symmetric_key::KeyUnwrappingKey;
use bouncycastle::tdes::{KEY_LEN, KEY_LEN_2KEY, TDES2Key, TDES3Key};

pub(crate) fn tdes_tkw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, KEY_LEN>(
        direction,
        &load_key_object::<TDES3Key<TKW>, KEY_LEN>(key, key_file, "TDES"),
        Some(&TDEA_LIMIT_TKW),
        output_hex,
        "TDES-TKW",
    );
}

pub(crate) fn tdes2_tkw_cmd(
    action: &DecryptOnlyAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let DecryptOnlyAction::Decrypt = action;
    let kek = load_key_object::<TDES2Key<TKW>, KEY_LEN_2KEY>(key, key_file, "two-key TDES");
    run_with(|input| kek.unwrap(input), None, output_hex, "two-key TDES-TKW");
}
