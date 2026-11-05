//! TDEA key wrap: `tdes-tkw -d encrypt|decrypt` (three-key, both directions) and
//! `tdes2-tkw -d decrypt` (two-key, unwrapping only), stdin to stdout.
//!
//! They are the `aes*-kw` command over TDEA (NIST SP 800-38F Sec 7, TKW), so everything in
//! [`crate::aes_kw_cmd`] -- the whole-input reading, the absence of an IV, the fail-closed unwrap
//! -- applies unchanged, at half the width: the input is a whole number of 4-byte semiblocks, at
//! least 8 bytes, and the output is 4 bytes longer. TKW is approved for legacy systems only
//! (SP 800-38F Sec 8), and two-key TDEA may not apply protection at all, so `tdes2-tkw` has no
//! `encrypt`, as the other `tdes2-*` commands have none.

use crate::aes_kw_cmd::{run, run_with};
use crate::helpers::block_mode_helpers::{CipherDirection, DecryptOnlyAction, load_key_object};
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
    run_with(|input| kek.unwrap(input), output_hex, "two-key TDES-TKW");
}
