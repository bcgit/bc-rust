//! Two-key TDES-CFB8 decryption, streaming stdin to stdout.
//!
//! Decryption only: NIST SP 800-131A Rev 2 Table 1 disallows two-key TDEA for encryption,
//! `bouncycastle-tdes` will not compile an encrypting mode over `TDES2Key`, and
//! [`DecryptOnlyAction`] has no `encrypt`. Everything else is `tdes-cfb8 decrypt` -- the first 8
//! bytes of input are the IV, the rest any length -- see [`crate::tdes_cfb8_cmd`] for how CFB8
//! differs from CFB64, and [`crate::stream_mode_cmd`]. The key is the 16-byte `KEY1 || KEY2`.

use crate::block_mode_cmd::{DecryptOnlyAction, load_key};
use crate::stream_mode_cmd::decrypt_stream;
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN_2KEY, TDES2_CFB8};

pub(crate) fn tdes2_cfb8_cmd(
    action: &DecryptOnlyAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let DecryptOnlyAction::Decrypt = action;
    let key = load_key::<KEY_LEN_2KEY>(key, key_file, "two-key TDES");
    decrypt_stream::<TDES2_CFB8, KEY_LEN_2KEY, BLOCK_LEN>(&key, output_hex)
}
