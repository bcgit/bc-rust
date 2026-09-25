//! Two-key TDES-CBC decryption, streaming stdin to stdout.
//!
//! Decryption only: NIST SP 800-131A Rev 2 Table 1 disallows two-key TDEA for encryption,
//! `bouncycastle-tdes` will not compile an encrypting mode over `TDES2Key`, and
//! [`DecryptOnlyAction`] has no `encrypt`. Everything else is `tdes-cbc decrypt` -- the first 8 bytes
//! of input are the IV, the rest whole 8-byte blocks -- see [`crate::tdes_cbc_cmd`] and
//! [`crate::block_mode_cmd`]. The key is the 16-byte `KEY1 || KEY2`.

use crate::block_mode_cmd::{DecryptOnlyAction, decrypt_stream, load_key};
use bouncycastle::modes::{Cbc, Decrypting};
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN_2KEY, TDES2Key};

pub(crate) fn tdes2_cbc_cmd(
    action: &DecryptOnlyAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let DecryptOnlyAction::Decrypt = action;
    let key = load_key::<KEY_LEN_2KEY>(key, key_file, "two-key TDES");
    decrypt_stream::<
        Cbc<TDES2Key, Decrypting, KEY_LEN_2KEY, BLOCK_LEN>,
        KEY_LEN_2KEY,
        BLOCK_LEN,
        BLOCK_LEN,
    >(&key, output_hex, "CBC")
}
