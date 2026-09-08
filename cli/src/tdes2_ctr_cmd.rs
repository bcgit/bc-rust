//! Two-key TDES-CTR decryption, streaming stdin to stdout.
//!
//! Decryption only: NIST SP 800-131A Rev 2 Table 1 disallows two-key TDEA for encryption,
//! `bouncycastle-tdes` will not compile an encrypting mode over `TDES2Key`, and
//! [`DecryptOnlyAction`] has no `encrypt`. Everything else is `tdes-ctr decrypt` -- the first 6
//! bytes of input are the nonce, the counter starts at zero, at most 512 KiB of data -- see
//! [`crate::tdes_ctr_cmd`] and [`crate::stream_mode_cmd`]. The key is the 16-byte `KEY1 || KEY2`.

use crate::block_mode_cmd::{DecryptOnlyAction, load_key};
use crate::stream_mode_cmd::decrypt_stream;
use bouncycastle::tdes::{CTR_NONCE_LEN, KEY_LEN_2KEY, TDES2_CTR};

pub(crate) fn tdes2_ctr_cmd(
    action: &DecryptOnlyAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let DecryptOnlyAction::Decrypt = action;
    let key = load_key::<KEY_LEN_2KEY>(key, key_file, "two-key TDES");
    decrypt_stream::<TDES2_CTR, KEY_LEN_2KEY, CTR_NONCE_LEN>(&key, output_hex)
}
