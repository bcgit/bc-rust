//! Two-key TDES-ECB decryption, streaming stdin to stdout.
//!
//! Decryption only: NIST SP 800-131A Rev 2 Table 1 disallows two-key TDEA for encryption,
//! `bouncycastle-tdes` will not compile an encrypting mode over `TDES2Key`, and
//! [`DecryptOnlyAction`] has no `encrypt`. Everything else is `tdes-ecb decrypt` -- no IV, input a
//! whole number of 8-byte blocks, no unpadding -- see [`crate::tdes_ecb_cmd`] for the ECB warning
//! and [`crate::block_mode_cmd`] for the framing. The key is the 16-byte `KEY1 || KEY2`.

use crate::block_mode_cmd::{DecryptOnlyAction, decrypt_stream, load_key};
use bouncycastle::modes::{Decrypting, Ecb};
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN_2KEY, TDES2Key};

pub(crate) fn tdes2_ecb_cmd(
    action: &DecryptOnlyAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let DecryptOnlyAction::Decrypt = action;
    let key = load_key::<KEY_LEN_2KEY>(key, key_file, "two-key TDES");
    decrypt_stream::<Ecb<TDES2Key, Decrypting, KEY_LEN_2KEY, BLOCK_LEN>, KEY_LEN_2KEY, 0, BLOCK_LEN>(
        &key, output_hex, "ECB",
    )
}
