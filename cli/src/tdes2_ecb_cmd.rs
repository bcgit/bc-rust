//! Two-key TDES-ECB decryption, streaming stdin to stdout.
//!
//! Decryption only: NIST SP 800-131A Rev 2 Table 1 disallows two-key TDEA for encryption,
//! `TDES2Key::create_encryptor` does not compile, and
//! [`DecryptOnlyAction`] has no `encrypt`. Everything else is `tdes-ecb decrypt` -- no IV, input a
//! whole number of 8-byte blocks, no unpadding -- see [`crate::tdes_ecb_cmd`] for the ECB warning
//! and [`crate::helpers::block_mode_helpers`] for the framing. The key is the 16-byte `KEY1 || KEY2`.

use crate::helpers::block_mode_helpers::{DecryptOnlyAction, decrypt_stream, load_key_object};
use bouncycastle::cipher::modes::hazmat::ecb::ECB;
use bouncycastle::cipher::padding::NoPadding;
use bouncycastle::core::symmetric_key::SymmetricDecryptionKey;
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN_2KEY, TDES2Key};

pub(crate) fn tdes2_ecb_cmd(
    action: &DecryptOnlyAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let DecryptOnlyAction::Decrypt = action;
    let key =
        load_key_object::<TDES2Key<ECB<NoPadding>>, KEY_LEN_2KEY>(key, key_file, "two-key TDES");
    decrypt_stream::<_, 0, BLOCK_LEN>(
        None,
        |no_iv| key.create_decryptor(no_iv),
        output_hex,
        Some("ECB"),
    )
}
