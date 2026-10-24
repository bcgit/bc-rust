//! Two-key TDES-CBC decryption, streaming stdin to stdout.
//!
//! Decryption only: NIST SP 800-131A Rev 2 Table 1 disallows two-key TDEA for encryption,
//! `TDES2Key::create_encryptor` does not compile, and
//! [`DecryptOnlyAction`] has no `encrypt`. Everything else is `tdes-cbc decrypt` -- the first 8 bytes
//! of input are the IV, the rest whole 8-byte blocks -- see [`crate::tdes_cbc_cmd`] and
//! [`crate::helpers::block_mode_helpers`]. The key is the 16-byte `KEY1 || KEY2`.

use crate::helpers::block_mode_helpers::{DecryptOnlyAction, decrypt_stream, load_key_object};
use bouncycastle::cipher::modes::CBC;
use bouncycastle::cipher::padding::NoPadding;
use bouncycastle::core::symmetric_key::SymmetricDecryptionKey;
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN_2KEY, TDES2Key};

pub(crate) fn tdes2_cbc_cmd(
    action: &DecryptOnlyAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let DecryptOnlyAction::Decrypt = action;
    let key =
        load_key_object::<TDES2Key<CBC<NoPadding>>, KEY_LEN_2KEY>(key, key_file, "two-key TDES");
    decrypt_stream::<_, BLOCK_LEN, BLOCK_LEN>(
        None,
        |iv| key.create_decryptor(iv),
        output_hex,
        Some("CBC"),
    )
}
