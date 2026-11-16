//! Two-key TDES-CTR decryption, streaming stdin to stdout.
//!
//! Decryption only: NIST SP 800-131A Rev 2 Table 1 disallows two-key TDEA for encryption,
//! `TDES2Key::create_encryptor` does not compile, and
//! [`DecryptOnlyAction`] has no `encrypt`. Everything else is `tdes-ctr decrypt` -- the first 6
//! bytes of input are the nonce unless `--iv` supplies it, the counter starts at zero, at most
//! 512 KiB of data -- see [`crate::tdes_ctr_cmd`] and [`crate::helpers::stream_mode_helpers`].
//! The key is the 16-byte `KEY1 || KEY2`.

use crate::helpers::block_mode_helpers::{DecryptOnlyAction, load_iv, load_key_object};
use crate::helpers::stream_mode_helpers::decrypt_stream;
use bouncycastle::cipher::modes::CTR;
use bouncycastle::tdes::{BLOCK_LEN, CTR_NONCE_LEN, KEY_LEN_2KEY, TDES2Key};

pub(crate) fn tdes2_ctr_cmd(
    action: &DecryptOnlyAction,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    let DecryptOnlyAction::Decrypt = action;
    let key = load_key_object::<TDES2Key<CTR<CTR_NONCE_LEN, BLOCK_LEN>>, KEY_LEN_2KEY>(
        key, key_file, "two-key TDES",
    );
    decrypt_stream::<_, KEY_LEN_2KEY, CTR_NONCE_LEN>(&key, load_iv(iv, iv_file), output_hex)
}
