//! TDES-CFB64 encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::stream_mode_cmd`] (and [`crate::block_mode_cmd`] for the key loader), shared with the
//! AES stream commands and `tdes-cfb8` / `tdes-ctr`. See those modules for the command-line
//! contract. The block, and so the IV, is 8 bytes; the segment is the full block, so this is CFB64
//! -- the TCFB mode of SP 800-38A Appendix E with `s = 64`.
//!
//! # Any length
//!
//! CFB is a stream cipher: input of any length is accepted, nothing is padded, and the output is
//! exactly as long as the input.
//!
//! # Warning
//!
//! CFB provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. Do not decrypt data you have not authenticated separately.
//!
//! TDEA is a legacy algorithm, disallowed for encryption by NIST SP 800-131A Rev 2 after 2023; see
//! the `bouncycastle-tdes` crate docs.

use crate::block_mode_cmd::{BlockModeAction, load_key};
use crate::stream_mode_cmd::run_stream_mode;
use bouncycastle::modes::{Decrypting, Encrypting};
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN, TDES_CFB};

pub(crate) fn tdes_cfb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<KEY_LEN>(key, key_file, "TDES");
    run_stream_mode::<TDES_CFB<Encrypting>, TDES_CFB<Decrypting>, KEY_LEN, BLOCK_LEN>(
        action, &key, output_hex,
    )
}
