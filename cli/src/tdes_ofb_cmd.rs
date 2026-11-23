//! TDES-OFB encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the
//! key and IV loaders), shared with the other stream-mode commands. The block, and so the IV, is
//! 8 bytes; this is the TOFB mode of SP 800-38A Appendix E.
//!
//! # Any length
//!
//! OFB is a stream cipher: input of any length is accepted, nothing is padded, and the output is
//! exactly as long as the input.
//!
//! # Warning
//!
//! OFB provides confidentiality only; see [`crate::ofb_cmd`]. TDEA is a legacy algorithm,
//! disallowed for encryption by NIST SP 800-131A Rev 2 after 2023; see the `bouncycastle_symmetric::tdes`
//! module docs.

use crate::helpers::block_mode_helpers::TDEA_LIMIT;
use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key_object};
use crate::helpers::stream_mode_helpers::run_stream_mode_bounded;
use bouncycastle::symmetric::modes::OFB;
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN, TDES3Key};

pub(crate) fn tdes_ofb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key_object::<TDES3Key<OFB>, KEY_LEN>(key, key_file, "TDES");
    run_stream_mode_bounded::<_, KEY_LEN, BLOCK_LEN>(
        action,
        &key,
        load_iv(iv, iv_file),
        output_hex,
        Some(&TDEA_LIMIT),
    )
}
