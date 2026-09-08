//! TDES-CTR encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the nonce convention, key loading and stdin framing are in
//! [`crate::stream_mode_cmd`] (and [`crate::block_mode_cmd`] for the key loader), shared with the
//! AES stream commands and `tdes-cfb` / `tdes-cfb8`. See those modules for the command-line
//! contract.
//!
//! # The nonce is 6 bytes and the counter is 2
//!
//! NIST SP 800-38A Sec 6.5 builds CTR on a sequence of counter blocks, and Appendix B.2's second
//! approach makes each one a message nonce followed by a counter; Appendix E allows TDEA as the
//! underlying cipher. With an 8-byte block the split is tight. This command uses the `TDES_CTR`
//! alias: a **6-byte** nonce and a 2-byte counter, so a single message is limited to 65 536 blocks
//! (512 KiB), past which the command fails rather than repeat a counter block. The
//! `bouncycastle-tdes` crate docs explain the trade-off against nonce collisions.
//!
//! `encrypt` writes that 6-byte nonce as the first bytes of its output and `decrypt` reads it back,
//! exactly as the other modes do with their IVs; note that it is 6 bytes here, not 8.
//!
//! # Any length (up to the counter limit)
//!
//! CTR is a stream cipher: nothing is padded, and the output is exactly as long as the input.
//!
//! # Warning
//!
//! CTR provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the nonce is authenticated. It is the most malleable of the modes here: flipping any ciphertext
//! bit flips exactly the corresponding plaintext bit and affects nothing else (SP 800-38A
//! Appendix D). Do not decrypt data you have not authenticated separately.
//!
//! A repeated nonce is fatal here rather than merely unwise: the same nonce under the same key
//! gives the same keystream. The nonce is drawn from the OS-backed DRBG and there is no way to
//! supply one, but with only 48 bits of nonce the number of messages under one key bundle must
//! stay small -- which SP 800-67 Rev 2 Sec 3.4's limit of 2^20 blocks per bundle already demands.
//!
//! TDEA is a legacy algorithm, disallowed for encryption by NIST SP 800-131A Rev 2 after 2023; see
//! the `bouncycastle-tdes` crate docs.

use crate::block_mode_cmd::{BlockModeAction, load_key};
use crate::stream_mode_cmd::run_stream_mode;
use bouncycastle::modes::{Decrypting, Encrypting};
use bouncycastle::tdes::{CTR_NONCE_LEN, KEY_LEN, TDES_CTR};

pub(crate) fn tdes_ctr_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<KEY_LEN>(key, key_file, "TDES");
    run_stream_mode::<TDES_CTR<Encrypting>, TDES_CTR<Decrypting>, KEY_LEN, CTR_NONCE_LEN>(
        action, &key, output_hex,
    )
}
