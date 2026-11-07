//! SM4-CCM authenticated encryption and decryption: the `aes*-ccm` command over the SM4 key
//! (GB/T 32907-2016; with the default 12-byte nonce and 16-byte tag it is RFC 8998 Sec 3.5.2's
//! `AEAD_SM4_CCM`), with the same contract -- the whole input read first, the nonce supplied
//! rather than generated, `ciphertext || tag` out. See [`crate::aes_ccm_cmd`] for why CCM cannot
//! stream and for the nonce and length rules; this file only names the SM4 key type for that
//! module's runner.

use crate::aes_ccm_cmd::{CcmKeys, run};
use crate::helpers::block_mode_helpers::{CipherDirection, load_key};
use bouncycastle::cipher::modes::CCM;
use bouncycastle::sm4::{KEY_LEN, SM4Key};

struct Sm4;

impl CcmKeys<KEY_LEN> for Sm4 {
    type Key<const N: usize, const T: usize> = SM4Key<CCM<N, T>>;
}

/// SM4 CCM. See the module docs and the subcommand help.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sm4_ccm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    tag_len: usize,
    output_hex: bool,
) {
    run::<Sm4, KEY_LEN>(
        action,
        &load_key::<KEY_LEN>(key, key_file, "SM4"),
        nonce,
        nonce_file,
        aad,
        aad_file,
        tag_len,
        output_hex,
    );
}
