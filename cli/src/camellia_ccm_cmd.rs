//! Camellia-CCM authenticated encryption and decryption: the `aes*-ccm` commands over the Camellia
//! permutation (RFC 3713; the Camellia-CCM of RFC 5528), with the same contract -- the whole
//! input read first, the nonce supplied rather than generated, `ciphertext || tag` out. See
//! [`crate::aes_ccm_cmd`] for why CCM cannot stream and for the nonce and length rules; this
//! file only names the Camellia key types for that module's runner.

use crate::aes_ccm_cmd::{CcmKeys, run};
use crate::helpers::block_mode_helpers::{CipherDirection, load_key};
use bouncycastle::camellia::{Camellia128Key, Camellia192Key, Camellia256Key};
use bouncycastle::cipher::modes::CCM;

struct Aria128;
struct Aria192;
struct Aria256;

impl CcmKeys<16> for Aria128 {
    type Key<const N: usize, const T: usize> = Camellia128Key<CCM<N, T>>;
}

impl CcmKeys<24> for Aria192 {
    type Key<const N: usize, const T: usize> = Camellia192Key<CCM<N, T>>;
}

impl CcmKeys<32> for Aria256 {
    type Key<const N: usize, const T: usize> = Camellia256Key<CCM<N, T>>;
}

/// Camellia-128 CCM. See the module docs and the subcommand help.
#[allow(clippy::too_many_arguments)]
pub(crate) fn camellia128_ccm_cmd(
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
    run::<Aria128, 16>(
        action,
        &load_key::<16>(key, key_file, "Camellia-128"),
        nonce,
        nonce_file,
        aad,
        aad_file,
        tag_len,
        output_hex,
    );
}

/// Camellia-192 CCM. See [`camellia128_ccm_cmd`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn camellia192_ccm_cmd(
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
    run::<Aria192, 24>(
        action,
        &load_key::<24>(key, key_file, "Camellia-192"),
        nonce,
        nonce_file,
        aad,
        aad_file,
        tag_len,
        output_hex,
    );
}

/// Camellia-256 CCM. See [`camellia128_ccm_cmd`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn camellia256_ccm_cmd(
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
    run::<Aria256, 32>(
        action,
        &load_key::<32>(key, key_file, "Camellia-256"),
        nonce,
        nonce_file,
        aad,
        aad_file,
        tag_len,
        output_hex,
    );
}
