//! SM4-CTR encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the nonce convention, key loading and stdin framing are in
//! [`crate::stream_mode_cmd`] (and [`crate::block_mode_cmd`] for the key loader), shared with the
//! `aes*-ctr` commands. See those modules for the command-line contract.
//!
//! `sm4-ctr` is the same command as `aes128-ctr` over the SM4 permutation (GB/T 32907-2016; 16-byte
//! key, 16-byte block), so every remark there applies unchanged, including the split of the counter
//! block: the nonce is **12 bytes** and the counter the remaining 4, giving 2^32 blocks -- 64 GiB
//! -- in a single message. draft-ribose-cfrg-sm4-10 Sec 8.7 takes the counter sequence as an input
//! and requires only that it "does not repeat within the block size", so this is one admissible
//! choice; it is NIST SP 800-38A Appendix B.2's.
//!
//! `encrypt` writes that 12-byte nonce as the first bytes of its output and `decrypt` reads it back,
//! exactly as the other modes do with their IVs; note that it is 12 bytes here, not 16.
//!
//! # Warning
//!
//! CTR provides confidentiality only and is the most malleable mode here: flipping any ciphertext
//! bit flips exactly the corresponding plaintext bit and affects nothing else (SP 800-38A
//! Appendix D, Table D.2), so an attacker can edit the plaintext at will with no garbling to give
//! it away. A repeated nonce under one key is fatal rather than merely unwise -- the same keystream
//! twice leaks the XOR of the two messages -- which is why the nonce is drawn from the OS-backed
//! DRBG and there is no way to supply one. Do not decrypt data you have not authenticated
//! separately.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, load_key};
use crate::stream_mode_cmd::run_stream_mode;
use bouncycastle::modes::{Ctr, Decrypting, Encrypting};
use bouncycastle::sm4::{CTR_NONCE_LEN, SM4};

pub(crate) fn sm4_ctr_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<16>(key, key_file, "SM4");
    run_stream_mode::<
        Ctr<SM4, Encrypting, 16, BLOCK_LEN, CTR_NONCE_LEN>,
        Ctr<SM4, Decrypting, 16, BLOCK_LEN, CTR_NONCE_LEN>,
        16,
        CTR_NONCE_LEN,
    >(action, &key, output_hex)
}
