#![forbid(unsafe_code)]

mod aes_cbc_cmd;
mod aes_ccm_cmd;
mod aes_cfb8_cmd;
mod aes_cfb_cmd;
mod aes_ctr_cmd;
mod aes_ecb_cmd;
mod aes_gcm_cmd;
mod aes_kw_cmd;
mod ascon_cmd;
mod chacha20_cmd;
mod chacha20_poly1305_cmd;
mod ecdsa_cmd;
mod encoders_cmd;
mod helpers;
mod hkdf_cmd;
mod mac_cmd;
mod mldsa_cmd;
mod mlkem_cmd;
mod rng_cmd;
mod sha2_cmd;
mod sha3_cmd;
mod sm2_cmd;
mod sm3_cmd;
mod tdes2_cbc_cmd;
mod tdes2_cfb8_cmd;
mod tdes2_cfb_cmd;
mod tdes2_ctr_cmd;
mod tdes2_ecb_cmd;
mod tdes_cbc_cmd;
mod tdes_cfb8_cmd;
mod tdes_cfb_cmd;
mod tdes_ctr_cmd;
mod tdes_ecb_cmd;
mod tdes_tkw_cmd;

use crate::ecdsa_cmd::ECDSAAction;
use crate::hkdf_cmd::HKDFVariant;
use crate::mac_cmd::HMACVariant;
use crate::mldsa_cmd::{MLDSAAction, PreHashAlg};
use crate::rng_cmd::DrbgHash;
use crate::sha2_cmd::SHA2Variant;
use crate::sha3_cmd::{SHA3Variant, Strength};
use crate::sm2_cmd::SM2Action;
use clap::{Parser, Subcommand};
use helpers::block_mode_helpers::{CipherDirection, DecryptOnlyAction};

#[derive(Parser)]
#[command(version, about, long_about=None, arg_required_else_help=true)]
struct Cli {
    /// Read the files a command decodes (keys, IVs and nonces, seeds, private and public keys,
    /// signatures, ciphertexts, contexts, salts, IKM, AAD files), and stdin where it carries
    /// one of those, as hex text rather than raw bytes. Values given inline (--key, --iv, ...)
    /// are always hex. Without this flag a file is its raw bytes, however hex-like they look.
    #[arg(long, global = true)]
    hex_input: bool,

    #[command(subcommand)]
    subcommands: Option<Subcommands>,
}

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Subcommand)]
enum Subcommands {
    /// AES-128 in CBC mode (NIST SP 800-38A Sec 6.2) with PKCS7 padding, streaming stdin to stdout.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input, so the two
    /// compose directly in a pipeline.
    ///
    /// With `--iv` (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead: `encrypt` uses it
    /// and writes ONLY the ciphertext, and `decrypt` reads ONLY ciphertext from stdin. This is for
    /// a format that carries the IV itself, and for reproducing published vectors. The IV must
    /// then be unpredictable to an attacker (SP 800-38A Appendix C) and never reused under one
    /// key; that is the caller's responsibility, which the default takes care of.
    ///
    /// Input may be any length: it is padded with PKCS7 to a whole number of 16-byte blocks, so the
    /// ciphertext after the IV is 1 to 16 bytes longer than the plaintext, and `decrypt` rejects
    /// a ciphertext whose padding is malformed.
    ///
    /// WARNING: CBC provides confidentiality only. It does not detect tampering, and neither the
    /// ciphertext nor the IV is authenticated. Do not decrypt data you have not authenticated
    /// separately.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 16-byte IV in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 16-byte IV, (raw bytes; hex with --hex-input). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-128 in CCM mode (NIST SP 800-38C): authenticated encryption of stdin to stdout.
    ///
    /// CCM is an AEAD: it protects both confidentiality and authenticity, and `decrypt` either
    /// writes the plaintext or fails, unlike aes*-cbc/-cfb/-ctr, which cannot detect tampering.
    ///
    /// The output of `encrypt` is `ciphertext || tag` -- SP 800-38C Sec 6.1 step 8's own layout --
    /// so it is `--tag-len` bytes longer than the input, and `decrypt` reads the tag back off the
    /// end. Both directions authenticate `--aad` as well as the payload.
    ///
    /// THE NONCE IS SUPPLIED, NOT GENERATED, and this is the only cipher command here that takes
    /// one. The other modes need an unpredictable IV, so they generate it; CCM needs the nonce to
    /// be UNIQUE but not unpredictable (Sec 5.3: "The nonce is not required to be random"), and a
    /// caller with a message counter can guarantee uniqueness better than a random draw. The nonce
    /// is NOT written to the output, so `decrypt` needs the same `--nonce` as `encrypt`.
    ///
    /// WARNING: never reuse a nonce under one key. For CCM a repeat is worse than for CTR: it
    /// reuses the keystream AND lets an attacker who can replay the nonce flip any chosen bit of
    /// the payload (Appendix B.1). Use a counter, or a random value long enough that a collision is
    /// negligible.
    ///
    /// Nonce length must be 7 to 13 bytes and `--tag-len` one of 4, 6, 8, 10, 12, 14, 16
    /// (Appendix A.1). The two are linked to the payload limit and the forgery bound respectively:
    /// a nonce of n bytes caps the payload at 2^(8*(15-n)) - 1 bytes, so 13 bytes allows only
    /// 64 KiB - 1 while 7 bytes is effectively unlimited; and Sec B.2 says a tag shorter than
    /// 8 bytes "shall not be used without a careful analysis of the risks". A 12-byte nonce with a
    /// 16-byte tag is the usual choice; `--tag-len` defaults to 16, while the nonce must be given.
    ///
    /// UNLIKE EVERY OTHER CIPHER COMMAND HERE, THIS ONE DOES NOT STREAM: it reads all of stdin
    /// before doing any work, so memory use is proportional to the input. That is inherent to CCM,
    /// not a limitation of this implementation -- Sec 3: "CCM is not designed to support partial
    /// processing or stream processing", because Appendix A.2.1 puts the payload length inside the
    /// first block the MAC covers. It does buy one thing: on `decrypt` NO plaintext is written
    /// until the tag has verified, so unlike `ascon-aead128` a non-zero exit leaves nothing to
    /// discard. For large inputs use `ascon-aead128`, which streams. The AAD is read whole as well.
    ///
    /// Input may be any length: CCM pads internally and the payload is not block-aligned.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_CCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The nonce in hex, 7 to 13 bytes. MUST be unique per encryption under a given key.
        #[arg(long)]
        nonce: Option<String>,

        /// A file containing the nonce, (raw bytes; hex with --hex-input).
        #[arg(long)]
        nonce_file: Option<String>,

        /// Associated data in hex: authenticated but not encrypted. Must match on decrypt.
        #[arg(long)]
        aad: Option<String>,

        /// A file containing the associated data, as raw bytes (never hex-decoded). If both aad and
        /// aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        /// Tag length in bytes: one of 4, 6, 8, 10, 12, 14, 16. Must match on decrypt.
        #[arg(long, default_value_t = 16)]
        tag_len: usize,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-128 in CFB128 mode (NIST SP 800-38A Sec 6.3), streaming stdin to stdout.
    ///
    /// The segment size is the full block, i.e. CFB128. SP 800-38A's 8-bit CFB is a different,
    /// non-interoperable mode; use `aes128-cfb8` for that. The 1-bit variant is not provided.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input, so the two
    /// compose directly in a pipeline.
    ///
    /// With `--iv` (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead: `encrypt` uses it
    /// and writes ONLY the ciphertext, and `decrypt` reads ONLY ciphertext from stdin. This is for
    /// a format that carries the IV itself, and for reproducing published vectors. The IV must
    /// then be unpredictable to an attacker (SP 800-38A Appendix C) and never reused under one
    /// key; that is the caller's responsibility, which the default takes care of.
    ///
    /// Input may be ANY length: CFB is a stream cipher, so nothing is padded and the ciphertext is
    /// exactly as long as the plaintext.
    ///
    /// WARNING: CFB provides confidentiality only. It does not detect tampering, and neither the
    /// ciphertext nor the IV is authenticated. Flipping a ciphertext bit flips the same bit of the
    /// plaintext in the same block, so tampering is directly exploitable. Do not decrypt data you
    /// have not authenticated separately.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 16-byte IV in hex. Supplied instead of generated: `encrypt` then writes no IV and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 16-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-128 in CFB8 mode (NIST SP 800-38A Sec 6.3, s = 8), streaming stdin to stdout.
    ///
    /// The segment size is one byte. This is a DIFFERENT, NON-INTEROPERABLE mode from the CFB128
    /// of `aes128-cfb`: the two ciphertexts agree only on their first byte. It also costs one AES
    /// call per byte, sixteen times the work of `aes128-cfb`, so prefer that unless a byte-granular
    /// self-synchronising stream is required or the format demands CFB8.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input, so the two
    /// compose directly in a pipeline.
    ///
    /// With `--iv` (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead: `encrypt` uses it
    /// and writes ONLY the ciphertext, and `decrypt` reads ONLY ciphertext from stdin. This is for
    /// a format that carries the IV itself, and for reproducing published vectors. The IV must
    /// then be unpredictable to an attacker (SP 800-38A Appendix C) and never reused under one
    /// key; that is the caller's responsibility, which the default takes care of.
    ///
    /// Input may be ANY length: CFB8's segment is a single byte, so nothing is padded and the
    /// ciphertext is exactly as long as the plaintext.
    ///
    /// WARNING: CFB8 provides confidentiality only. It does not detect tampering, and neither the
    /// ciphertext nor the IV is authenticated. Flipping a ciphertext bit flips the same bit of the
    /// same plaintext byte and corrupts the following 16 bytes, after which decryption
    /// resynchronises. Do not decrypt data you have not authenticated separately.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 16-byte IV in hex. Supplied instead of generated: `encrypt` then writes no IV and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 16-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Compute or verify an AES-128 CMAC (NIST SP 800-38B) over the content provided on stdin:
    /// a 16-byte tag. Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_CMAC {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// AES-128 in CTR mode (NIST SP 800-38A Sec 6.5), streaming stdin to stdout.
    ///
    /// The counter block is a 12-byte nonce followed by a 4-byte counter starting at zero, so one
    /// message can be up to 2^32 blocks (64 GiB); past that the command errors rather than
    /// repeating keystream.
    ///
    /// On `encrypt`, a fresh nonce is generated and written as the FIRST 12 BYTES of the output;
    /// on `decrypt` it is read back from the first 12 bytes of the input, so the two compose
    /// directly in a pipeline. Note that this is 12 bytes, not the 16 the other modes write.
    ///
    /// With `--iv` (hex) or `--iv-file` (raw bytes; hex with --hex-input), the 12-byte nonce is supplied instead:
    /// `encrypt` uses it and writes ONLY the ciphertext, and `decrypt` reads ONLY ciphertext from
    /// stdin. The counter block is then `nonce || 00000000`, which is how an OpenSSL `-iv` whose
    /// low four bytes are zero lines up with it. The nonce MUST be unique per message under one
    /// key; that is the caller's responsibility, which the default takes care of.
    ///
    /// Input may be ANY length: CTR is a stream cipher, so nothing is padded and the ciphertext is
    /// exactly as long as the plaintext.
    ///
    /// WARNING: CTR provides confidentiality only and is the most malleable mode here. It does not
    /// detect tampering, and flipping any ciphertext bit flips exactly the corresponding plaintext
    /// bit and nothing else, so an attacker can edit the plaintext at will with no garbling to give
    /// it away. A repeated nonce under one key leaks the XOR of the two messages outright. Do not
    /// decrypt data you have not authenticated separately.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce, (raw bytes; hex with --hex-input). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-128 in ECB mode (NIST SP 800-38A Sec 6.1), streaming stdin to stdout.
    ///
    /// WARNING: ECB is NOT a confidentiality mode for data. Under a given key every plaintext
    /// block maps to the same ciphertext block, so equal blocks stay visibly equal, the same input
    /// always gives the same output, and blocks can be reordered, repeated or removed undetectably.
    /// This command exists for interoperability with systems that require ECB and for test
    /// vectors. For data use aes*-cbc or aes*-cfb under separate authentication, or an AEAD.
    ///
    /// There is NO IV: nothing is prepended on `encrypt` and nothing is consumed on `decrypt`, so
    /// the output is exactly as long as the input.
    ///
    /// Input must be a whole number of 16-byte blocks: this command is block-aligned and applies
    /// no padding, so unaligned input is rejected rather than padded.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_ECB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-128 in GCM (NIST SP 800-38D), streaming stdin to stdout.
    ///
    /// AUTHENTICATED, unlike the other AES modes here: tampering with the ciphertext, the AAD or
    /// the IV is detected rather than merely producing wrong plaintext.
    ///
    /// On `encrypt`, a fresh 12-byte IV is generated and written as the FIRST 12 BYTES of the
    /// output, the ciphertext follows, and the 16-byte tag is written last. `decrypt` reads the IV
    /// back from the first 12 bytes of input and streams the rest, checking the tag once input is
    /// exhausted. (SP 800-38D calls this value the IV, and defines it as a nonce.)
    ///
    /// With `--iv` (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead: `encrypt` uses it
    /// and writes ONLY `ciphertext || tag`, and `decrypt` reads ONLY that from stdin. The IV MUST
    /// be unique per message under one key (Sec 8), and a repeat is worse here than merely
    /// unwise: it lets an attacker recover the hash subkey (Appendix A). The default takes care of
    /// that; with `--iv` it is on the caller.
    ///
    /// `--aad` (hex) or `--aad-file` (raw bytes; hex with --hex-input) supply the additional authenticated data,
    /// which is covered by the tag but not encrypted; if neither is given, AAD is empty.
    ///
    /// Input may be ANY length: GCM needs no padding.
    ///
    /// WARNING: on `decrypt`, a tag failure may be reported only after plaintext has already been
    /// written to stdout, because this command streams the inline decryptor. A script MUST check
    /// the exit code before trusting anything already written; on failure this command prints
    /// `Error: authentication failed` and exits non-zero.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_GCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte IV in hex. Supplied instead of generated: `encrypt` then writes none and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        /// The additional authenticated data, in hex. Covered by the tag but not encrypted.
        #[arg(long)]
        aad: Option<String>,

        /// A file containing the additional authenticated data, as raw bytes (never hex-decoded).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Compute or verify an AES-128 GMAC (NIST SP 800-38D Sec 5.2) over the content provided on
    /// stdin: a 16-byte tag bound to a 12-byte nonce. Without `--iv` a fresh nonce is drawn and
    /// written FIRST, so the output is `nonce || tag`; with `--iv` only the tag is written. To
    /// verify, give `--verify` the tag along with `--iv`, or the 28-byte `nonce || tag` alone.
    /// A nonce MUST NOT repeat under one key (SP 800-38D Sec 8).
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_GMAC {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Hazardous: supplying it makes uniqueness the caller's
        /// responsibility.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce (raw bytes; hex with --hex-input); the same
        /// hazardous override.
        #[arg(long)]
        iv_file: Option<String>,

        /// A MAC value to be verified: the tag (with --iv) or nonce || tag.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in CBC mode (NIST SP 800-38A Sec 6.2) with PKCS7 padding, streaming stdin to stdout.
    ///
    /// See `aes128-cbc` for the IV convention, padding and warnings; only the
    /// key length differs.
    AES192_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 16-byte IV in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 16-byte IV, (raw bytes; hex with --hex-input). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in CCM mode (NIST SP 800-38C), authenticated encryption of stdin to stdout.
    ///
    /// See `aes128-ccm` for the nonce convention, the length rules, the non-streaming note and the
    /// warnings; only the key length differs.
    AES192_CCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The nonce in hex, 7 to 13 bytes. MUST be unique per encryption under a given key.
        #[arg(long)]
        nonce: Option<String>,

        /// A file containing the nonce, (raw bytes; hex with --hex-input).
        #[arg(long)]
        nonce_file: Option<String>,

        /// Associated data in hex: authenticated but not encrypted. Must match on decrypt.
        #[arg(long)]
        aad: Option<String>,

        /// A file containing the associated data, as raw bytes (never hex-decoded). If both aad and
        /// aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        /// Tag length in bytes: one of 4, 6, 8, 10, 12, 14, 16. Must match on decrypt.
        #[arg(long, default_value_t = 16)]
        tag_len: usize,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in CFB128 mode (NIST SP 800-38A Sec 6.3), streaming stdin to stdout.
    ///
    /// See `aes128-cfb` for the IV convention, input-length rule and warnings; only the key length
    /// differs.
    AES192_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 16-byte IV in hex. Supplied instead of generated: `encrypt` then writes no IV and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 16-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in CFB8 mode (NIST SP 800-38A Sec 6.3, s = 8), streaming stdin to stdout.
    ///
    /// See `aes128-cfb8` for the IV convention, input-length rule and warnings; only the key length
    /// differs.
    AES192_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 16-byte IV in hex. Supplied instead of generated: `encrypt` then writes no IV and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 16-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Compute or verify an AES-192 CMAC (NIST SP 800-38B) over the content provided on stdin:
    /// a 16-byte tag. Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES192_CMAC {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// AES-192 in CTR mode (NIST SP 800-38A Sec 6.5), streaming stdin to stdout.
    ///
    /// See `aes128-ctr` for the nonce convention, input-length rule and warnings; only the key
    /// length differs.
    AES192_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce, (raw bytes; hex with --hex-input). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in ECB mode (NIST SP 800-38A Sec 6.1), streaming stdin to stdout.
    ///
    /// See `aes128-ecb` for the warning, the absence of an IV and the block-alignment requirement;
    /// only the key length differs.
    AES192_ECB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in GCM (NIST SP 800-38D), streaming stdin to stdout.
    ///
    /// See `aes128-gcm` for the IV/tag framing, the AAD flags and the warnings; only the key
    /// length differs.
    AES192_GCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte IV in hex. Supplied instead of generated: `encrypt` then writes none and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        /// The additional authenticated data, in hex. Covered by the tag but not encrypted.
        #[arg(long)]
        aad: Option<String>,

        /// A file containing the additional authenticated data, as raw bytes (never hex-decoded).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Compute or verify an AES-192 GMAC (NIST SP 800-38D Sec 5.2) over the content provided on
    /// stdin: a 16-byte tag bound to a 12-byte nonce. Without `--iv` a fresh nonce is drawn and
    /// written FIRST, so the output is `nonce || tag`; with `--iv` only the tag is written. To
    /// verify, give `--verify` the tag along with `--iv`, or the 28-byte `nonce || tag` alone.
    /// A nonce MUST NOT repeat under one key (SP 800-38D Sec 8).
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES192_GMAC {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Hazardous: supplying it makes uniqueness the caller's
        /// responsibility.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce (raw bytes; hex with --hex-input); the same
        /// hazardous override.
        #[arg(long)]
        iv_file: Option<String>,

        /// A MAC value to be verified: the tag (with --iv) or nonce || tag.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in CBC mode (NIST SP 800-38A Sec 6.2) with PKCS7 padding, streaming stdin to stdout.
    ///
    /// See `aes128-cbc` for the IV convention, padding and warnings; only the
    /// key length differs.
    AES256_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 16-byte IV in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 16-byte IV, (raw bytes; hex with --hex-input). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in CCM mode (NIST SP 800-38C), authenticated encryption of stdin to stdout.
    ///
    /// See `aes128-ccm` for the nonce convention, the length rules, the non-streaming note and the
    /// warnings; only the key length differs.
    AES256_CCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The nonce in hex, 7 to 13 bytes. MUST be unique per encryption under a given key.
        #[arg(long)]
        nonce: Option<String>,

        /// A file containing the nonce, (raw bytes; hex with --hex-input).
        #[arg(long)]
        nonce_file: Option<String>,

        /// Associated data in hex: authenticated but not encrypted. Must match on decrypt.
        #[arg(long)]
        aad: Option<String>,

        /// A file containing the associated data, as raw bytes (never hex-decoded). If both aad and
        /// aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        /// Tag length in bytes: one of 4, 6, 8, 10, 12, 14, 16. Must match on decrypt.
        #[arg(long, default_value_t = 16)]
        tag_len: usize,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in CFB128 mode (NIST SP 800-38A Sec 6.3), streaming stdin to stdout.
    ///
    /// See `aes128-cfb` for the IV convention, input-length rule and warnings; only the key length
    /// differs.
    AES256_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 16-byte IV in hex. Supplied instead of generated: `encrypt` then writes no IV and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 16-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in CFB8 mode (NIST SP 800-38A Sec 6.3, s = 8), streaming stdin to stdout.
    ///
    /// See `aes128-cfb8` for the IV convention, input-length rule and warnings; only the key length
    /// differs.
    AES256_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 16-byte IV in hex. Supplied instead of generated: `encrypt` then writes no IV and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 16-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Compute or verify an AES-256 CMAC (NIST SP 800-38B) over the content provided on stdin:
    /// a 16-byte tag. Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES256_CMAC {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// AES-256 in CTR mode (NIST SP 800-38A Sec 6.5), streaming stdin to stdout.
    ///
    /// See `aes128-ctr` for the nonce convention, input-length rule and warnings; only the key
    /// length differs.
    AES256_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce, (raw bytes; hex with --hex-input). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in ECB mode (NIST SP 800-38A Sec 6.1), streaming stdin to stdout.
    ///
    /// See `aes128-ecb` for the warning, the absence of an IV and the block-alignment requirement;
    /// only the key length differs.
    /// The ECDSA signature algorithm over NIST P-256 (FIPS 186-5); `--deterministic` selects
    /// Deterministic ECDSA (RFC 6979). `ctx` has no effect: ECDSA has no context-string input.
    ECDSA_P256 {
        action: ECDSAAction,

        #[arg(long)]
        /// The private key file (in hex or binary) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (in hex or binary) for verifying
        sigfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,

        #[arg(long)]
        /// Deterministic ECDSA (FIPS 186-5 Section 6.3.2, RFC 6979): `k` is derived from the key
        /// and the message rather than drawn from the RNG, so signing is repeatable. Verification
        /// is the same either way.
        deterministic: bool,
    },

    /// The ECDSA signature algorithm over NIST P-384 (FIPS 186-5). See ecdsa-p256.
    ECDSA_P384 {
        action: ECDSAAction,

        #[arg(long)]
        /// The private key file (in hex or binary) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (in hex or binary) for verifying
        sigfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,

        #[arg(long)]
        /// Deterministic ECDSA (FIPS 186-5 Section 6.3.2, RFC 6979): `k` is derived from the key
        /// and the message rather than drawn from the RNG, so signing is repeatable. Verification
        /// is the same either way.
        deterministic: bool,
    },

    /// The ECDSA signature algorithm over NIST P-521 (FIPS 186-5). See ecdsa-p256.
    ECDSA_P521 {
        action: ECDSAAction,

        #[arg(long)]
        /// The private key file (in hex or binary) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (in hex or binary) for verifying
        sigfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,

        #[arg(long)]
        /// Deterministic ECDSA (FIPS 186-5 Section 6.3.2, RFC 6979): `k` is derived from the key
        /// and the message rather than drawn from the RNG, so signing is repeatable. Verification
        /// is the same either way.
        deterministic: bool,
    },

    /// The ECDSA signature algorithm over secp256k1 (SEC 2). See ecdsa-p256.
    ECDSA_SECP256K1 {
        action: ECDSAAction,

        #[arg(long)]
        /// The private key file (in hex or binary) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (in hex or binary) for verifying
        sigfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,

        #[arg(long)]
        /// Deterministic ECDSA (FIPS 186-5 Section 6.3.2, RFC 6979): `k` is derived from the key
        /// and the message rather than drawn from the RNG, so signing is repeatable. Verification
        /// is the same either way.
        deterministic: bool,
    },

    /// The ECDSA signature algorithm over brainpoolP256r1 (RFC 5639). See ecdsa-p256.
    ECDSA_BP256R1 {
        action: ECDSAAction,

        #[arg(long)]
        /// The private key file (in hex or binary) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (in hex or binary) for verifying
        sigfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,

        #[arg(long)]
        /// Deterministic ECDSA (FIPS 186-5 Section 6.3.2, RFC 6979): `k` is derived from the key
        /// and the message rather than drawn from the RNG, so signing is repeatable. Verification
        /// is the same either way.
        deterministic: bool,
    },

    /// The ECDSA signature algorithm over brainpoolP384r1 (RFC 5639). See ecdsa-p256.
    ECDSA_BP384R1 {
        action: ECDSAAction,

        #[arg(long)]
        /// The private key file (in hex or binary) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (in hex or binary) for verifying
        sigfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,

        #[arg(long)]
        /// Deterministic ECDSA (FIPS 186-5 Section 6.3.2, RFC 6979): `k` is derived from the key
        /// and the message rather than drawn from the RNG, so signing is repeatable. Verification
        /// is the same either way.
        deterministic: bool,
    },

    /// The ECDSA signature algorithm over brainpoolP512r1 (RFC 5639). See ecdsa-p256.
    ECDSA_BP512R1 {
        action: ECDSAAction,

        #[arg(long)]
        /// The private key file (in hex or binary) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (in hex or binary) for verifying
        sigfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,

        #[arg(long)]
        /// Deterministic ECDSA (FIPS 186-5 Section 6.3.2, RFC 6979): `k` is derived from the key
        /// and the message rather than drawn from the RNG, so signing is repeatable. Verification
        /// is the same either way.
        deterministic: bool,
    },

    AES256_ECB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in GCM (NIST SP 800-38D), streaming stdin to stdout.
    ///
    /// See `aes128-gcm` for the IV/tag framing, the AAD flags and the warnings; only the key
    /// length differs.
    AES256_GCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte IV in hex. Supplied instead of generated: `encrypt` then writes none and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        /// The additional authenticated data, in hex. Covered by the tag but not encrypted.
        #[arg(long)]
        aad: Option<String>,

        /// A file containing the additional authenticated data, as raw bytes (never hex-decoded).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Compute or verify an AES-256 GMAC (NIST SP 800-38D Sec 5.2) over the content provided on
    /// stdin: a 16-byte tag bound to a 12-byte nonce. Without `--iv` a fresh nonce is drawn and
    /// written FIRST, so the output is `nonce || tag`; with `--iv` only the tag is written. To
    /// verify, give `--verify` the tag along with `--iv`, or the 28-byte `nonce || tag` alone.
    /// A nonce MUST NOT repeat under one key (SP 800-38D Sec 8).
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES256_GMAC {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Hazardous: supplying it makes uniqueness the caller's
        /// responsibility.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce (raw bytes; hex with --hex-input); the same
        /// hazardous override.
        #[arg(long)]
        iv_file: Option<String>,

        /// A MAC value to be verified: the tag (with --iv) or nonce || tag.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Ascon-AEAD128 authenticated encryption/decryption of the content provided on stdin
    /// (NIST SP 800-232).
    ///
    /// On encrypt, a fresh nonce is generated and written as the FIRST 16 BYTES of the output,
    /// followed by the ciphertext and then the 16-byte tag; on --decrypt the nonce is read back
    /// from the first 16 bytes of the input, so the two compose directly in a pipeline. This is
    /// the same convention the AES commands use for their IV. Decryption fails with a non-zero
    /// exit status if the tag does not verify.
    ///
    /// --nonce/--nonce-file override that: the nonce is then neither written on encrypt nor read
    /// on decrypt, and the stream is exactly ciphertext||tag in both directions. That override
    /// exists for reproducing known-answer vectors; repeating a nonce under one key destroys both
    /// the confidentiality and the authenticity of Ascon-AEAD128.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    ///
    /// Security note: decryption streams its output, so plaintext bytes are written to stdout
    /// before the authentication tag (the last 16 bytes of input) can be checked. Do not treat
    /// the output as authentic until this command exits with status 0; a non-zero exit means the
    /// input was tampered with and any plaintext already written must be discarded.
    AsconAEAD128 {
        /// The 128-bit key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 128-bit key (raw bytes; hex with --hex-input).
        #[arg(long)]
        key_file: Option<String>,

        /// The 128-bit nonce in hex. Hazardous override: supplying it keeps the nonce out of the
        /// stream (see above), and reusing one under a given key breaks the cipher.
        #[arg(long)]
        nonce: Option<String>,

        /// A file containing a 128-bit nonce (raw bytes; hex with --hex-input); the same hazardous override.
        #[arg(long)]
        nonce_file: Option<String>,

        /// Associated data in hex (authenticated but not encrypted).
        #[arg(long)]
        aad: Option<String>,

        /// A file holding the associated data (raw bytes; hex with --hex-input).
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short, long)]
        direction: CipherDirection,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform Ascon-CXOF128 of the content provided on stdin. Requires the output length in bytes.
    /// Supports streaming update for low memory footprint.
    AsconCXOF128 {
        /// Length of the output in bytes.
        length: usize,

        /// Customization string Z, as the characters given (optional).
        #[arg(long)]
        customization: Option<String>,

        /// Customization string Z in hex, for bytes that are not text.
        #[arg(long)]
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform Ascon-Hash256 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    AsconHash256 {
        #[arg(short)]
        /// Output the digest in hex format.
        x: bool,
    },

    /// Perform Ascon-XOF128 of the content provided on stdin. Requires the output length in bytes.
    /// Supports streaming update for low memory footprint.
    AsconXOF128 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Decode base64 data from stdin to binary.
    /// Supports streaming for low memory footprint and continuous processing from stdin to stdout.
    Base64Decode,

    /// Encode binary data from stdin to base64.
    /// Supports streaming for low memory footprint and continuous processing from stdin to stdout.
    Base64Encode,

    /// ChaCha20 (RFC 8439 Sec 2.4), streaming stdin to stdout.
    ///
    /// On `encrypt`, a fresh nonce is generated and written as the FIRST 12 BYTES of the output;
    /// on `decrypt` it is read back from the first 12 bytes of the input, so the two compose
    /// directly in a pipeline. The block counter starts at 0.
    ///
    /// With `--iv` (hex) or `--iv-file` (raw bytes; hex with --hex-input), the 12-byte nonce is supplied instead:
    /// `encrypt` uses it and writes ONLY the ciphertext, and `decrypt` reads ONLY ciphertext from
    /// stdin, so a nonce left at the front of the input is decrypted as ciphertext. The nonce MUST
    /// be unique per message under one key: a repeat gives the same keystream, and the XOR of the
    /// two ciphertexts is then the XOR of the two plaintexts (RFC 8439 Sec 4). That is the
    /// caller's responsibility, which the default takes care of.
    ///
    /// Input may be ANY length, up to 2^32 64-byte blocks (256 GiB) per message, and the
    /// ciphertext is exactly as long as the plaintext.
    ///
    /// WARNING: ChaCha20 provides confidentiality only and is as malleable as CTR: flipping a
    /// ciphertext bit flips the same plaintext bit. Use `chacha20-poly1305` unless the ciphertext
    /// is authenticated separately.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    CHACHA20 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce (raw bytes; hex with --hex-input). If both iv and
        /// iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform cSHAKE128 (NIST SP 800-185 Sec 3) of the content provided on stdin, under a
    /// function name N and a customization string S; with both empty it is SHAKE128. Requires
    /// the output length in bytes. Supports streaming update for low memory footprint.
    CSHAKE128 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 'n', long)]
        /// Function name N, as the characters given (SP 800-185 reserves it for NIST-defined
        /// functions; leave it empty otherwise).
        function_name: Option<String>,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ChaCha20-Poly1305 (RFC 8439 Sec 2.8), streaming stdin to stdout.
    ///
    /// On `encrypt`, a fresh 12-byte nonce is generated and written as the FIRST 12 BYTES of the
    /// output, the ciphertext follows, and the 16-byte tag is written last. `decrypt` reads the
    /// nonce back from the first 12 bytes of input and streams the rest, checking the tag once
    /// input is exhausted.
    ///
    /// With `--iv` (hex) or `--iv-file` (raw bytes; hex with --hex-input), the nonce is supplied instead: `encrypt` uses
    /// it and writes ONLY `ciphertext || tag`, and `decrypt` reads ONLY that from stdin, so a nonce
    /// left at the front of the input fails the tag check. The nonce MUST be unique per message
    /// under one key (RFC 8439 Sec 2.8), and a repeat is worse here than for `chacha20`: the two
    /// messages then share the keystream, which reveals the XOR of their plaintexts, and the
    /// one-time Poly1305 key (Sec 4), which must be unique per message (Sec 2.5) because two tags
    /// under it let an attacker forge others. The default takes care of that; with `--iv` it is on
    /// the caller.
    ///
    /// See `aes128-gcm` for the AAD flags and the streaming warning, which apply here unchanged.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    CHACHA20_POLY1305 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes none and
        /// `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce (raw bytes; hex with --hex-input). If both iv and
        /// iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        /// The additional authenticated data, in hex. Covered by the tag but not encrypted.
        #[arg(long)]
        aad: Option<String>,

        /// A file containing the additional authenticated data (raw bytes; hex with --hex-input).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform cSHAKE256 (NIST SP 800-185 Sec 3). See cshake128.
    CSHAKE256 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 'n', long)]
        /// Function name N, as the characters given.
        function_name: Option<String>,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The HashML-DSA-44 signature algorithm, with the hash given by --hash (SHA-512 by default).
    HashMLDSA44 {
        action: MLDSAAction,

        #[arg(long, value_enum, default_value_t = PreHashAlg::Sha512)]
        /// The pre-hash (FIPS 204 Section 5.4); it must be at least as strong as the parameter
        /// set, so sha256 and shake128 fit hash-mldsa44 only.
        hash: PreHashAlg,

        #[arg(long)]
        /// The file containing the context string (raw bytes; hex with --hex-input) for signing or verifying
        ctxfile: Option<String>,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (raw bytes; hex with --hex-input) for verifying
        sigfile: Option<String>,

        #[arg(long)]
        /// The message representative file (64 bytes; raw bytes; hex with --hex-input) for
        /// sign-mu and verify-mu; stdin without it.
        mufile: Option<String>,

        #[arg(long)]
        /// Sign with the deterministic variant (FIPS 204 Section 3.4: rnd all zero) rather than
        /// the hedged default.
        deterministic: bool,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The HashML-DSA-65 signature algorithm, with the hash given by --hash (SHA-512 by default).
    HashMLDSA65 {
        action: MLDSAAction,

        #[arg(long, value_enum, default_value_t = PreHashAlg::Sha512)]
        /// The pre-hash (FIPS 204 Section 5.4); it must be at least as strong as the parameter
        /// set, so sha256 and shake128 fit hash-mldsa44 only.
        hash: PreHashAlg,

        #[arg(long)]
        /// The file containing the context string (raw bytes; hex with --hex-input) for signing or verifying
        ctxfile: Option<String>,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (raw bytes; hex with --hex-input) for verifying
        sigfile: Option<String>,

        #[arg(long)]
        /// The message representative file (64 bytes; raw bytes; hex with --hex-input) for
        /// sign-mu and verify-mu; stdin without it.
        mufile: Option<String>,

        #[arg(long)]
        /// Sign with the deterministic variant (FIPS 204 Section 3.4: rnd all zero) rather than
        /// the hedged default.
        deterministic: bool,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The HashML-DSA-87 signature algorithm, with the hash given by --hash (SHA-512 by default).
    HashMLDSA87 {
        action: MLDSAAction,

        #[arg(long, value_enum, default_value_t = PreHashAlg::Sha512)]
        /// The pre-hash (FIPS 204 Section 5.4); it must be at least as strong as the parameter
        /// set, so sha256 and shake128 fit hash-mldsa44 only.
        hash: PreHashAlg,

        #[arg(long)]
        /// The file containing the context string (raw bytes; hex with --hex-input) for signing or verifying
        ctxfile: Option<String>,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (raw bytes; hex with --hex-input) for verifying
        sigfile: Option<String>,

        #[arg(long)]
        /// The message representative file (64 bytes; raw bytes; hex with --hex-input) for
        /// sign-mu and verify-mu; stdin without it.
        mufile: Option<String>,

        #[arg(long)]
        /// Sign with the deterministic variant (FIPS 204 Section 3.4: rnd all zero) rather than
        /// the hedged default.
        deterministic: bool,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Decode hex data from stdin to binary.
    /// Supports streaming for low memory footprint and continuous processing from stdin to stdout.
    HexDecode,

    /// Encode binary data from stdin to hex.
    /// Supports streaming for low memory footprint and continuous processing from stdin to stdout.
    HexEncode,

    /// Perform HKDF-SHA256 (RFC 5869 extract-then-expand) of the provided input keying material:
    ///     OKM = HKDF-Expand(HKDF-Extract(salt, ikm), info, len)
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HKDF_SHA256 {
        /// The salt value in hex.
        /// The `salt_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        salt: Option<String>,

        /// A file containing the salt value in binary.
        /// If both salt and salt_file options are provided, the file will be used.
        #[arg(short, long)]
        salt_file: Option<String>,

        /// An Input Keying Material in hex.
        /// The `ikm_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        ikm: Option<String>,

        /// A file containing the input keying material in binary.
        /// If both ikm and ikm_file options are provided, the file will be used.
        #[arg(short, long)]
        ikm_file: Option<String>,

        /// The HKDF `info` input (RFC 5869 Section 2.3) in hex. Optional; defaults to empty.
        #[arg(long)]
        additional_input: Option<String>,

        /// A file containing the HKDF `info` input in binary. Optional; defaults to empty.
        /// If both additional_input and additional_input_file options are provided, the file will be used.
        #[arg(short, long)]
        additional_input_file: Option<String>,

        /// Length of output to produce, in bytes: at most 255 times the hash's output length.
        #[arg(short, long)]
        len: usize,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform HKDF-SHA384 (RFC 5869 extract-then-expand) of the provided input keying material:
    ///     OKM = HKDF-Expand(HKDF-Extract(salt, ikm), info, len)
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HKDF_SHA384 {
        /// The salt value in hex.
        /// The `salt_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        salt: Option<String>,

        /// A file containing the salt value in binary.
        /// If both salt and salt_file options are provided, the file will be used.
        #[arg(short, long)]
        salt_file: Option<String>,

        /// An Input Keying Material in hex.
        /// The `ikm_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        ikm: Option<String>,

        /// A file containing the input keying material in binary.
        /// If both ikm and ikm_file options are provided, the file will be used.
        #[arg(short, long)]
        ikm_file: Option<String>,

        /// The HKDF `info` input (RFC 5869 Section 2.3) in hex. Optional; defaults to empty.
        #[arg(long)]
        additional_input: Option<String>,

        /// A file containing the HKDF `info` input in binary. Optional; defaults to empty.
        /// If both additional_input and additional_input_file options are provided, the file will be used.
        #[arg(short, long)]
        additional_input_file: Option<String>,

        /// Length of output to produce, in bytes: at most 255 times the hash's output length.
        #[arg(short, long)]
        len: usize,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform HKDF-SHA512 (RFC 5869 extract-then-expand) of the provided input keying material:
    ///     OKM = HKDF-Expand(HKDF-Extract(salt, ikm), info, len)
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HKDF_SHA512 {
        /// The salt value in hex.
        /// The `salt_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        salt: Option<String>,

        /// A file containing the salt value in binary.
        /// If both salt and salt_file options are provided, the file will be used.
        #[arg(short, long)]
        salt_file: Option<String>,

        /// An Input Keying Material in hex.
        /// The `ikm_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        ikm: Option<String>,

        /// A file containing the input keying material in binary.
        /// If both ikm and ikm_file options are provided, the file will be used.
        #[arg(short, long)]
        ikm_file: Option<String>,

        /// The HKDF `info` input (RFC 5869 Section 2.3) in hex. Optional; defaults to empty.
        #[arg(long)]
        additional_input: Option<String>,

        /// A file containing the HKDF `info` input in binary. Optional; defaults to empty.
        /// If both additional_input and additional_input_file options are provided, the file will be used.
        #[arg(short, long)]
        additional_input_file: Option<String>,

        /// Length of output to produce, in bytes: at most 255 times the hash's output length.
        #[arg(short, long)]
        len: usize,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform HKDF-SM3 (RFC 5869 extract-then-expand) of the provided input keying material:
    ///     OKM = HKDF-Expand(HKDF-Extract(salt, ikm), info, len)
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HKDF_SM3 {
        /// The salt value in hex.
        /// The `salt_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        salt: Option<String>,

        /// A file containing the salt value in binary.
        /// If both salt and salt_file options are provided, the file will be used.
        #[arg(short, long)]
        salt_file: Option<String>,

        /// An Input Keying Material in hex.
        /// The `ikm_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        ikm: Option<String>,

        /// A file containing the input keying material in binary.
        /// If both ikm and ikm_file options are provided, the file will be used.
        #[arg(short, long)]
        ikm_file: Option<String>,

        /// The HKDF `info` input (RFC 5869 Section 2.3) in hex. Optional; defaults to empty.
        #[arg(long)]
        additional_input: Option<String>,

        /// A file containing the HKDF `info` input in binary. Optional; defaults to empty.
        /// If both additional_input and additional_input_file options are provided, the file will be used.
        #[arg(short, long)]
        additional_input_file: Option<String>,

        /// Length of output to produce, in bytes: at most 255 times the hash's output length.
        #[arg(short, long)]
        len: usize,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA224 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SHA224 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA256 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SHA256 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA384 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SHA384 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA512 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SHA512 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA512/224 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SHA512_224 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA512/256 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SHA512_256 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA3-224 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SHA3_224 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA3-256 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SHA3_256 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA3-384 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SHA3_384 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA3-512 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SHA3_512 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// Perform HMAC-SM3 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    HMAC_SM3 {
        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// Exits 0 if the value matches and 255 with an error message if not; nothing is written.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Compute or verify a KMAC128 (NIST SP 800-185 Sec 4) over the content provided on stdin.
    /// The tag length and customization string are bound into the computation, so the verifier
    /// must use the same values.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    KMAC128 {
        /// Length of the tag in bytes, at least 4 (SP 800-185 Sec 8.4.2).
        length: usize,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given, domain-separating this use of KMAC
        /// from another.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short, long)]
        /// Verify against this tag (hex) instead of computing one.
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// Compute or verify a KMAC256 (NIST SP 800-185 Sec 4) over the content provided on stdin.
    /// See kmac128.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    KMAC256 {
        /// Length of the tag in bytes, at least 4 (SP 800-185 Sec 8.4.2).
        length: usize,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given, domain-separating this use of KMAC
        /// from another.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        /// The MAC key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the MAC key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short, long)]
        /// Verify against this tag (hex) instead of computing one.
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// Compute a KMACXOF128 (NIST SP 800-185 Sec 4.3.1) over the content provided on stdin: KMAC
    /// as a XOF, with the output length not bound in, so any length streams. Requires the
    /// output length in bytes. Nothing is verified; a reader squeezes the same stream.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    KMACXOF128 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        /// The key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the key (raw bytes; hex with --hex-input).
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Compute a KMACXOF256 (NIST SP 800-185 Sec 4.3.1) over the content provided on stdin: KMAC
    /// as a XOF, with the output length not bound in, so any length streams. Requires the
    /// output length in bytes. Nothing is verified; a reader squeezes the same stream.
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    KMACXOF256 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        /// The key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the key (raw bytes; hex with --hex-input).
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The ML-DSA-44 signature algorithm.
    MLDSA44 {
        action: MLDSAAction,

        #[arg(long)]
        /// The file containing the context string (raw bytes; hex with --hex-input) for signing or verifying
        ctxfile: Option<String>,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (raw bytes; hex with --hex-input) for verifying
        sigfile: Option<String>,

        #[arg(long)]
        /// The message representative file (64 bytes; raw bytes; hex with --hex-input) for
        /// sign-mu and verify-mu; stdin without it.
        mufile: Option<String>,

        #[arg(long)]
        /// Sign with the deterministic variant (FIPS 204 Section 3.4: rnd all zero) rather than
        /// the hedged default.
        deterministic: bool,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The ML-DSA-65 signature algorithm.
    MLDSA65 {
        action: MLDSAAction,

        #[arg(long)]
        /// The file containing the context string (raw bytes; hex with --hex-input) for signing or verifying
        ctxfile: Option<String>,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (raw bytes; hex with --hex-input) for verifying
        sigfile: Option<String>,

        #[arg(long)]
        /// The message representative file (64 bytes; raw bytes; hex with --hex-input) for
        /// sign-mu and verify-mu; stdin without it.
        mufile: Option<String>,

        #[arg(long)]
        /// Sign with the deterministic variant (FIPS 204 Section 3.4: rnd all zero) rather than
        /// the hedged default.
        deterministic: bool,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The ML-DSA-87 signature algorithm.
    MLDSA87 {
        action: MLDSAAction,

        #[arg(long)]
        /// The file containing the context string (raw bytes; hex with --hex-input) for signing or verifying
        ctxfile: Option<String>,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (raw bytes; hex with --hex-input) for verifying
        sigfile: Option<String>,

        #[arg(long)]
        /// The message representative file (64 bytes; raw bytes; hex with --hex-input) for
        /// sign-mu and verify-mu; stdin without it.
        mufile: Option<String>,

        #[arg(long)]
        /// Sign with the deterministic variant (FIPS 204 Section 3.4: rnd all zero) rather than
        /// the hedged default.
        deterministic: bool,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-128 Key Wrap (NIST SP 800-38F Sec 6.2, RFC 3394): `-d encrypt` wraps stdin to stdout,
    /// `-d decrypt` unwraps it.
    ///
    /// Wraps a key -- or any data that is a whole number of 8-byte blocks, at least 16 bytes --
    /// under the given key-encryption key (KEK). The output is 8 bytes longer than the input.
    /// There is NO IV: wrapping is deterministic, and nothing is prepended on `encrypt` or
    /// consumed on `decrypt`.
    ///
    /// Unwrapping is authenticated. A ciphertext that was tampered with, wrapped under a different
    /// KEK, or produced by aes*-kwp makes the command exit non-zero with nothing written. Input to
    /// `decrypt` must be a whole number of 8-byte blocks, at least 24 bytes.
    ///
    /// This command is not streaming: all of stdin is read before anything is written, because
    /// the algorithm makes six passes over the whole input. For data that is not a multiple of
    /// 8 bytes, use aes128-kwp.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_KW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte AES key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 Key Wrap (NIST SP 800-38F Sec 6.2, RFC 3394): `-d encrypt` wraps stdin to stdout,
    /// `-d decrypt` unwraps it.
    ///
    /// See `aes128-kw` for the input-length rules, the absence of an IV and the non-streaming
    /// note; only the key length differs.
    AES192_KW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte AES key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 Key Wrap (NIST SP 800-38F Sec 6.2, RFC 3394): `-d encrypt` wraps stdin to stdout,
    /// `-d decrypt` unwraps it.
    ///
    /// See `aes128-kw` for the input-length rules, the absence of an IV and the non-streaming
    /// note; only the key length differs.
    AES256_KW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte AES key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-128 Key Wrap with Padding (NIST SP 800-38F Sec 6.3, RFC 5649): `-d encrypt` wraps
    /// stdin to stdout, `-d decrypt` unwraps it.
    ///
    /// As aes128-kw, but for data of any length from 1 byte up: the input is padded to a whole
    /// number of 8-byte blocks and the output is that length plus 8. Its ciphertexts are not
    /// interchangeable with aes128-kw's. Input to `decrypt` must be a whole number of 8-byte
    /// blocks, at least 16 bytes.
    ///
    /// See `aes128-kw` for the absence of an IV, the authenticated `decrypt` and the non-streaming
    /// note.
    AES128_KWP {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte AES key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 Key Wrap with Padding (NIST SP 800-38F Sec 6.3, RFC 5649): `-d encrypt` wraps
    /// stdin to stdout, `-d decrypt` unwraps it.
    ///
    /// See `aes128-kwp`; only the key length differs.
    AES192_KWP {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte AES key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 Key Wrap with Padding (NIST SP 800-38F Sec 6.3, RFC 5649): `-d encrypt` wraps
    /// stdin to stdout, `-d decrypt` unwraps it.
    ///
    /// See `aes128-kwp`; only the key length differs.
    AES256_KWP {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte AES key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Triple DES Key Wrap, TKW (NIST SP 800-38F Sec 7): `-d encrypt` wraps stdin to stdout,
    /// `-d decrypt` unwraps it. LEGACY ONLY: SP 800-38F approves TKW to support legacy systems
    /// and says it should not be used for new applications.
    ///
    /// The same command as `aes128-kw` over TDEA at half the width: input to `encrypt` is a whole
    /// number of 4-byte blocks, at least 8 bytes, and the output is 4 bytes longer; input to
    /// `decrypt` is a whole number of 4-byte blocks, at least 12 bytes. There is NO IV, and the
    /// whole input is read before anything is written. See `aes128-kw` for the rest.
    ///
    /// The key is 24 bytes, KEY1 || KEY2 || KEY3, with three distinct component keys none of which
    /// is a weak DES key (SP 800-67 Rev 2 Sec 3.1 and 3.3.2). Two-key TDEA unwraps through
    /// `tdes2-tkw`.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    TDES_TKW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte TDES key-encryption key bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte TDES key-encryption key bundle (raw bytes; hex with
        /// --hex-input). If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Two-key Triple DES Key Wrap (2TDEA TKW), UNWRAPPING ONLY. See `tdes2-cbc` for why there is
    /// no `encrypt`, and `tdes-tkw` for the input rules.
    TDES2_TKW {
        #[arg(short = 'd', long = "direction")]
        action: DecryptOnlyAction,

        /// The 16-byte two-key TDES bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte two-key TDES bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The ML-KEM-512 key encapsulation algorithm.
    MLKEM512 {
        action: mlkem_cmd::MLKEMAction,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for decaps
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for encaps
        pkfile: Option<String>,

        #[arg(long)]
        /// The ciphertext value file (raw bytes; hex with --hex-input) either for encaps to output to, or for decaps to read from.
        ctfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The ML-KEM-768 key encapsulation algorithm.
    MLKEM768 {
        action: mlkem_cmd::MLKEMAction,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for decaps
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for encaps
        pkfile: Option<String>,

        #[arg(long)]
        /// The ciphertext value file (raw bytes; hex with --hex-input) either for encaps to output to, or for decaps to read from.
        ctfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The ML-KEM-1024 key encapsulation algorithm.
    MLKEM1024 {
        action: mlkem_cmd::MLKEMAction,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for decaps
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for encaps
        pkfile: Option<String>,

        #[arg(long)]
        /// The ciphertext value file (raw bytes; hex with --hex-input) either for encaps to output to, or for decaps to read from.
        ctfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform ParallelHash128 (NIST SP 800-185 Sec 6) of the content provided on stdin.
    /// The block size is part of the function: the same input under a different block size gives
    /// an unrelated hash, so both sides must use the same value.
    /// Supports streaming update for low memory footprint.
    PARALLELHASH128 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 'b', long)]
        /// Block size B in bytes, for the parallel split.
        block_size: usize,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform ParallelHash256 (NIST SP 800-185 Sec 6). See parallelhash128.
    PARALLELHASH256 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 'b', long)]
        /// Block size B in bytes, for the parallel split.
        block_size: usize,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Compute or verify a Poly1305 tag (RFC 8439 Sec 2.5) over the content provided on stdin.
    ///
    /// WARNING: the key is ONE-TIME. MACing two messages under the same 32-byte key lets an
    /// attacker forge tags. For general-purpose authentication use an HMAC or KMAC command, or
    /// `chacha20-poly1305`, which derives a fresh Poly1305 key for every message.
    POLY1305 {
        /// The 32-byte one-time key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte one-time key (raw bytes; hex with --hex-input).
        #[arg(short, long)]
        key_file: Option<String>,

        /// A 16-byte tag to be verified.
        /// The command will output either 0 for success or -1 for verification failure.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// Perform ParallelHashXOF128 (NIST SP 800-185 Sec 6.3.1): ParallelHash as a XOF, with
    /// the output length not bound in. See parallelhash128 for the block size.
    PARALLELHASHXOF128 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 'b', long)]
        /// Block size B in bytes, for the parallel split.
        block_size: usize,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform ParallelHashXOF256 (NIST SP 800-185 Sec 6.3.1): ParallelHash as a XOF, with
    /// the output length not bound in. See parallelhash128 for the block size.
    PARALLELHASHXOF256 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 'b', long)]
        /// Block size B in bytes, for the parallel split.
        block_size: usize,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Generate cryptographically-secure random bytes from a Hash_DRBG (SP 800-90A Rev. 1), seeded
    /// from the operating system's entropy source (/dev/random or equivalent) unless --seed-file.
    RNG {
        /// Number of bytes to generate. If omitted, it will stream continuously until the process is terminated.
        #[arg(short, long)]
        len: Option<u32>,

        /// The hash under the DRBG: sha512 is a 256-bit instance, sha256 a 128-bit one.
        #[arg(long, value_enum, default_value_t = DrbgHash::Sha512)]
        hash: DrbgHash,

        /// HAZARDOUS: instantiate the DRBG from this file's bytes (raw; hex with --hex-input)
        /// as its entropy input instead of the operating system, so the same file gives the
        /// same stream. There is no nonce, so the file must hold 3/2 of the strength: 48 bytes
        /// for sha512, 24 for sha256. For reproducible test data only; the output is as secret as
        /// the file.
        #[arg(long)]
        seed_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform SHA3-224 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA3_224 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHA3-256 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA3_256 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHA3-384 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA3_384 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHA3-512 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA3_512 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHA224 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA224 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHA256 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA256 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHA384 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA384 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHA512 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA512 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHA512/224 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA512_224 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHA512/256 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA512_256 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHAKE128 of the content provided on stdin. Requires the output length in bytes.
    /// Supports streaming update for low memory footprint.
    SHAKE128 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHAKE256 of the content provided on stdin. Requires the output length in bytes.
    /// Supports streaming update for low memory footprint.
    SHAKE256 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// The SM2 Digital Signature Algorithm (GB/T 32918.2-2016; draft-shen-sm2-ecdsa-02 S5),
    /// randomised only (the standard specifies no deterministic scheme). `--idfile` is mandatory
    /// for signing and verifying: it carries the signer's identity IDA (S5.5), which every SM2
    /// operation needs and which has no default value.
    SM2 {
        action: SM2Action,

        #[arg(long)]
        /// The file containing the signer's identity IDA (raw bytes), mandatory for signing and
        /// verifying
        idfile: Option<String>,

        #[arg(long)]
        /// The private key file (in hex or binary) for signing
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for verifying
        pkfile: Option<String>,

        #[arg(long)]
        /// The signature value file (in hex or binary) for verifying
        sigfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform SM3 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SM3 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Triple DES (three-key TDEA, NIST SP 800-67 Rev 2) in CBC mode (SP 800-38A Sec 6.2) with
    /// PKCS7 padding, streaming stdin to stdout. LEGACY: NIST disallows TDEA for encryption after
    /// 2023 (SP 800-131A Rev 2); this exists for data and protocols that still depend on it.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 8 BYTES of the
    /// output; on `decrypt` it is read back from the first 8 bytes of the input, so the two compose
    /// directly in a pipeline. With `--iv` (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied
    /// instead: `encrypt` uses it and writes ONLY the ciphertext, and `decrypt` reads ONLY
    /// ciphertext from stdin, as for `aes128-cbc`.
    ///
    /// Input may be any length: it is padded with PKCS7 to a whole number of 8-byte blocks, so the
    /// ciphertext after the IV is 1 to 8 bytes longer than the plaintext, and `decrypt` rejects a
    /// ciphertext whose padding is malformed.
    ///
    /// The key is 24 bytes, KEY1 || KEY2 || KEY3, with three distinct component keys none of which
    /// is a weak DES key (SP 800-67 Rev 2 Sec 3.1 and 3.3.2). Two-key TDEA decrypts through the
    /// `tdes2-*` commands.
    ///
    /// WARNING: CBC provides confidentiality only. It does not detect tampering, and neither the
    /// ciphertext nor the IV is authenticated. Do not decrypt data you have not authenticated
    /// separately. One key bundle must not encrypt more than 2^20 blocks (8 MiB) in total:
    /// `encrypt` refuses longer input, and counting across invocations is the caller's.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    TDES_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte TDES key bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte TDES key bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 8-byte IV in hex. Supplied instead of generated: `encrypt` then writes no IV and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 8-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Triple DES (three-key TDEA) in CFB64 mode (SP 800-38A Sec 6.3, segment = block), streaming
    /// stdin to stdout. LEGACY: see `tdes-cbc`.
    ///
    /// The segment size is the full 8-byte block, i.e. CFB64. SP 800-38A's 8-bit CFB is a
    /// different, non-interoperable mode; use `tdes-cfb8` for that.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 8 BYTES of the
    /// output; on `decrypt` it is read back from the first 8 bytes of the input. With `--iv` (hex)
    /// or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead and only ciphertext is written or
    /// read.
    ///
    /// Input may be ANY length: CFB is a stream cipher, so nothing is padded and the ciphertext is
    /// exactly as long as the plaintext.
    ///
    /// See `tdes-cbc` for the key format and the warnings, which apply unchanged.
    TDES_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte TDES key bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte TDES key bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 8-byte IV in hex. Supplied instead of generated: `encrypt` then writes no IV and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 8-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Triple DES (three-key TDEA) in CFB8 mode (SP 800-38A Sec 6.3, s = 8), streaming stdin to
    /// stdout. LEGACY: see `tdes-cbc`.
    ///
    /// CFB8 is a DIFFERENT mode from `tdes-cfb`, not a variant: the two ciphertexts agree only on
    /// their first byte. It also costs one TDES call per byte, eight times the work of `tdes-cfb`,
    /// so prefer that unless a byte-granular mode is specifically required.
    ///
    /// See `tdes-cfb` for the IV convention and input-length rule, and `tdes-cbc` for the key
    /// format and the warnings, which apply unchanged.
    TDES_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte TDES key bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte TDES key bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 8-byte IV in hex. Supplied instead of generated: `encrypt` then writes no IV and
        /// `decrypt` reads none. See the IV paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 8-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Triple DES (three-key TDEA) in CTR mode (SP 800-38A Sec 6.5, TDEA per its Appendix E),
    /// streaming stdin to stdout. LEGACY: see `tdes-cbc`.
    ///
    /// On `encrypt`, a fresh 6-BYTE NONCE is generated and written as the first 6 bytes of the
    /// output; on `decrypt` it is read back from the first 6 bytes of the input. With `--iv` (hex)
    /// or `--iv-file` (raw bytes), the nonce is supplied instead and only ciphertext is written or
    /// read; it MUST then be unique per message under one key bundle. The remaining 2 bytes of the
    /// 8-byte counter block are the counter, so a single message is limited to 65 536 blocks
    /// (512 KiB); longer input fails rather than repeating a counter block.
    ///
    /// Input may be any length up to that limit: CTR is a stream cipher, so nothing is padded and
    /// the ciphertext is exactly as long as the plaintext.
    ///
    /// WARNING: CTR provides confidentiality only, and is the most malleable of the modes here: a
    /// flipped ciphertext bit flips exactly the corresponding plaintext bit. A repeated nonce under
    /// one key is fatal, and the nonce is only 48 bits, so the number of messages under one key
    /// bundle must stay small. See `tdes-cbc` for the key format and the other warnings.
    TDES_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte TDES key bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte TDES key bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 6-byte nonce in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 6-byte nonce, as raw bytes exactly as they are (no hex
        /// decoding). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Triple DES (three-key TDEA) in ECB mode (SP 800-38A Sec 6.1), streaming stdin to stdout.
    /// LEGACY: see `tdes-cbc`.
    ///
    /// WARNING: ECB is NOT a confidentiality mode for data. Under a given key every plaintext
    /// block maps to the same ciphertext block, so equal blocks stay visibly equal, the same input
    /// always gives the same output, and blocks can be reordered, repeated or removed undetectably.
    /// This command exists for interoperability with systems that require ECB and for test
    /// vectors.
    ///
    /// There is NO IV: nothing is prepended on `encrypt` and nothing is consumed on `decrypt`, so
    /// the output is exactly as long as the input.
    ///
    /// Input must be a whole number of 8-byte blocks: this command is block-aligned and applies no
    /// padding, so unaligned input is rejected rather than padded.
    ///
    /// See `tdes-cbc` for the key format.
    TDES_ECB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte TDES key bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte TDES key bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Two-key Triple DES (2TDEA, Key3 = Key1) in CBC mode, DECRYPTION ONLY, streaming stdin to
    /// stdout. NIST SP 800-131A Rev 2 Table 1 disallows two-key TDEA for encryption and allows
    /// decryption for legacy use, so `encrypt` does not exist for this command. That is a guard
    /// against accidental encryption: `tdes2-cfb` and `tdes2-ctr` decryption are the forward
    /// cipher, which a determined caller can turn into encryption, so a deployment that must rule
    /// that out should expose only `tdes2-cbc` and `tdes2-ecb`.
    ///
    /// The first 8 bytes of input are the IV, as the `tdes-cbc decrypt` convention, unless `--iv`
    /// or `--iv-file` supplies it; the rest is PKCS7-padded ciphertext, as `tdes-cbc` writes it.
    ///
    /// The key is 16 bytes, KEY1 || KEY2, with two distinct component keys neither of which is a
    /// weak DES key (SP 800-67 Rev 2 Sec 3.1 and 3.3.2).
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    TDES2_CBC {
        #[arg(short = 'd', long = "direction")]
        action: DecryptOnlyAction,

        /// The 16-byte two-key TDES bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte two-key TDES bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 8-byte IV in hex. Supplied instead of read from the input, which is then
        /// ciphertext only.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 8-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Two-key Triple DES (2TDEA) in CFB64 mode, DECRYPTION ONLY. See `tdes2-cbc` for why there is
    /// no `encrypt`, and `tdes-cfb` for the IV convention (first 8 bytes of input, or `--iv`) and
    /// the any-length input rule.
    TDES2_CFB {
        #[arg(short = 'd', long = "direction")]
        action: DecryptOnlyAction,

        /// The 16-byte two-key TDES bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte two-key TDES bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 8-byte IV in hex. Supplied instead of read from the input, which is then
        /// ciphertext only.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 8-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Two-key Triple DES (2TDEA) in CFB8 mode, DECRYPTION ONLY. See `tdes2-cbc` for why there is
    /// no `encrypt`, and `tdes-cfb8` for the IV convention and the difference from CFB64.
    TDES2_CFB8 {
        #[arg(short = 'd', long = "direction")]
        action: DecryptOnlyAction,

        /// The 16-byte two-key TDES bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte two-key TDES bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 8-byte IV in hex. Supplied instead of read from the input, which is then
        /// ciphertext only.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 8-byte IV, (raw bytes; hex with --hex-input).
        /// If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Two-key Triple DES (2TDEA) in CTR mode, DECRYPTION ONLY. See `tdes2-cbc` for why there is
    /// no `encrypt`, and `tdes-ctr` for the nonce convention (first 6 bytes of input, or `--iv`)
    /// and the 512 KiB per-message limit.
    TDES2_CTR {
        #[arg(short = 'd', long = "direction")]
        action: DecryptOnlyAction,

        /// The 16-byte two-key TDES bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte two-key TDES bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 6-byte nonce in hex. Supplied instead of read from the input, which is then
        /// ciphertext only.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 6-byte nonce, as raw bytes exactly as they are (no hex
        /// decoding). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Two-key Triple DES (2TDEA) in ECB mode, DECRYPTION ONLY. See `tdes2-cbc` for why there is
    /// no `encrypt`, and `tdes-ecb` for the ECB warning: no IV, input a whole number of 8-byte
    /// blocks, no unpadding.
    TDES2_ECB {
        #[arg(short = 'd', long = "direction")]
        action: DecryptOnlyAction,

        /// The 16-byte two-key TDES bundle in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte two-key TDES bundle (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform TupleHash128 (NIST SP 800-185 Sec 5) over a tuple of strings. The tuple is given
    /// by repeated --element flags, each in hex; with none, stdin is hashed as a single element.
    /// The boundaries between elements are part of the hash.
    TUPLEHASH128 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 'e', long = "element")]
        /// A tuple element, in hex. Repeat for each element, in order.
        elements: Vec<String>,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform TupleHash256 (NIST SP 800-185 Sec 5). See tuplehash128.
    TUPLEHASH256 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 'e', long = "element")]
        /// A tuple element, in hex. Repeat for each element, in order.
        elements: Vec<String>,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform TupleHashXOF128 (NIST SP 800-185 Sec 5.3.1): TupleHash as a XOF, with the
    /// output length not bound in. See tuplehash128 for the tuple.
    TUPLEHASHXOF128 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 'e', long = "element")]
        /// A tuple element, in hex. Repeat for each element, in order.
        elements: Vec<String>,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform TupleHashXOF256 (NIST SP 800-185 Sec 5.3.1): TupleHash as a XOF, with the
    /// output length not bound in. See tuplehash128 for the tuple.
    TUPLEHASHXOF256 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 'e', long = "element")]
        /// A tuple element, in hex. Repeat for each element, in order.
        elements: Vec<String>,

        #[arg(short = 's', long)]
        /// Customization string S, as the characters given.
        customization: Option<String>,

        #[arg(long)]
        /// Customization string S in hex, for bytes that are not text.
        customization_hex: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },
}

fn main() {
    std::thread::Builder::new()
        .name("bc-rust-main".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(run)
        .expect("failed to start CLI thread")
        .join()
        .expect("CLI thread panicked");
}

fn run() {
    let cli = Cli::parse();
    helpers::set_hex_input(cli.hex_input);

    match &cli.subcommands {
        Some(Subcommands::AES128_CBC { direction, key, key_file, iv, iv_file, x }) => {
            aes_cbc_cmd::aes128_cbc_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES128_CCM {
            direction,
            key,
            key_file,
            nonce,
            nonce_file,
            aad,
            aad_file,
            tag_len,
            x,
        }) => {
            aes_ccm_cmd::aes128_ccm_cmd(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x,
            );
        }
        Some(Subcommands::AES128_CFB { direction, key, key_file, iv, iv_file, x }) => {
            aes_cfb_cmd::aes128_cfb_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES128_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            aes_cfb8_cmd::aes128_cfb8_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES128_CTR { direction, key, key_file, iv, iv_file, x }) => {
            aes_ctr_cmd::aes128_ctr_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES128_ECB { direction, key, key_file, x }) => {
            aes_ecb_cmd::aes128_ecb_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::AES128_GCM {
            direction,
            key,
            key_file,
            iv,
            iv_file,
            aad,
            aad_file,
            x,
        }) => {
            aes_gcm_cmd::aes128_gcm_cmd(direction, key, key_file, iv, iv_file, aad, aad_file, *x);
        }
        Some(Subcommands::AES192_CBC { direction, key, key_file, iv, iv_file, x }) => {
            aes_cbc_cmd::aes192_cbc_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES192_CCM {
            direction,
            key,
            key_file,
            nonce,
            nonce_file,
            aad,
            aad_file,
            tag_len,
            x,
        }) => {
            aes_ccm_cmd::aes192_ccm_cmd(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x,
            );
        }
        Some(Subcommands::AES192_CFB { direction, key, key_file, iv, iv_file, x }) => {
            aes_cfb_cmd::aes192_cfb_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES192_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            aes_cfb8_cmd::aes192_cfb8_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES192_CTR { direction, key, key_file, iv, iv_file, x }) => {
            aes_ctr_cmd::aes192_ctr_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES192_ECB { direction, key, key_file, x }) => {
            aes_ecb_cmd::aes192_ecb_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::AES192_GCM {
            direction,
            key,
            key_file,
            iv,
            iv_file,
            aad,
            aad_file,
            x,
        }) => {
            aes_gcm_cmd::aes192_gcm_cmd(direction, key, key_file, iv, iv_file, aad, aad_file, *x);
        }
        Some(Subcommands::AES256_CBC { direction, key, key_file, iv, iv_file, x }) => {
            aes_cbc_cmd::aes256_cbc_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES256_CCM {
            direction,
            key,
            key_file,
            nonce,
            nonce_file,
            aad,
            aad_file,
            tag_len,
            x,
        }) => {
            aes_ccm_cmd::aes256_ccm_cmd(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x,
            );
        }
        Some(Subcommands::AES256_CFB { direction, key, key_file, iv, iv_file, x }) => {
            aes_cfb_cmd::aes256_cfb_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES256_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            aes_cfb8_cmd::aes256_cfb8_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES256_CTR { direction, key, key_file, iv, iv_file, x }) => {
            aes_ctr_cmd::aes256_ctr_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::AES256_ECB { direction, key, key_file, x }) => {
            aes_ecb_cmd::aes256_ecb_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::AES256_GCM {
            direction,
            key,
            key_file,
            iv,
            iv_file,
            aad,
            aad_file,
            x,
        }) => {
            aes_gcm_cmd::aes256_gcm_cmd(direction, key, key_file, iv, iv_file, aad, aad_file, *x);
        }
        Some(Subcommands::AsconAEAD128 {
            key,
            key_file,
            nonce,
            nonce_file,
            aad,
            aad_file,
            direction,
            x,
        }) => {
            let decrypt = matches!(direction, CipherDirection::Decrypt);
            ascon_cmd::aead128_cmd(key, key_file, nonce, nonce_file, aad, aad_file, decrypt, *x);
        }
        Some(Subcommands::AsconCXOF128 { length, customization, customization_hex, x }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            ascon_cmd::cxof128_cmd(&s, *length, *x);
        }
        Some(Subcommands::AsconHash256 { x }) => {
            ascon_cmd::hash256_cmd(*x);
        }
        Some(Subcommands::AsconXOF128 { length, x }) => {
            ascon_cmd::xof128_cmd(*length, *x);
        }
        Some(Subcommands::Base64Decode) => {
            encoders_cmd::base64_decode_cmd();
        }
        Some(Subcommands::Base64Encode) => {
            encoders_cmd::base64_encode_cmd();
        }
        Some(Subcommands::ECDSA_P256 { action, skfile, pkfile, sigfile, x, deterministic }) => {
            ecdsa_cmd::ecdsa_p256_cmd(action, skfile, pkfile, sigfile, *x, *deterministic);
        }
        Some(Subcommands::ECDSA_P384 { action, skfile, pkfile, sigfile, x, deterministic }) => {
            ecdsa_cmd::ecdsa_p384_cmd(action, skfile, pkfile, sigfile, *x, *deterministic);
        }
        Some(Subcommands::ECDSA_P521 { action, skfile, pkfile, sigfile, x, deterministic }) => {
            ecdsa_cmd::ecdsa_p521_cmd(action, skfile, pkfile, sigfile, *x, *deterministic);
        }
        Some(Subcommands::ECDSA_SECP256K1 {
            action,
            skfile,
            pkfile,
            sigfile,
            x,
            deterministic,
        }) => {
            ecdsa_cmd::ecdsa_secp256k1_cmd(action, skfile, pkfile, sigfile, *x, *deterministic);
        }
        Some(Subcommands::ECDSA_BP256R1 { action, skfile, pkfile, sigfile, x, deterministic }) => {
            ecdsa_cmd::ecdsa_bp256r1_cmd(action, skfile, pkfile, sigfile, *x, *deterministic);
        }
        Some(Subcommands::ECDSA_BP384R1 { action, skfile, pkfile, sigfile, x, deterministic }) => {
            ecdsa_cmd::ecdsa_bp384r1_cmd(action, skfile, pkfile, sigfile, *x, *deterministic);
        }
        Some(Subcommands::ECDSA_BP512R1 { action, skfile, pkfile, sigfile, x, deterministic }) => {
            ecdsa_cmd::ecdsa_bp512r1_cmd(action, skfile, pkfile, sigfile, *x, *deterministic);
        }
        Some(Subcommands::CHACHA20 { direction, key, key_file, iv, iv_file, x }) => {
            chacha20_cmd::chacha20_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::CHACHA20_POLY1305 {
            direction,
            key,
            key_file,
            iv,
            iv_file,
            aad,
            aad_file,
            x,
        }) => {
            chacha20_poly1305_cmd::chacha20_poly1305_cmd(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x,
            );
        }
        Some(Subcommands::HashMLDSA44 {
            action,
            hash,
            ctxfile,
            skfile,
            pkfile,
            sigfile,
            mufile,
            deterministic,
            x,
        }) => {
            let files =
                mldsa_cmd::Files { ctx: ctxfile, sk: skfile, pk: pkfile, sig: sigfile, mu: mufile };
            mldsa_cmd::mldsa_cmd(
                &mldsa_cmd::MLDSA44_SET,
                action,
                &files,
                Some(*hash),
                *deterministic,
                *x,
            );
        }
        Some(Subcommands::HashMLDSA65 {
            action,
            hash,
            ctxfile,
            skfile,
            pkfile,
            sigfile,
            mufile,
            deterministic,
            x,
        }) => {
            let files =
                mldsa_cmd::Files { ctx: ctxfile, sk: skfile, pk: pkfile, sig: sigfile, mu: mufile };
            mldsa_cmd::mldsa_cmd(
                &mldsa_cmd::MLDSA65_SET,
                action,
                &files,
                Some(*hash),
                *deterministic,
                *x,
            );
        }
        Some(Subcommands::HashMLDSA87 {
            action,
            hash,
            ctxfile,
            skfile,
            pkfile,
            sigfile,
            mufile,
            deterministic,
            x,
        }) => {
            let files =
                mldsa_cmd::Files { ctx: ctxfile, sk: skfile, pk: pkfile, sig: sigfile, mu: mufile };
            mldsa_cmd::mldsa_cmd(
                &mldsa_cmd::MLDSA87_SET,
                action,
                &files,
                Some(*hash),
                *deterministic,
                *x,
            );
        }
        Some(Subcommands::HexDecode) => {
            encoders_cmd::hex_decode_cmd();
        }
        Some(Subcommands::HexEncode) => {
            encoders_cmd::hex_encode_cmd();
        }
        Some(Subcommands::HKDF_SHA256 {
            salt,
            salt_file,
            ikm,
            ikm_file,
            additional_input,
            additional_input_file,
            len,
            x,
        }) => hkdf_cmd::hkdf_cmd(
            HKDFVariant::SHA256,
            salt,
            salt_file,
            ikm,
            ikm_file,
            additional_input,
            additional_input_file,
            *len,
            *x,
        ),
        Some(Subcommands::HKDF_SHA384 {
            salt,
            salt_file,
            ikm,
            ikm_file,
            additional_input,
            additional_input_file,
            len,
            x,
        }) => hkdf_cmd::hkdf_cmd(
            HKDFVariant::SHA384,
            salt,
            salt_file,
            ikm,
            ikm_file,
            additional_input,
            additional_input_file,
            *len,
            *x,
        ),
        Some(Subcommands::HKDF_SHA512 {
            salt,
            salt_file,
            ikm,
            ikm_file,
            additional_input,
            additional_input_file,
            len,
            x,
        }) => hkdf_cmd::hkdf_cmd(
            HKDFVariant::SHA512,
            salt,
            salt_file,
            ikm,
            ikm_file,
            additional_input,
            additional_input_file,
            *len,
            *x,
        ),
        Some(Subcommands::HKDF_SM3 {
            salt,
            salt_file,
            ikm,
            ikm_file,
            additional_input,
            additional_input_file,
            len,
            x,
        }) => hkdf_cmd::hkdf_cmd(
            HKDFVariant::SM3,
            salt,
            salt_file,
            ikm,
            ikm_file,
            additional_input,
            additional_input_file,
            *len,
            *x,
        ),
        Some(Subcommands::HMAC_SHA256 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SHA256, key, key_file, verify, *x)
        }
        Some(Subcommands::HMAC_SHA512 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SHA512, key, key_file, verify, *x)
        }
        Some(Subcommands::HMAC_SHA512_224 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SHA512_224, key, key_file, verify, *x)
        }
        Some(Subcommands::HMAC_SHA512_256 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SHA512_256, key, key_file, verify, *x)
        }
        Some(Subcommands::HMAC_SM3 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SM3, key, key_file, verify, *x)
        }
        Some(Subcommands::KMAC128 {
            length,
            customization,
            customization_hex,
            key,
            key_file,
            verify,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            mac_cmd::kmac_cmd(Strength::Bits128, *length, &s, key, key_file, verify, *x)
        }
        Some(Subcommands::KMAC256 {
            length,
            customization,
            customization_hex,
            key,
            key_file,
            verify,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            mac_cmd::kmac_cmd(Strength::Bits256, *length, &s, key, key_file, verify, *x)
        }
        Some(Subcommands::MLDSA44 {
            action,
            ctxfile,
            skfile,
            pkfile,
            sigfile,
            mufile,
            deterministic,
            x,
        }) => {
            let files =
                mldsa_cmd::Files { ctx: ctxfile, sk: skfile, pk: pkfile, sig: sigfile, mu: mufile };
            mldsa_cmd::mldsa_cmd(&mldsa_cmd::MLDSA44_SET, action, &files, None, *deterministic, *x);
        }
        Some(Subcommands::MLDSA65 {
            action,
            ctxfile,
            skfile,
            pkfile,
            sigfile,
            mufile,
            deterministic,
            x,
        }) => {
            let files =
                mldsa_cmd::Files { ctx: ctxfile, sk: skfile, pk: pkfile, sig: sigfile, mu: mufile };
            mldsa_cmd::mldsa_cmd(&mldsa_cmd::MLDSA65_SET, action, &files, None, *deterministic, *x);
        }
        Some(Subcommands::MLDSA87 {
            action,
            ctxfile,
            skfile,
            pkfile,
            sigfile,
            mufile,
            deterministic,
            x,
        }) => {
            let files =
                mldsa_cmd::Files { ctx: ctxfile, sk: skfile, pk: pkfile, sig: sigfile, mu: mufile };
            mldsa_cmd::mldsa_cmd(&mldsa_cmd::MLDSA87_SET, action, &files, None, *deterministic, *x);
        }
        Some(Subcommands::AES128_KW { direction, key, key_file, x }) => {
            aes_kw_cmd::aes128_kw_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::AES192_KW { direction, key, key_file, x }) => {
            aes_kw_cmd::aes192_kw_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::AES256_KW { direction, key, key_file, x }) => {
            aes_kw_cmd::aes256_kw_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::AES128_KWP { direction, key, key_file, x }) => {
            aes_kw_cmd::aes128_kwp_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::AES192_KWP { direction, key, key_file, x }) => {
            aes_kw_cmd::aes192_kwp_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::AES256_KWP { direction, key, key_file, x }) => {
            aes_kw_cmd::aes256_kwp_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::TDES_TKW { direction, key, key_file, x }) => {
            tdes_tkw_cmd::tdes_tkw_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::TDES2_TKW { action, key, key_file, x }) => {
            tdes_tkw_cmd::tdes2_tkw_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::MLKEM512 { action, skfile, pkfile, ctfile, x }) => {
            mlkem_cmd::mlkem_cmd(&mlkem_cmd::MLKEM512_SET, action, skfile, pkfile, ctfile, *x);
        }
        Some(Subcommands::MLKEM768 { action, skfile, pkfile, ctfile, x }) => {
            mlkem_cmd::mlkem_cmd(&mlkem_cmd::MLKEM768_SET, action, skfile, pkfile, ctfile, *x);
        }
        Some(Subcommands::MLKEM1024 { action, skfile, pkfile, ctfile, x }) => {
            mlkem_cmd::mlkem_cmd(&mlkem_cmd::MLKEM1024_SET, action, skfile, pkfile, ctfile, *x);
        }
        Some(Subcommands::PARALLELHASH128 {
            length,
            block_size,
            customization,
            customization_hex,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            sha3_cmd::parallelhash_cmd(Strength::Bits128, *length, *block_size, &s, *x);
        }
        Some(Subcommands::PARALLELHASH256 {
            length,
            block_size,
            customization,
            customization_hex,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            sha3_cmd::parallelhash_cmd(Strength::Bits256, *length, *block_size, &s, *x);
        }
        Some(Subcommands::RNG { len, hash, seed_file, x }) => {
            rng_cmd::rng_cmd(*len, *hash, seed_file, *x)
        }
        Some(Subcommands::POLY1305 { key, key_file, verify, x }) => {
            mac_cmd::poly1305_cmd(key, key_file, verify, *x)
        }
        Some(Subcommands::SHA3_224 { x }) => {
            sha3_cmd::sha3_cmd(SHA3Variant::SHA3_224, *x);
        }
        Some(Subcommands::SHA3_256 { x }) => {
            sha3_cmd::sha3_cmd(SHA3Variant::SHA3_256, *x);
        }
        Some(Subcommands::SHA3_384 { x }) => {
            sha3_cmd::sha3_cmd(SHA3Variant::SHA3_384, *x);
        }
        Some(Subcommands::SHA3_512 { x }) => {
            sha3_cmd::sha3_cmd(SHA3Variant::SHA3_512, *x);
        }
        Some(Subcommands::SHA224 { x }) => {
            sha2_cmd::sha2_cmd(SHA2Variant::SHA224, *x);
        }
        Some(Subcommands::SHA256 { x }) => {
            sha2_cmd::sha2_cmd(SHA2Variant::SHA256, *x);
        }
        Some(Subcommands::SHA384 { x }) => {
            sha2_cmd::sha2_cmd(SHA2Variant::SHA384, *x);
        }
        Some(Subcommands::SHA512 { x }) => {
            sha2_cmd::sha2_cmd(SHA2Variant::SHA512, *x);
        }
        Some(Subcommands::SHA512_224 { x }) => {
            sha2_cmd::sha2_cmd(SHA2Variant::SHA512_224, *x);
        }
        Some(Subcommands::SHA512_256 { x }) => {
            sha2_cmd::sha2_cmd(SHA2Variant::SHA512_256, *x);
        }
        Some(Subcommands::SHAKE128 { length, x }) => {
            sha3_cmd::shake_cmd(Strength::Bits128, *length, *x);
        }
        Some(Subcommands::SHAKE256 { length, x }) => {
            sha3_cmd::shake_cmd(Strength::Bits256, *length, *x);
        }
        Some(Subcommands::SM2 { action, idfile, skfile, pkfile, sigfile, x }) => {
            sm2_cmd::sm2_cmd(action, idfile, skfile, pkfile, sigfile, *x);
        }
        Some(Subcommands::SM3 { x }) => {
            sm3_cmd::sm3_cmd(*x);
        }
        Some(Subcommands::TDES_CBC { direction, key, key_file, iv, iv_file, x }) => {
            tdes_cbc_cmd::tdes_cbc_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::TDES_CFB { direction, key, key_file, iv, iv_file, x }) => {
            tdes_cfb_cmd::tdes_cfb_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::TDES_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            tdes_cfb8_cmd::tdes_cfb8_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::TDES_CTR { direction, key, key_file, iv, iv_file, x }) => {
            tdes_ctr_cmd::tdes_ctr_cmd(direction, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::TDES_ECB { direction, key, key_file, x }) => {
            tdes_ecb_cmd::tdes_ecb_cmd(direction, key, key_file, *x);
        }
        Some(Subcommands::TDES2_CBC { action, key, key_file, iv, iv_file, x }) => {
            tdes2_cbc_cmd::tdes2_cbc_cmd(action, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::TDES2_CFB { action, key, key_file, iv, iv_file, x }) => {
            tdes2_cfb_cmd::tdes2_cfb_cmd(action, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::TDES2_CFB8 { action, key, key_file, iv, iv_file, x }) => {
            tdes2_cfb8_cmd::tdes2_cfb8_cmd(action, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::TDES2_CTR { action, key, key_file, iv, iv_file, x }) => {
            tdes2_ctr_cmd::tdes2_ctr_cmd(action, key, key_file, iv, iv_file, *x);
        }
        Some(Subcommands::TDES2_ECB { action, key, key_file, x }) => {
            tdes2_ecb_cmd::tdes2_ecb_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::TUPLEHASH128 {
            length,
            elements,
            customization,
            customization_hex,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            sha3_cmd::tuplehash_cmd(Strength::Bits128, *length, elements, &s, *x);
        }
        Some(Subcommands::TUPLEHASH256 {
            length,
            elements,
            customization,
            customization_hex,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            sha3_cmd::tuplehash_cmd(Strength::Bits256, *length, elements, &s, *x);
        }
        Some(Subcommands::AES128_CMAC { key, key_file, verify, x }) => {
            mac_cmd::aes128_cmac_cmd(key, key_file, verify, *x)
        }
        Some(Subcommands::AES128_GMAC { key, key_file, iv, iv_file, verify, x }) => {
            mac_cmd::aes128_gmac_cmd(key, key_file, iv, iv_file, verify, *x)
        }
        Some(Subcommands::AES192_CMAC { key, key_file, verify, x }) => {
            mac_cmd::aes192_cmac_cmd(key, key_file, verify, *x)
        }
        Some(Subcommands::AES192_GMAC { key, key_file, iv, iv_file, verify, x }) => {
            mac_cmd::aes192_gmac_cmd(key, key_file, iv, iv_file, verify, *x)
        }
        Some(Subcommands::AES256_CMAC { key, key_file, verify, x }) => {
            mac_cmd::aes256_cmac_cmd(key, key_file, verify, *x)
        }
        Some(Subcommands::AES256_GMAC { key, key_file, iv, iv_file, verify, x }) => {
            mac_cmd::aes256_gmac_cmd(key, key_file, iv, iv_file, verify, *x)
        }
        Some(Subcommands::CSHAKE128 {
            length,
            function_name,
            customization,
            customization_hex,
            x,
        }) => {
            let n = function_name.as_deref().unwrap_or("").as_bytes();
            let s = sha3_cmd::load_customization(customization, customization_hex);
            sha3_cmd::cshake_cmd(Strength::Bits128, *length, n, &s, *x);
        }
        Some(Subcommands::KMACXOF128 {
            length,
            customization,
            customization_hex,
            key,
            key_file,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            mac_cmd::kmacxof_cmd(Strength::Bits128, *length, &s, key, key_file, *x)
        }
        Some(Subcommands::TUPLEHASHXOF128 {
            length,
            elements,
            customization,
            customization_hex,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            sha3_cmd::tuplehashxof_cmd(Strength::Bits128, *length, elements, &s, *x);
        }
        Some(Subcommands::PARALLELHASHXOF128 {
            length,
            block_size,
            customization,
            customization_hex,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            sha3_cmd::parallelhashxof_cmd(Strength::Bits128, *length, *block_size, &s, *x);
        }
        Some(Subcommands::CSHAKE256 {
            length,
            function_name,
            customization,
            customization_hex,
            x,
        }) => {
            let n = function_name.as_deref().unwrap_or("").as_bytes();
            let s = sha3_cmd::load_customization(customization, customization_hex);
            sha3_cmd::cshake_cmd(Strength::Bits256, *length, n, &s, *x);
        }
        Some(Subcommands::KMACXOF256 {
            length,
            customization,
            customization_hex,
            key,
            key_file,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            mac_cmd::kmacxof_cmd(Strength::Bits256, *length, &s, key, key_file, *x)
        }
        Some(Subcommands::TUPLEHASHXOF256 {
            length,
            elements,
            customization,
            customization_hex,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            sha3_cmd::tuplehashxof_cmd(Strength::Bits256, *length, elements, &s, *x);
        }
        Some(Subcommands::PARALLELHASHXOF256 {
            length,
            block_size,
            customization,
            customization_hex,
            x,
        }) => {
            let s = sha3_cmd::load_customization(customization, customization_hex);
            sha3_cmd::parallelhashxof_cmd(Strength::Bits256, *length, *block_size, &s, *x);
        }
        Some(Subcommands::HMAC_SHA224 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SHA224, key, key_file, verify, *x)
        }
        Some(Subcommands::HMAC_SHA384 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SHA384, key, key_file, verify, *x)
        }
        Some(Subcommands::HMAC_SHA3_224 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SHA3_224, key, key_file, verify, *x)
        }
        Some(Subcommands::HMAC_SHA3_256 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SHA3_256, key, key_file, verify, *x)
        }
        Some(Subcommands::HMAC_SHA3_384 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SHA3_384, key, key_file, verify, *x)
        }
        Some(Subcommands::HMAC_SHA3_512 { key, key_file, verify, x }) => {
            mac_cmd::mac_cmd(HMACVariant::SHA3_512, key, key_file, verify, *x)
        }
        None => {
            eprintln!("No command provided. See -h")
        }
    }
}
