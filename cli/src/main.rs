#![forbid(unsafe_code)]

mod ascon_cmd;
mod cbc_cmd;
mod ccm_cmd;
mod cfb8_cmd;
mod cfb_cmd;
mod chacha20_cmd;
mod chacha20_poly1305_cmd;
mod ctr_cmd;
mod ecb_cmd;
mod ecdsa_cmd;
mod encoders_cmd;
mod gcm_cmd;
mod helpers;
mod hkdf_cmd;
mod kw_cmd;
mod mac_cmd;
mod mldsa_cmd;
mod mlkem_cmd;
mod rng_cmd;
mod sha2_cmd;
mod sha3_cmd;
mod sm2_cmd;
mod sm3_cmd;

use crate::ecdsa_cmd::ECDSAAction;
use crate::hkdf_cmd::HKDFVariant;
use crate::mac_cmd::HMACVariant;
use crate::mldsa_cmd::{MLDSAAction, PreHashAlg};
use crate::rng_cmd::DrbgHash;
use crate::sha2_cmd::SHA2Variant;
use crate::sha3_cmd::{SHA3Variant, Strength};
use crate::sm2_cmd::SM2Action;
use bouncycastle::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle::camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};
use bouncycastle::sm4::hazmat::SM4Internal;
use clap::{Parser, Subcommand};
use helpers::block_mode_helpers::CipherDirection;

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

    /// Camellia-128 Key Wrap (RFC 3657 `id-camellia128-wrap`; NIST SP 800-38F Sec 6.2 over the
    /// Camellia permutation): `-d encrypt` wraps stdin to stdout, `-d decrypt` unwraps it.
    ///
    /// The same command as `aes128-kw` over Camellia: see it for the input-length rules, the
    /// absence of an IV, the authenticated `decrypt` and the non-streaming note. RFC 3657 defines
    /// no padded form, so there is no `camellia*-kwp`.
    CAMELLIA128_KW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte Camellia key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte Camellia key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Camellia-192 Key Wrap (RFC 3657 `id-camellia192-wrap`). See `camellia128-kw`; only the key
    /// length differs.
    CAMELLIA192_KW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte Camellia key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte Camellia key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Camellia-256 Key Wrap (RFC 3657 `id-camellia256-wrap`). See `camellia128-kw`; only the key
    /// length differs.
    CAMELLIA256_KW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte Camellia key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte Camellia key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ARIA-128 Key Wrap (RFC 5794 Appendix B `id-aria128-kw`; NIST SP 800-38F
    /// Sec 6.2 over the ARIA permutation): `-d encrypt` wraps stdin to stdout, `-d decrypt`
    /// unwraps it.
    ///
    /// The same command as `aes128-kw` over ARIA: see it for the input-length rules, the
    /// absence of an IV, the authenticated `decrypt` and the non-streaming note.
    ARIA128_KW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte ARIA key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte ARIA key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ARIA-192 Key Wrap (RFC 5794 Appendix B `id-aria192-kw`). See `aria128-kw`;
    /// only the key length differs.
    ARIA192_KW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte ARIA key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte ARIA key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ARIA-256 Key Wrap (RFC 5794 Appendix B `id-aria256-kw`). See `aria128-kw`;
    /// only the key length differs.
    ARIA256_KW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte ARIA key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte ARIA key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ARIA-128 Key Wrap with Padding (RFC 5794 Appendix B `id-aria128-kwp`; NIST SP 800-38F
    /// Sec 6.3 over the ARIA permutation): `-d encrypt` wraps stdin to stdout, `-d decrypt`
    /// unwraps it.
    ///
    /// The same command as `aes128-kwp` over ARIA: see it for the input-length rules, the
    /// absence of an IV, the authenticated `decrypt` and the non-streaming note.
    ARIA128_KWP {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte ARIA key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte ARIA key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ARIA-192 Key Wrap with Padding (RFC 5794 Appendix B `id-aria192-kwp`). See `aria128-kwp`;
    /// only the key length differs.
    ARIA192_KWP {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte ARIA key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte ARIA key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ARIA-256 Key Wrap with Padding (RFC 5794 Appendix B `id-aria256-kwp`). See `aria128-kwp`;
    /// only the key length differs.
    ARIA256_KWP {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte ARIA key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte ARIA key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// SM4 Key Wrap (GM/T 0006 `sms4_wrap`; NIST SP 800-38F Sec 6.2 over the SM4 permutation):
    /// `-d encrypt` wraps stdin to stdout, `-d decrypt` unwraps it.
    ///
    /// The same command as `aes128-kw` over SM4: see it for the input-length rules, the absence
    /// of an IV, the authenticated `decrypt` and the non-streaming note.
    SM4_KW {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte SM4 key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte SM4 key-encryption key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// SM4 Key Wrap with Padding (GM/T 0006 `sms4_wrap_pad`; NIST SP 800-38F Sec 6.3 over the SM4
    /// permutation): `-d encrypt` wraps stdin to stdout, `-d decrypt` unwraps it.
    ///
    /// The same command as `aes128-kwp` over SM4: see it and `sm4-kw`.
    SM4_KWP {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte SM4 key-encryption key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte SM4 key-encryption key (raw bytes; hex with --hex-input).
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

    /// ML-KEM-512 with the shared secret derived through HKDF-SHA256 (MLKEM512-HKDF-SHA256):
    /// encaps and decaps with mlkem512 keys, the output being
    /// HKDF-SHA256(salt, K, info) over the ML-KEM secret K, one hash output long. Keys are made
    /// with the mlkem512 subcommand.
    MLKEM512_HKDF_SHA256 {
        action: mlkem_cmd::MLKEMHkdfAction,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for decaps
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for encaps
        pkfile: Option<String>,

        #[arg(long)]
        /// The ciphertext value file (raw bytes; hex with --hex-input) either for encaps to output to, or for decaps to read from.
        ctfile: Option<String>,

        /// The HKDF salt (RFC 5869 Section 2.2, a non-secret random value) in hex. Optional:
        /// absent, HKDF uses a string of HashLen zeros.
        #[arg(long)]
        salt: Option<String>,

        /// A file containing the HKDF salt in binary.
        /// If both salt and salt_file options are provided, the file will be used.
        #[arg(short, long)]
        salt_file: Option<String>,

        /// The HKDF `info` input (RFC 5869 Section 2.3) in hex. Optional; defaults to empty.
        #[arg(long)]
        additional_input: Option<String>,

        /// A file containing the HKDF `info` input in binary. Optional; defaults to empty.
        /// If both additional_input and additional_input_file options are provided, the file will be used.
        #[arg(short, long)]
        additional_input_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ML-KEM-768 with the shared secret derived through HKDF-SHA512 (MLKEM768-HKDF-SHA512):
    /// encaps and decaps with mlkem768 keys, the output being
    /// HKDF-SHA512(salt, K, info) over the ML-KEM secret K, one hash output long. Keys are made
    /// with the mlkem768 subcommand.
    MLKEM768_HKDF_SHA512 {
        action: mlkem_cmd::MLKEMHkdfAction,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for decaps
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for encaps
        pkfile: Option<String>,

        #[arg(long)]
        /// The ciphertext value file (raw bytes; hex with --hex-input) either for encaps to output to, or for decaps to read from.
        ctfile: Option<String>,

        /// The HKDF salt (RFC 5869 Section 2.2, a non-secret random value) in hex. Optional:
        /// absent, HKDF uses a string of HashLen zeros.
        #[arg(long)]
        salt: Option<String>,

        /// A file containing the HKDF salt in binary.
        /// If both salt and salt_file options are provided, the file will be used.
        #[arg(short, long)]
        salt_file: Option<String>,

        /// The HKDF `info` input (RFC 5869 Section 2.3) in hex. Optional; defaults to empty.
        #[arg(long)]
        additional_input: Option<String>,

        /// A file containing the HKDF `info` input in binary. Optional; defaults to empty.
        /// If both additional_input and additional_input_file options are provided, the file will be used.
        #[arg(short, long)]
        additional_input_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ML-KEM-1024 with the shared secret derived through HKDF-SHA512 (MLKEM1024-HKDF-SHA512):
    /// encaps and decaps with mlkem1024 keys, the output being
    /// HKDF-SHA512(salt, K, info) over the ML-KEM secret K, one hash output long. Keys are made
    /// with the mlkem1024 subcommand.
    MLKEM1024_HKDF_SHA512 {
        action: mlkem_cmd::MLKEMHkdfAction,

        #[arg(long)]
        /// The private key file (raw bytes; hex with --hex-input) for decaps
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (raw bytes; hex with --hex-input) for encaps
        pkfile: Option<String>,

        #[arg(long)]
        /// The ciphertext value file (raw bytes; hex with --hex-input) either for encaps to output to, or for decaps to read from.
        ctfile: Option<String>,

        /// The HKDF salt (RFC 5869 Section 2.2, a non-secret random value) in hex. Optional:
        /// absent, HKDF uses a string of HashLen zeros.
        #[arg(long)]
        salt: Option<String>,

        /// A file containing the HKDF salt in binary.
        /// If both salt and salt_file options are provided, the file will be used.
        #[arg(short, long)]
        salt_file: Option<String>,

        /// The HKDF `info` input (RFC 5869 Section 2.3) in hex. Optional; defaults to empty.
        #[arg(long)]
        additional_input: Option<String>,

        /// A file containing the HKDF `info` input in binary. Optional; defaults to empty.
        /// If both additional_input and additional_input_file options are provided, the file will be used.
        #[arg(short, long)]
        additional_input_file: Option<String>,

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

    /// Camellia-128 in CBC mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.2 mode) with PKCS7
    /// padding, streaming stdin to stdout.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input, so the two
    /// compose directly in a pipeline. With `--iv` (hex) or `--iv-file` (raw bytes), the IV is
    /// supplied instead: `encrypt` uses it and writes ONLY the ciphertext, and `decrypt` reads
    /// ONLY ciphertext from stdin.
    ///
    /// Input may be any length: it is padded with PKCS7 to a whole number of 16-byte blocks.
    ///
    /// See `aes128-cbc` for the full IV convention, the padding rule and the warnings; the key
    /// and block are both 16 bytes, as for AES-128.
    CAMELLIA128_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte Camellia key (raw bytes; hex with --hex-input).
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
    /// Camellia-192 in CBC mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.2 mode) with PKCS7
    /// padding, streaming stdin to stdout.
    ///
    /// See `camellia128-cbc` for the IV convention, the padding rule and the warnings; only the
    /// key length differs.
    CAMELLIA192_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte Camellia key (raw bytes; hex with --hex-input).
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
    /// Camellia-256 in CBC mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.2 mode) with PKCS7
    /// padding, streaming stdin to stdout.
    ///
    /// See `camellia128-cbc` for the IV convention, the padding rule and the warnings; only the
    /// key length differs.
    CAMELLIA256_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte Camellia key (raw bytes; hex with --hex-input).
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
    /// Camellia-128 in CCM mode (NIST SP 800-38C): authenticated encryption of stdin to stdout.
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
    CAMELLIA128_CCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte Camellia key (raw bytes; hex with --hex-input).
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

        /// A file containing the associated data (raw bytes; hex with --hex-input). If both aad and
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

    /// Camellia-128 in CFB128 mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.3 mode),
    /// streaming stdin to stdout.
    ///
    /// The segment size is the full block, i.e. CFB128. The 8-bit variant is a different,
    /// non-interoperable mode; use `camellia128-cfb8` for that.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input. With `--iv`
    /// (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead and only ciphertext is written
    /// or read. Input may be ANY length: nothing is padded.
    ///
    /// See `aes128-cfb` for the full IV convention, input-length rule and warnings; the key and
    /// block are both 16 bytes, as for AES-128.
    CAMELLIA128_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte Camellia key (raw bytes; hex with --hex-input).
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
    /// Camellia-192 in CCM mode (NIST SP 800-38C), authenticated encryption of stdin to stdout.
    ///
    /// See `aes128-ccm` for the nonce convention, the length rules, the non-streaming note and the
    /// warnings; only the key length differs.
    CAMELLIA192_CCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte Camellia key (raw bytes; hex with --hex-input).
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

        /// A file containing the associated data (raw bytes; hex with --hex-input). If both aad and
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

    /// Camellia-192 in CFB128 mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.3 mode),
    /// streaming stdin to stdout.
    ///
    /// See `camellia128-cfb` for the IV convention, input-length rule and warnings; only the key
    /// length differs.
    CAMELLIA192_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte Camellia key (raw bytes; hex with --hex-input).
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
    /// Camellia-256 in CCM mode (NIST SP 800-38C), authenticated encryption of stdin to stdout.
    ///
    /// See `aes128-ccm` for the nonce convention, the length rules, the non-streaming note and the
    /// warnings; only the key length differs.
    CAMELLIA256_CCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte Camellia key (raw bytes; hex with --hex-input).
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

        /// A file containing the associated data (raw bytes; hex with --hex-input). If both aad and
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

    /// Camellia-256 in CFB128 mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.3 mode),
    /// streaming stdin to stdout.
    ///
    /// See `camellia128-cfb` for the IV convention, input-length rule and warnings; only the key
    /// length differs.
    CAMELLIA256_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte Camellia key (raw bytes; hex with --hex-input).
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
    /// Camellia-128 in CFB8 mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.3 mode, s = 8),
    /// streaming stdin to stdout.
    ///
    /// The segment size is one byte. This is a DIFFERENT, NON-INTEROPERABLE mode from the CFB128 of
    /// `camellia128-cfb`: the two ciphertexts agree only on their first byte. It also costs one
    /// Camellia call per byte, sixteen times the work, so prefer `camellia128-cfb` unless a
    /// byte-granular self-synchronising stream is required or the format demands CFB8.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input. With `--iv`
    /// (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead and only ciphertext is written
    /// or read. Input may be ANY length: nothing is padded.
    ///
    /// See `aes128-cfb8` for the full IV convention, input-length rule and warnings; the key and
    /// block are both 16 bytes, as for AES-128.
    CAMELLIA128_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte Camellia key (raw bytes; hex with --hex-input).
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
    /// Camellia-192 in CFB8 mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.3 mode, s = 8),
    /// streaming stdin to stdout.
    ///
    /// See `camellia128-cfb8` for the IV convention, input-length rule and warnings; only the key
    /// length differs.
    CAMELLIA192_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte Camellia key (raw bytes; hex with --hex-input).
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
    /// Camellia-256 in CFB8 mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.3 mode, s = 8),
    /// streaming stdin to stdout.
    ///
    /// See `camellia128-cfb8` for the IV convention, input-length rule and warnings; only the key
    /// length differs.
    CAMELLIA256_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte Camellia key (raw bytes; hex with --hex-input).
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
    /// Camellia-128 in CTR mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.5 mode), streaming
    /// stdin to stdout.
    ///
    /// The counter block is a 12-byte nonce followed by a 4-byte counter starting at zero, so one
    /// message can be up to 2^32 blocks (64 GiB); past that the command errors rather than
    /// repeating keystream. On `encrypt` the nonce is written as the FIRST 12 BYTES of the output
    /// and on `decrypt` it is read back from there -- 12, not the 16 the other modes write. With
    /// `--iv` (hex) or `--iv-file` (raw bytes), the 12-byte nonce is supplied instead and only
    /// ciphertext is written or read; it MUST then be unique per message under one key. This is
    /// SP 800-38A Appendix B.2's construction, not RFC 5528's, so ciphertexts do not interoperate
    /// with an RFC 5528 implementation.
    ///
    /// See `aes128-ctr` for the full nonce convention, input-length rule and warnings, including
    /// why a repeated nonce is fatal and why CTR is the most malleable mode here.
    CAMELLIA128_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte Camellia key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce, as raw bytes exactly as they are (no hex
        /// decoding). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Camellia-128 in GCM (NIST SP 800-38D), streaming stdin to stdout.
    ///
    /// AUTHENTICATED, unlike the other Camellia modes here: tampering with the ciphertext, the AAD or
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
    CAMELLIA128_GCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte Camellia key (raw bytes; hex with --hex-input).
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

        /// A file containing the additional authenticated data (raw bytes; hex with --hex-input).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },
    /// Camellia-192 in CTR mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.5 mode), streaming
    /// stdin to stdout.
    ///
    /// See `camellia128-ctr` for the nonce convention, input-length rule and warnings; only the key
    /// length differs.
    CAMELLIA192_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte Camellia key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce, as raw bytes exactly as they are (no hex
        /// decoding). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Camellia-192 in GCM (NIST SP 800-38D), streaming stdin to stdout.
    ///
    /// See `aes128-gcm` for the IV/tag framing, the AAD flags and the warnings; only the key
    /// length differs.
    CAMELLIA192_GCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte Camellia key (raw bytes; hex with --hex-input).
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

        /// A file containing the additional authenticated data (raw bytes; hex with --hex-input).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },
    /// Camellia-256 in CTR mode (RFC 3713 block cipher; NIST SP 800-38A Sec 6.5 mode), streaming
    /// stdin to stdout.
    ///
    /// See `camellia128-ctr` for the nonce convention, input-length rule and warnings; only the key
    /// length differs.
    CAMELLIA256_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte Camellia key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce, as raw bytes exactly as they are (no hex
        /// decoding). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Camellia-256 in GCM (NIST SP 800-38D), streaming stdin to stdout.
    ///
    /// See `aes128-gcm` for the IV/tag framing, the AAD flags and the warnings; only the key
    /// length differs.
    CAMELLIA256_GCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte Camellia key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte Camellia key (raw bytes; hex with --hex-input).
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

        /// A file containing the additional authenticated data (raw bytes; hex with --hex-input).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ARIA-128 in CBC mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.2 mode) with PKCS7
    /// padding, streaming stdin to stdout.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input, so the two
    /// compose directly in a pipeline. With `--iv` (hex) or `--iv-file` (raw bytes), the IV is
    /// supplied instead: `encrypt` uses it and writes ONLY the ciphertext, and `decrypt` reads
    /// ONLY ciphertext from stdin.
    ///
    /// Input may be any length: it is padded with PKCS7 to a whole number of 16-byte blocks.
    ///
    /// See `aes128-cbc` for the full IV convention, the padding rule and the warnings; the key
    /// and block are both 16 bytes, as for AES-128.
    ARIA128_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte ARIA key (raw bytes; hex with --hex-input).
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
    /// ARIA-192 in CBC mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.2 mode) with PKCS7
    /// padding, streaming stdin to stdout.
    ///
    /// See `aria128-cbc` for the IV convention, the padding rule and the warnings; only the
    /// key length differs.
    ARIA192_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte ARIA key (raw bytes; hex with --hex-input).
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
    /// ARIA-256 in CBC mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.2 mode) with PKCS7
    /// padding, streaming stdin to stdout.
    ///
    /// See `aria128-cbc` for the IV convention, the padding rule and the warnings; only the
    /// key length differs.
    ARIA256_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte ARIA key (raw bytes; hex with --hex-input).
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
    /// ARIA-128 in CCM mode (NIST SP 800-38C): authenticated encryption of stdin to stdout.
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
    ARIA128_CCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte ARIA key (raw bytes; hex with --hex-input).
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

        /// A file containing the associated data (raw bytes; hex with --hex-input). If both aad and
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

    /// ARIA-128 in CFB128 mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.3 mode), streaming
    /// stdin to stdout.
    ///
    /// The segment size is the full block, i.e. CFB128. The 8-bit variant is a different,
    /// non-interoperable mode; use `aria128-cfb8` for that.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input. With `--iv`
    /// (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead and only ciphertext is written
    /// or read. Input may be ANY length: nothing is padded.
    ///
    /// See `aes128-cfb` for the full IV convention, input-length rule and warnings; the key and
    /// block are both 16 bytes, as for AES-128.
    ARIA128_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte ARIA key (raw bytes; hex with --hex-input).
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
    /// ARIA-192 in CCM mode (NIST SP 800-38C), authenticated encryption of stdin to stdout.
    ///
    /// See `aes128-ccm` for the nonce convention, the length rules, the non-streaming note and the
    /// warnings; only the key length differs.
    ARIA192_CCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte ARIA key (raw bytes; hex with --hex-input).
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

        /// A file containing the associated data (raw bytes; hex with --hex-input). If both aad and
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

    /// ARIA-192 in CFB128 mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.3 mode), streaming
    /// stdin to stdout.
    ///
    /// See `aria128-cfb` for the IV convention, input-length rule and warnings; only the key length
    /// differs.
    ARIA192_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte ARIA key (raw bytes; hex with --hex-input).
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
    /// ARIA-256 in CCM mode (NIST SP 800-38C), authenticated encryption of stdin to stdout.
    ///
    /// See `aes128-ccm` for the nonce convention, the length rules, the non-streaming note and the
    /// warnings; only the key length differs.
    ARIA256_CCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte ARIA key (raw bytes; hex with --hex-input).
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

        /// A file containing the associated data (raw bytes; hex with --hex-input). If both aad and
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

    /// ARIA-256 in CFB128 mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.3 mode), streaming
    /// stdin to stdout.
    ///
    /// See `aria128-cfb` for the IV convention, input-length rule and warnings; only the key length
    /// differs.
    ARIA256_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte ARIA key (raw bytes; hex with --hex-input).
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
    /// ARIA-128 in CFB8 mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.3 mode, s = 8),
    /// streaming stdin to stdout.
    ///
    /// The segment size is one byte. This is a DIFFERENT, NON-INTEROPERABLE mode from the CFB128 of
    /// `aria128-cfb`: the two ciphertexts agree only on their first byte. It also costs one ARIA
    /// call per byte, sixteen times the work, so prefer `aria128-cfb` unless a byte-granular
    /// self-synchronising stream is required or the format demands CFB8.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input. With `--iv`
    /// (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead and only ciphertext is written
    /// or read. Input may be ANY length: nothing is padded.
    ///
    /// See `aes128-cfb8` for the full IV convention, input-length rule and warnings; the key and
    /// block are both 16 bytes, as for AES-128.
    ARIA128_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte ARIA key (raw bytes; hex with --hex-input).
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
    /// ARIA-192 in CFB8 mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.3 mode, s = 8),
    /// streaming stdin to stdout.
    ///
    /// See `aria128-cfb8` for the IV convention, input-length rule and warnings; only the key
    /// length differs.
    ARIA192_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte ARIA key (raw bytes; hex with --hex-input).
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
    /// ARIA-256 in CFB8 mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.3 mode, s = 8),
    /// streaming stdin to stdout.
    ///
    /// See `aria128-cfb8` for the IV convention, input-length rule and warnings; only the key
    /// length differs.
    ARIA256_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte ARIA key (raw bytes; hex with --hex-input).
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
    /// ARIA-128 in CTR mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.5 mode), streaming stdin
    /// to stdout.
    ///
    /// The counter block is a 12-byte nonce followed by a 4-byte counter starting at zero, so one
    /// message can be up to 2^32 blocks (64 GiB); past that the command errors rather than
    /// repeating keystream. On `encrypt` the nonce is written as the FIRST 12 BYTES of the output
    /// and on `decrypt` it is read back from there -- 12, not the 16 the other modes write. With
    /// `--iv` (hex) or `--iv-file` (raw bytes), the nonce is supplied instead and only ciphertext
    /// is written or read; its uniqueness under the key is then the caller's to keep.
    ///
    /// See `aes128-ctr` for the full nonce convention, input-length rule and warnings, including
    /// why a repeated nonce is fatal and why CTR is the most malleable mode here.
    ARIA128_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte ARIA key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes no nonce
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce, as raw bytes exactly as they are (no hex
        /// decoding). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ARIA-128 in GCM (NIST SP 800-38D), streaming stdin to stdout.
    ///
    /// AUTHENTICATED, unlike the other ARIA modes here: tampering with the ciphertext, the AAD or
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
    ARIA128_GCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte ARIA key (raw bytes; hex with --hex-input).
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

        /// A file containing the additional authenticated data (raw bytes; hex with --hex-input).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },
    /// ARIA-192 in CTR mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.5 mode), streaming stdin
    /// to stdout.
    ///
    /// See `aria128-ctr` for the nonce convention, input-length rule and warnings; only the key
    /// length differs.
    ARIA192_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte ARIA key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes no nonce
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce, as raw bytes exactly as they are (no hex
        /// decoding). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ARIA-192 in GCM (NIST SP 800-38D), streaming stdin to stdout.
    ///
    /// See `aes128-gcm` for the IV/tag framing, the AAD flags and the warnings; only the key
    /// length differs.
    ARIA192_GCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 24-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte ARIA key (raw bytes; hex with --hex-input).
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

        /// A file containing the additional authenticated data (raw bytes; hex with --hex-input).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },
    /// ARIA-256 in CTR mode (RFC 5794 block cipher; NIST SP 800-38A Sec 6.5 mode), streaming stdin
    /// to stdout.
    ///
    /// See `aria128-ctr` for the nonce convention, input-length rule and warnings; only the key
    /// length differs.
    ARIA256_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte ARIA key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes no nonce
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce, as raw bytes exactly as they are (no hex
        /// decoding). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// ARIA-256 in GCM (NIST SP 800-38D), streaming stdin to stdout.
    ///
    /// See `aes128-gcm` for the IV/tag framing, the AAD flags and the warnings; only the key
    /// length differs.
    ARIA256_GCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 32-byte ARIA key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte ARIA key (raw bytes; hex with --hex-input).
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

        /// A file containing the additional authenticated data (raw bytes; hex with --hex-input).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// SM4 in CBC mode (GB/T 32907-2016 block cipher; NIST SP 800-38A Sec 6.2 mode) with PKCS7
    /// padding, streaming stdin to stdout.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input, so the two
    /// compose directly in a pipeline. With `--iv` (hex) or `--iv-file` (raw bytes), the IV is
    /// supplied instead: `encrypt` uses it and writes ONLY the ciphertext, and `decrypt` reads
    /// ONLY ciphertext from stdin.
    ///
    /// Input may be any length: it is padded with PKCS7 to a whole number of 16-byte blocks.
    ///
    /// See `aes128-cbc` for the full IV convention, the padding rule and the warnings; the key
    /// and block are both 16 bytes, as for AES-128.
    SM4_CBC {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte SM4 key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte SM4 key (raw bytes; hex with --hex-input).
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

    /// SM4 in CCM mode (NIST SP 800-38C): authenticated encryption of stdin to stdout.
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
    SM4_CCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte SM4 key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte SM4 key (raw bytes; hex with --hex-input).
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

        /// A file containing the associated data (raw bytes; hex with --hex-input). If both aad and
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

    /// SM4 in CFB128 mode (GB/T 32907-2016 block cipher; NIST SP 800-38A Sec 6.3 mode), streaming
    /// stdin to stdout.
    ///
    /// The segment size is the full block: draft-ribose-cfrg-sm4-10 calls this SM4-CFB-128. Its
    /// 8-bit variant is a different, non-interoperable mode; use `sm4-cfb8` for that.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input. With `--iv`
    /// (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead and only ciphertext is written
    /// or read. Input may be ANY length: nothing is padded.
    ///
    /// See `aes128-cfb` for the full IV convention, input-length rule and warnings; the key and
    /// block are both 16 bytes, as for AES-128.
    SM4_CFB {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte SM4 key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte SM4 key (raw bytes; hex with --hex-input).
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

    /// SM4 in CFB8 mode (GB/T 32907-2016 block cipher; NIST SP 800-38A Sec 6.3 mode, s = 8),
    /// streaming stdin to stdout.
    ///
    /// The segment size is one byte. This is a DIFFERENT, NON-INTEROPERABLE mode from the CFB128 of
    /// `sm4-cfb`: the two ciphertexts agree only on their first byte. It also costs one SM4 call
    /// per byte, sixteen times the work of `sm4-cfb`, so prefer that unless a byte-granular
    /// self-synchronising stream is required or the format demands CFB8.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input. With `--iv`
    /// (hex) or `--iv-file` (raw bytes; hex with --hex-input), the IV is supplied instead and only ciphertext is written
    /// or read. Input may be ANY length: nothing is padded.
    ///
    /// See `aes128-cfb8` for the full IV convention, input-length rule and warnings; the key and
    /// block are both 16 bytes, as for AES-128.
    SM4_CFB8 {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte SM4 key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte SM4 key (raw bytes; hex with --hex-input).
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

    /// SM4 in CTR mode (GB/T 32907-2016 block cipher; NIST SP 800-38A Sec 6.5 mode), streaming
    /// stdin to stdout.
    ///
    /// The counter block is a 12-byte nonce followed by a 4-byte counter starting at zero, so one
    /// message can be up to 2^32 blocks (64 GiB); past that the command errors rather than
    /// repeating keystream. On `encrypt` the nonce is written as the FIRST 12 BYTES of the output
    /// and on `decrypt` it is read back from there -- 12, not the 16 the other modes write. With
    /// `--iv` (hex) or `--iv-file` (raw bytes), the 12-byte nonce is supplied instead and only
    /// ciphertext is written or read; it MUST then be unique per message under one key.
    ///
    /// See `aes128-ctr` for the full nonce convention, input-length rule and warnings, including
    /// why a repeated nonce is fatal and why CTR is the most malleable mode here; the key and
    /// block are both 16 bytes, as for AES-128.
    SM4_CTR {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte SM4 key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte SM4 key (raw bytes; hex with --hex-input).
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// The 12-byte nonce in hex. Supplied instead of generated: `encrypt` then writes none
        /// and `decrypt` reads none. See the nonce paragraph above.
        #[arg(long)]
        iv: Option<String>,

        /// A file containing the 12-byte nonce, as raw bytes exactly as they are (no hex
        /// decoding). If both iv and iv_file options are provided, the file will be used.
        #[arg(long)]
        iv_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// SM4 in GCM (GB/T 32907-2016 block cipher; NIST SP 800-38D mode; RFC 8998 Sec 3.5.1's
    /// AEAD_SM4_GCM), streaming stdin to stdout.
    ///
    /// AUTHENTICATED, unlike the other SM4 modes here: tampering with the ciphertext, the AAD or
    /// the IV is detected rather than merely producing wrong plaintext. The framing is
    /// `aes128-gcm`'s: on `encrypt` a fresh 12-byte IV is written first, the ciphertext follows
    /// and the 16-byte tag comes last; `decrypt` reads the same layout back and checks the tag
    /// once input is exhausted. With `--iv` / `--iv-file` the IV is supplied and not written or
    /// read, and MUST then be unique per message under one key. `--aad` (hex) or `--aad-file`
    /// (raw bytes) supply the additional authenticated data; if neither is given, AAD is empty.
    ///
    /// See `aes128-gcm` for the full contract and the warnings, including that on `decrypt` a tag
    /// failure may be reported only after plaintext has already been written to stdout, so a
    /// script MUST check the exit code; the key and block are both 16 bytes, as for AES-128.
    SM4_GCM {
        #[arg(short, long)]
        direction: CipherDirection,

        /// The 16-byte SM4 key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte SM4 key (raw bytes; hex with --hex-input).
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

        /// A file containing the additional authenticated data (raw bytes; hex with --hex-input).
        /// If both aad and aad_file options are provided, the file will be used.
        #[arg(long)]
        aad_file: Option<String>,

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
            cbc_cmd::cbc_cmd::<AES128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "AES-128",
            );
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
            ccm_cmd::ccm_cmd::<AES128Internal, 16>(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x, "AES-128",
            );
        }
        Some(Subcommands::AES128_CFB { direction, key, key_file, iv, iv_file, x }) => {
            cfb_cmd::cfb_cmd::<AES128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "AES-128",
            );
        }
        Some(Subcommands::AES128_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            cfb8_cmd::cfb8_cmd::<AES128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "AES-128",
            );
        }
        Some(Subcommands::AES128_CTR { direction, key, key_file, iv, iv_file, x }) => {
            ctr_cmd::ctr_cmd::<AES128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "AES-128",
            );
        }
        Some(Subcommands::AES128_ECB { direction, key, key_file, x }) => {
            ecb_cmd::ecb_cmd::<AES128Internal, 16>(direction, key, key_file, *x, "AES-128");
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
            gcm_cmd::gcm_cmd::<AES128Internal, 16>(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x, "AES-128",
            );
        }
        Some(Subcommands::AES192_CBC { direction, key, key_file, iv, iv_file, x }) => {
            cbc_cmd::cbc_cmd::<AES192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "AES-192",
            );
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
            ccm_cmd::ccm_cmd::<AES192Internal, 24>(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x, "AES-192",
            );
        }
        Some(Subcommands::AES192_CFB { direction, key, key_file, iv, iv_file, x }) => {
            cfb_cmd::cfb_cmd::<AES192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "AES-192",
            );
        }
        Some(Subcommands::AES192_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            cfb8_cmd::cfb8_cmd::<AES192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "AES-192",
            );
        }
        Some(Subcommands::AES192_CTR { direction, key, key_file, iv, iv_file, x }) => {
            ctr_cmd::ctr_cmd::<AES192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "AES-192",
            );
        }
        Some(Subcommands::AES192_ECB { direction, key, key_file, x }) => {
            ecb_cmd::ecb_cmd::<AES192Internal, 24>(direction, key, key_file, *x, "AES-192");
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
            gcm_cmd::gcm_cmd::<AES192Internal, 24>(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x, "AES-192",
            );
        }
        Some(Subcommands::AES256_CBC { direction, key, key_file, iv, iv_file, x }) => {
            cbc_cmd::cbc_cmd::<AES256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "AES-256",
            );
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
            ccm_cmd::ccm_cmd::<AES256Internal, 32>(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x, "AES-256",
            );
        }
        Some(Subcommands::AES256_CFB { direction, key, key_file, iv, iv_file, x }) => {
            cfb_cmd::cfb_cmd::<AES256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "AES-256",
            );
        }
        Some(Subcommands::AES256_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            cfb8_cmd::cfb8_cmd::<AES256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "AES-256",
            );
        }
        Some(Subcommands::AES256_CTR { direction, key, key_file, iv, iv_file, x }) => {
            ctr_cmd::ctr_cmd::<AES256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "AES-256",
            );
        }
        Some(Subcommands::AES256_ECB { direction, key, key_file, x }) => {
            ecb_cmd::ecb_cmd::<AES256Internal, 32>(direction, key, key_file, *x, "AES-256");
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
            gcm_cmd::gcm_cmd::<AES256Internal, 32>(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x, "AES-256",
            );
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
            kw_cmd::kw_cmd::<AES128Internal, 16>(direction, key, key_file, *x, "AES-128");
        }
        Some(Subcommands::AES192_KW { direction, key, key_file, x }) => {
            kw_cmd::kw_cmd::<AES192Internal, 24>(direction, key, key_file, *x, "AES-192");
        }
        Some(Subcommands::AES256_KW { direction, key, key_file, x }) => {
            kw_cmd::kw_cmd::<AES256Internal, 32>(direction, key, key_file, *x, "AES-256");
        }
        Some(Subcommands::AES128_KWP { direction, key, key_file, x }) => {
            kw_cmd::kwp_cmd::<AES128Internal, 16>(direction, key, key_file, *x, "AES-128");
        }
        Some(Subcommands::AES192_KWP { direction, key, key_file, x }) => {
            kw_cmd::kwp_cmd::<AES192Internal, 24>(direction, key, key_file, *x, "AES-192");
        }
        Some(Subcommands::AES256_KWP { direction, key, key_file, x }) => {
            kw_cmd::kwp_cmd::<AES256Internal, 32>(direction, key, key_file, *x, "AES-256");
        }
        Some(Subcommands::CAMELLIA128_KW { direction, key, key_file, x }) => {
            kw_cmd::kw_cmd::<Camellia128Internal, 16>(direction, key, key_file, *x, "Camellia-128");
        }
        Some(Subcommands::CAMELLIA192_KW { direction, key, key_file, x }) => {
            kw_cmd::kw_cmd::<Camellia192Internal, 24>(direction, key, key_file, *x, "Camellia-192");
        }
        Some(Subcommands::CAMELLIA256_KW { direction, key, key_file, x }) => {
            kw_cmd::kw_cmd::<Camellia256Internal, 32>(direction, key, key_file, *x, "Camellia-256");
        }
        Some(Subcommands::ARIA128_KW { direction, key, key_file, x }) => {
            kw_cmd::kw_cmd::<ARIA128Internal, 16>(direction, key, key_file, *x, "ARIA-128");
        }
        Some(Subcommands::ARIA192_KW { direction, key, key_file, x }) => {
            kw_cmd::kw_cmd::<ARIA192Internal, 24>(direction, key, key_file, *x, "ARIA-192");
        }
        Some(Subcommands::ARIA256_KW { direction, key, key_file, x }) => {
            kw_cmd::kw_cmd::<ARIA256Internal, 32>(direction, key, key_file, *x, "ARIA-256");
        }
        Some(Subcommands::ARIA128_KWP { direction, key, key_file, x }) => {
            kw_cmd::kwp_cmd::<ARIA128Internal, 16>(direction, key, key_file, *x, "ARIA-128");
        }
        Some(Subcommands::ARIA192_KWP { direction, key, key_file, x }) => {
            kw_cmd::kwp_cmd::<ARIA192Internal, 24>(direction, key, key_file, *x, "ARIA-192");
        }
        Some(Subcommands::ARIA256_KWP { direction, key, key_file, x }) => {
            kw_cmd::kwp_cmd::<ARIA256Internal, 32>(direction, key, key_file, *x, "ARIA-256");
        }
        Some(Subcommands::SM4_KW { direction, key, key_file, x }) => {
            kw_cmd::kw_cmd::<SM4Internal, 16>(direction, key, key_file, *x, "SM4");
        }
        Some(Subcommands::SM4_KWP { direction, key, key_file, x }) => {
            kw_cmd::kwp_cmd::<SM4Internal, 16>(direction, key, key_file, *x, "SM4");
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
        Some(Subcommands::MLKEM512_HKDF_SHA256 {
            action,
            skfile,
            pkfile,
            ctfile,
            salt,
            salt_file,
            additional_input,
            additional_input_file,
            x,
        }) => {
            mlkem_cmd::mlkem_hkdf_cmd(
                &mlkem_cmd::MLKEM512_SET,
                std::marker::PhantomData::<bouncycastle::sha2::SHA256>,
                action,
                skfile,
                pkfile,
                ctfile,
                salt,
                salt_file,
                additional_input,
                additional_input_file,
                *x,
            );
        }
        Some(Subcommands::MLKEM768_HKDF_SHA512 {
            action,
            skfile,
            pkfile,
            ctfile,
            salt,
            salt_file,
            additional_input,
            additional_input_file,
            x,
        }) => {
            mlkem_cmd::mlkem_hkdf_cmd(
                &mlkem_cmd::MLKEM768_SET,
                std::marker::PhantomData::<bouncycastle::sha2::SHA512>,
                action,
                skfile,
                pkfile,
                ctfile,
                salt,
                salt_file,
                additional_input,
                additional_input_file,
                *x,
            );
        }
        Some(Subcommands::MLKEM1024_HKDF_SHA512 {
            action,
            skfile,
            pkfile,
            ctfile,
            salt,
            salt_file,
            additional_input,
            additional_input_file,
            x,
        }) => {
            mlkem_cmd::mlkem_hkdf_cmd(
                &mlkem_cmd::MLKEM1024_SET,
                std::marker::PhantomData::<bouncycastle::sha2::SHA512>,
                action,
                skfile,
                pkfile,
                ctfile,
                salt,
                salt_file,
                additional_input,
                additional_input_file,
                *x,
            );
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
        Some(Subcommands::CAMELLIA128_CBC { direction, key, key_file, iv, iv_file, x }) => {
            cbc_cmd::cbc_cmd::<Camellia128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-128",
            );
        }
        Some(Subcommands::CAMELLIA192_CBC { direction, key, key_file, iv, iv_file, x }) => {
            cbc_cmd::cbc_cmd::<Camellia192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-192",
            );
        }
        Some(Subcommands::CAMELLIA256_CBC { direction, key, key_file, iv, iv_file, x }) => {
            cbc_cmd::cbc_cmd::<Camellia256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-256",
            );
        }
        Some(Subcommands::CAMELLIA128_CCM {
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
            ccm_cmd::ccm_cmd::<Camellia128Internal, 16>(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x,
                "Camellia-128",
            );
        }
        Some(Subcommands::CAMELLIA128_CFB { direction, key, key_file, iv, iv_file, x }) => {
            cfb_cmd::cfb_cmd::<Camellia128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-128",
            );
        }
        Some(Subcommands::CAMELLIA192_CCM {
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
            ccm_cmd::ccm_cmd::<Camellia192Internal, 24>(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x,
                "Camellia-192",
            );
        }
        Some(Subcommands::CAMELLIA192_CFB { direction, key, key_file, iv, iv_file, x }) => {
            cfb_cmd::cfb_cmd::<Camellia192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-192",
            );
        }
        Some(Subcommands::CAMELLIA256_CCM {
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
            ccm_cmd::ccm_cmd::<Camellia256Internal, 32>(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x,
                "Camellia-256",
            );
        }
        Some(Subcommands::CAMELLIA256_CFB { direction, key, key_file, iv, iv_file, x }) => {
            cfb_cmd::cfb_cmd::<Camellia256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-256",
            );
        }
        Some(Subcommands::CAMELLIA128_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            cfb8_cmd::cfb8_cmd::<Camellia128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-128",
            );
        }
        Some(Subcommands::CAMELLIA192_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            cfb8_cmd::cfb8_cmd::<Camellia192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-192",
            );
        }
        Some(Subcommands::CAMELLIA256_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            cfb8_cmd::cfb8_cmd::<Camellia256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-256",
            );
        }
        Some(Subcommands::CAMELLIA128_CTR { direction, key, key_file, iv, iv_file, x }) => {
            ctr_cmd::ctr_cmd::<Camellia128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-128",
            );
        }
        Some(Subcommands::CAMELLIA128_GCM {
            direction,
            key,
            key_file,
            iv,
            iv_file,
            aad,
            aad_file,
            x,
        }) => {
            gcm_cmd::gcm_cmd::<Camellia128Internal, 16>(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x, "Camellia-128",
            );
        }
        Some(Subcommands::CAMELLIA192_CTR { direction, key, key_file, iv, iv_file, x }) => {
            ctr_cmd::ctr_cmd::<Camellia192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-192",
            );
        }
        Some(Subcommands::CAMELLIA192_GCM {
            direction,
            key,
            key_file,
            iv,
            iv_file,
            aad,
            aad_file,
            x,
        }) => {
            gcm_cmd::gcm_cmd::<Camellia192Internal, 24>(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x, "Camellia-192",
            );
        }
        Some(Subcommands::CAMELLIA256_CTR { direction, key, key_file, iv, iv_file, x }) => {
            ctr_cmd::ctr_cmd::<Camellia256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "Camellia-256",
            );
        }
        Some(Subcommands::CAMELLIA256_GCM {
            direction,
            key,
            key_file,
            iv,
            iv_file,
            aad,
            aad_file,
            x,
        }) => {
            gcm_cmd::gcm_cmd::<Camellia256Internal, 32>(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x, "Camellia-256",
            );
        }
        Some(Subcommands::ARIA128_CBC { direction, key, key_file, iv, iv_file, x }) => {
            cbc_cmd::cbc_cmd::<ARIA128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-128",
            );
        }
        Some(Subcommands::ARIA192_CBC { direction, key, key_file, iv, iv_file, x }) => {
            cbc_cmd::cbc_cmd::<ARIA192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-192",
            );
        }
        Some(Subcommands::ARIA256_CBC { direction, key, key_file, iv, iv_file, x }) => {
            cbc_cmd::cbc_cmd::<ARIA256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-256",
            );
        }
        Some(Subcommands::ARIA128_CCM {
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
            ccm_cmd::ccm_cmd::<ARIA128Internal, 16>(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x,
                "ARIA-128",
            );
        }
        Some(Subcommands::ARIA128_CFB { direction, key, key_file, iv, iv_file, x }) => {
            cfb_cmd::cfb_cmd::<ARIA128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-128",
            );
        }
        Some(Subcommands::ARIA192_CCM {
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
            ccm_cmd::ccm_cmd::<ARIA192Internal, 24>(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x,
                "ARIA-192",
            );
        }
        Some(Subcommands::ARIA192_CFB { direction, key, key_file, iv, iv_file, x }) => {
            cfb_cmd::cfb_cmd::<ARIA192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-192",
            );
        }
        Some(Subcommands::ARIA256_CCM {
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
            ccm_cmd::ccm_cmd::<ARIA256Internal, 32>(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x,
                "ARIA-256",
            );
        }
        Some(Subcommands::ARIA256_CFB { direction, key, key_file, iv, iv_file, x }) => {
            cfb_cmd::cfb_cmd::<ARIA256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-256",
            );
        }
        Some(Subcommands::ARIA128_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            cfb8_cmd::cfb8_cmd::<ARIA128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-128",
            );
        }
        Some(Subcommands::ARIA192_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            cfb8_cmd::cfb8_cmd::<ARIA192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-192",
            );
        }
        Some(Subcommands::ARIA256_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            cfb8_cmd::cfb8_cmd::<ARIA256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-256",
            );
        }
        Some(Subcommands::ARIA128_CTR { direction, key, key_file, iv, iv_file, x }) => {
            ctr_cmd::ctr_cmd::<ARIA128Internal, 16>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-128",
            );
        }
        Some(Subcommands::ARIA128_GCM {
            direction,
            key,
            key_file,
            iv,
            iv_file,
            aad,
            aad_file,
            x,
        }) => {
            gcm_cmd::gcm_cmd::<ARIA128Internal, 16>(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x, "ARIA-128",
            );
        }
        Some(Subcommands::ARIA192_CTR { direction, key, key_file, iv, iv_file, x }) => {
            ctr_cmd::ctr_cmd::<ARIA192Internal, 24>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-192",
            );
        }
        Some(Subcommands::ARIA192_GCM {
            direction,
            key,
            key_file,
            iv,
            iv_file,
            aad,
            aad_file,
            x,
        }) => {
            gcm_cmd::gcm_cmd::<ARIA192Internal, 24>(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x, "ARIA-192",
            );
        }
        Some(Subcommands::ARIA256_CTR { direction, key, key_file, iv, iv_file, x }) => {
            ctr_cmd::ctr_cmd::<ARIA256Internal, 32>(
                direction, key, key_file, iv, iv_file, *x, "ARIA-256",
            );
        }
        Some(Subcommands::ARIA256_GCM {
            direction,
            key,
            key_file,
            iv,
            iv_file,
            aad,
            aad_file,
            x,
        }) => {
            gcm_cmd::gcm_cmd::<ARIA256Internal, 32>(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x, "ARIA-256",
            );
        }
        Some(Subcommands::SM4_CBC { direction, key, key_file, iv, iv_file, x }) => {
            cbc_cmd::cbc_cmd::<SM4Internal, 16>(direction, key, key_file, iv, iv_file, *x, "SM4");
        }
        Some(Subcommands::SM4_CCM {
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
            ccm_cmd::ccm_cmd::<SM4Internal, 16>(
                direction, key, key_file, nonce, nonce_file, aad, aad_file, *tag_len, *x, "SM4",
            );
        }
        Some(Subcommands::SM4_CFB { direction, key, key_file, iv, iv_file, x }) => {
            cfb_cmd::cfb_cmd::<SM4Internal, 16>(direction, key, key_file, iv, iv_file, *x, "SM4");
        }
        Some(Subcommands::SM4_CFB8 { direction, key, key_file, iv, iv_file, x }) => {
            cfb8_cmd::cfb8_cmd::<SM4Internal, 16>(direction, key, key_file, iv, iv_file, *x, "SM4");
        }
        Some(Subcommands::SM4_CTR { direction, key, key_file, iv, iv_file, x }) => {
            ctr_cmd::ctr_cmd::<SM4Internal, 16>(direction, key, key_file, iv, iv_file, *x, "SM4");
        }
        Some(Subcommands::SM4_GCM { direction, key, key_file, iv, iv_file, aad, aad_file, x }) => {
            gcm_cmd::gcm_cmd::<SM4Internal, 16>(
                direction, key, key_file, iv, iv_file, aad, aad_file, *x, "SM4",
            );
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
