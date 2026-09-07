mod aes_cbc_cmd;
mod aes_cfb8_cmd;
mod aes_cfb_cmd;
mod aes_ctr_cmd;
mod aes_ecb_cmd;
mod block_mode_cmd;
mod encoders_cmd;
mod helpers;
mod hkdf_cmd;
mod mac_cmd;
mod mldsa_cmd;
mod mlkem_cmd;
mod rng_cmd;
mod sha2_cmd;
mod sha3_cmd;
mod sm3_cmd;
mod stream_mode_cmd;

use crate::block_mode_cmd::BlockModeAction;
use crate::mac_cmd::HMACVariant;
use crate::mldsa_cmd::MLDSAAction;
use crate::sha2_cmd::SHA2Variant;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about=None, arg_required_else_help=true)]
struct Cli {
    #[command(subcommand)]
    subcommands: Option<Subcommands>,
}

#[allow(non_camel_case_types)]
#[derive(Subcommand)]
enum Subcommands {
    /// Encode binary data from stdin to base64.
    /// Supports streaming for low memory footprint and continuous processing from stdin to stdout.
    HexEncode,

    /// Decode base64 data from stdin to binary.
    /// Supports streaming for low memory footprint and continuous processing from stdin to stdout.
    HexDecode,

    /// Encode binary data from stdin to base64.
    /// Supports streaming for low memory footprint and continuous processing from stdin to stdout.
    Base64Encode,

    /// Decode base64 data from stdin to binary.
    /// Supports streaming for low memory footprint and continuous processing from stdin to stdout.
    Base64Decode,

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

    /// Perform SHA3-256 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA3_384 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SHA3-256 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SHA3_512 {
        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform SM3 of the content provided on stdin.
    /// Supports streaming update for low memory footprint.
    SM3 {
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
        /// Customization string.
        customization: Option<String>,

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
        /// Customization string.
        customization: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
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
        /// Customization string.
        customization: Option<String>,

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
        /// Customization string.
        customization: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Compute or verify a KMAC128 (NIST SP 800-185 Sec 4) over the content provided on stdin.
    /// The tag length and customization string are bound into the computation, so the verifier
    /// must use the same values.
    KMAC128 {
        /// Length of the tag in bytes.
        length: usize,

        #[arg(short = 's', long)]
        /// Customization string, domain-separating this use of KMAC from another.
        customization: Option<String>,

        #[arg(short, long)]
        /// The key, in hex.
        key: Option<String>,

        #[arg(long)]
        /// File containing the key, as raw bytes.
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
    KMAC256 {
        /// Length of the tag in bytes.
        length: usize,

        #[arg(short = 's', long)]
        /// Customization string, domain-separating this use of KMAC from another.
        customization: Option<String>,

        #[arg(short, long)]
        /// The key, in hex.
        key: Option<String>,

        #[arg(long)]
        /// File containing the key, as raw bytes.
        key_file: Option<String>,

        #[arg(short, long)]
        /// Verify against this tag (hex) instead of computing one.
        verify: Option<String>,

        #[arg(short)]
        /// Output the tag in hex format.
        x: bool,
    },

    /// Perform cSHAKE128 (NIST SP 800-185) of the content provided on stdin. Requires the output
    /// length in bytes. With no customization string this is exactly SHAKE128.
    /// Supports streaming update for low memory footprint.
    CSHAKE128 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 's', long)]
        /// Customization string. Two cSHAKEs with different customization strings produce
        /// unrelated output, so this domain-separates one use of the function from another.
        customization: Option<String>,

        #[arg(short = 'n', long)]
        /// Function-name string. Reserved by NIST for functions it defines (SP 800-185 Sec 3.4);
        /// use --customization for your own domain separation.
        function_name: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform cSHAKE256 (NIST SP 800-185) of the content provided on stdin. Requires the output
    /// length in bytes. With no customization string this is exactly SHAKE256.
    /// Supports streaming update for low memory footprint.
    CSHAKE256 {
        /// Length of the output in bytes.
        length: usize,

        #[arg(short = 's', long)]
        /// Customization string. See cshake128.
        customization: Option<String>,

        #[arg(short = 'n', long)]
        /// Function-name string, reserved by NIST. See cshake128.
        function_name: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
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

        /// A file containing the MAC key in binary.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// The command will output either 0 for success or -1 for verification failure.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
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

        /// A file containing the MAC key in binary.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// The command will output either 0 for success or -1 for verification failure.
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

        /// A file containing the MAC key in binary.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// The command will output either 0 for success or -1 for verification failure.
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

        /// A file containing the MAC key in binary.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// The command will output either 0 for success or -1 for verification failure.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
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

        /// A file containing the MAC key in binary.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        /// A MAC value to be verified.
        /// The command will output either 0 for success or -1 for verification failure.
        #[arg(short, long)]
        verify: Option<String>,

        #[arg(short)]
        /// Output the hashes in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA256 of the content provided on stdin.
    ///     HKDF.extract_and_expand(salt, ikm, additional_info, L)
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

        /// A file containing the salt value in binary.
        /// If both ikm and ikm_file options are provided, the file will be used.
        #[arg(short, long)]
        ikm_file: Option<String>,

        /// Additional input data in hex.
        #[arg(long)]
        additional_input: Option<String>,

        /// A file containing the additional input data in binary.
        /// If both additional_input and additional_input_file options are provided, the file will be used.
        #[arg(short, long)]
        additional_input_file: Option<String>,

        /// Length of output to produce, in bytes.
        #[arg(short, long)]
        len: usize,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Perform HMAC-SHA512 of the content provided on stdin.
    ///     HKDF.extract_and_expand(salt, ikm, additional_info, L)
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

        /// A file containing the salt value in binary.
        /// If both ikm and ikm_file options are provided, the file will be used.
        #[arg(short, long)]
        ikm_file: Option<String>,

        /// Additional input data in hex.
        #[arg(long)]
        additional_input: Option<String>,

        /// A file containing the additional input data in binary.
        /// If both additional_input and additional_input_file options are provided, the file will be used.
        #[arg(short, long)]
        additional_input_file: Option<String>,

        /// Length of output to produce, in bytes.
        #[arg(short, long)]
        len: usize,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// Generate cryptographically-secure random bytes, seeded from the operating system's entropy source (/dev/random or equivalent).
    /// Uses the library's default 256-bit secure RNG algorithm.
    RNG {
        /// Number of bytes to generate. If omitted, it will stream continuously until the process is terminated.
        #[arg(short, long)]
        len: Option<u32>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-128 in CBC mode (NIST SP 800-38A Sec 6.2), streaming stdin to stdout.
    ///
    /// On `encrypt`, a fresh unpredictable IV is generated and written as the FIRST 16 BYTES of
    /// the output; on `decrypt` it is read back from the first 16 bytes of the input, so the two
    /// compose directly in a pipeline. There is deliberately no `--iv` flag.
    ///
    /// Input must be a whole number of 16-byte blocks: CBC is defined only on whole blocks and
    /// these commands apply no padding, so unaligned input is rejected rather than padded.
    ///
    /// WARNING: CBC provides confidentiality only. It does not detect tampering, and neither the
    /// ciphertext nor the IV is authenticated. Do not decrypt data you have not authenticated
    /// separately.
    ///
    /// Note: in production uses, secrets should not be passed on the command-line because they get
    /// logged in shell history. Use the file-based input instead.
    AES128_CBC {
        action: BlockModeAction,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in CBC mode (NIST SP 800-38A Sec 6.2), streaming stdin to stdout.
    ///
    /// See `aes128-cbc` for the IV convention, block-alignment requirement and warnings; only the
    /// key length differs.
    AES192_CBC {
        action: BlockModeAction,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in CBC mode (NIST SP 800-38A Sec 6.2), streaming stdin to stdout.
    ///
    /// See `aes128-cbc` for the IV convention, block-alignment requirement and warnings; only the
    /// key length differs.
    AES256_CBC {
        action: BlockModeAction,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

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
    /// compose directly in a pipeline. There is deliberately no `--iv` flag.
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
        action: BlockModeAction,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in CFB128 mode (NIST SP 800-38A Sec 6.3), streaming stdin to stdout.
    ///
    /// See `aes128-cfb` for the IV convention, input-length rule and warnings; only the key length
    /// differs.
    AES192_CFB {
        action: BlockModeAction,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in CFB128 mode (NIST SP 800-38A Sec 6.3), streaming stdin to stdout.
    ///
    /// See `aes128-cfb` for the IV convention, input-length rule and warnings; only the key length
    /// differs.
    AES256_CFB {
        action: BlockModeAction,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

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
    /// compose directly in a pipeline. There is deliberately no `--iv` flag.
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
        action: BlockModeAction,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in CFB8 mode (NIST SP 800-38A Sec 6.3, s = 8), streaming stdin to stdout.
    ///
    /// See `aes128-cfb8` for the IV convention, input-length rule and warnings; only the key length
    /// differs.
    AES192_CFB8 {
        action: BlockModeAction,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in CFB8 mode (NIST SP 800-38A Sec 6.3, s = 8), streaming stdin to stdout.
    ///
    /// See `aes128-cfb8` for the IV convention, input-length rule and warnings; only the key length
    /// differs.
    AES256_CFB8 {
        action: BlockModeAction,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
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
    /// directly in a pipeline. Note that this is 12 bytes, not the 16 the other modes write. There
    /// is deliberately no `--iv` flag.
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
        action: BlockModeAction,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in CTR mode (NIST SP 800-38A Sec 6.5), streaming stdin to stdout.
    ///
    /// See `aes128-ctr` for the nonce convention, input-length rule and warnings; only the key
    /// length differs.
    AES192_CTR {
        action: BlockModeAction,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in CTR mode (NIST SP 800-38A Sec 6.5), streaming stdin to stdout.
    ///
    /// See `aes128-ctr` for the nonce convention, input-length rule and warnings; only the key
    /// length differs.
    AES256_CTR {
        action: BlockModeAction,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

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
        action: BlockModeAction,

        /// The 16-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 16-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-192 in ECB mode (NIST SP 800-38A Sec 6.1), streaming stdin to stdout.
    ///
    /// See `aes128-ecb` for the warning, the absence of an IV and the block-alignment requirement;
    /// only the key length differs.
    AES192_ECB {
        action: BlockModeAction,

        /// The 24-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 24-byte AES key, in binary or hex.
        /// If both key and key_file options are provided, the file will be used.
        #[arg(short, long)]
        key_file: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// AES-256 in ECB mode (NIST SP 800-38A Sec 6.1), streaming stdin to stdout.
    ///
    /// See `aes128-ecb` for the warning, the absence of an IV and the block-alignment requirement;
    /// only the key length differs.
    AES256_ECB {
        action: BlockModeAction,

        /// The 32-byte AES key in hex.
        /// The `key_file` option is preferred to avoid leaving key material in command history.
        #[arg(long)]
        key: Option<String>,

        /// A file containing the 32-byte AES key, in binary or hex.
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
        /// The private key file (in hex or binary) for decaps
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for encaps
        pkfile: Option<String>,

        #[arg(long)]
        /// The ciphertext value file (in hex or binary) either for encaps to output to, or for decaps to read from.
        ctfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The ML-KEM-768 key encapsulation algorithm.
    MLKEM768 {
        action: mlkem_cmd::MLKEMAction,

        #[arg(long)]
        /// The private key file (in hex or binary) for decaps
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for encaps
        pkfile: Option<String>,

        #[arg(long)]
        /// The ciphertext value file (in hex or binary) either for encaps to output to, or for decaps to read from.
        ctfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The ML-KEM-1024 key encapsulation algorithm.
    MLKEM1024 {
        action: mlkem_cmd::MLKEMAction,

        #[arg(long)]
        /// The private key file (in hex or binary) for decaps
        skfile: Option<String>,

        #[arg(long)]
        /// The public key file (in hex or binary) for encaps
        pkfile: Option<String>,

        #[arg(long)]
        /// The ciphertext value file (in hex or binary) either for encaps to output to, or for decaps to read from.
        ctfile: Option<String>,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },

    /// The ML-DSA-44 signature algorithm.
    MLDSA44 {
        action: MLDSAAction,

        #[arg(long)]
        /// The file containing context string (in hex) for signing or verifying
        ctxfile: Option<String>,

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

    /// The ML-DSA-65 signature algorithm.
    MLDSA65 {
        action: MLDSAAction,

        #[arg(long)]
        /// The file containing context string (in hex) for signing or verifying
        ctxfile: Option<String>,

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

    /// The ML-DSA-87 signature algorithm.
    MLDSA87 {
        action: MLDSAAction,

        #[arg(long)]
        /// The file containing context string (in hex) for signing or verifying
        ctxfile: Option<String>,

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

    /// The HashML-DSA-44 signature algorithm.
    HashMLDSA44 {
        action: MLDSAAction,

        #[arg(long)]
        /// The file containing context string (in hex) for signing or verifying
        ctxfile: Option<String>,

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

    /// The HashML-DSA-65 signature algorithm.
    HashMLDSA65 {
        action: MLDSAAction,

        #[arg(long)]
        /// The file containing context string (in hex) for signing or verifying
        ctxfile: Option<String>,

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

    /// The HashML-DSA87 signature algorithm.
    HashMLDSA87 {
        action: MLDSAAction,

        #[arg(long)]
        /// The file containing context string (in hex) for signing or verifying
        ctxfile: Option<String>,

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
}

fn main() {
    let cli = Cli::parse();

    match &cli.subcommands {
        Some(Subcommands::HexEncode) => {
            encoders_cmd::hex_encode_cmd();
        }
        Some(Subcommands::HexDecode) => {
            encoders_cmd::hex_decode_cmd();
        }
        Some(Subcommands::Base64Encode) => {
            encoders_cmd::base64_encode_cmd();
        }
        Some(Subcommands::Base64Decode) => {
            encoders_cmd::base64_decode_cmd();
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
        Some(Subcommands::SHA3_224 { x }) => {
            sha3_cmd::sha3_cmd(224, *x);
        }
        Some(Subcommands::SHA3_256 { x }) => {
            sha3_cmd::sha3_cmd(256, *x);
        }
        Some(Subcommands::SHA3_384 { x }) => {
            sha3_cmd::sha3_cmd(384, *x);
        }
        Some(Subcommands::SHA3_512 { x }) => {
            sha3_cmd::sha3_cmd(512, *x);
        }
        Some(Subcommands::SM3 { x }) => {
            sm3_cmd::sm3_cmd(*x);
        }
        Some(Subcommands::SHAKE128 { length, x }) => {
            sha3_cmd::shake_cmd(128, *length, *x);
        }
        Some(Subcommands::SHAKE256 { length, x }) => {
            sha3_cmd::shake_cmd(256, *length, *x);
        }
        Some(Subcommands::CSHAKE128 { length, customization, function_name, x }) => {
            sha3_cmd::cshake_cmd(128, *length, function_name, customization, *x);
        }
        Some(Subcommands::TUPLEHASH128 { length, elements, customization, x }) => {
            sha3_cmd::tuplehash_cmd(128, *length, elements, customization, *x);
        }
        Some(Subcommands::TUPLEHASH256 { length, elements, customization, x }) => {
            sha3_cmd::tuplehash_cmd(256, *length, elements, customization, *x);
        }
        Some(Subcommands::PARALLELHASH128 { length, block_size, customization, x }) => {
            sha3_cmd::parallelhash_cmd(128, *length, *block_size, customization, *x);
        }
        Some(Subcommands::PARALLELHASH256 { length, block_size, customization, x }) => {
            sha3_cmd::parallelhash_cmd(256, *length, *block_size, customization, *x);
        }
        Some(Subcommands::KMAC128 { length, customization, key, key_file, verify, x }) => {
            mac_cmd::kmac_cmd(128, *length, customization, key, key_file, verify, *x)
        }
        Some(Subcommands::KMAC256 { length, customization, key, key_file, verify, x }) => {
            mac_cmd::kmac_cmd(256, *length, customization, key, key_file, verify, *x)
        }
        Some(Subcommands::CSHAKE256 { length, customization, function_name, x }) => {
            sha3_cmd::cshake_cmd(256, *length, function_name, customization, *x);
        }
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
            "HKDF-SHA256", salt, salt_file, ikm, ikm_file, additional_input, additional_input_file,
            *len, *x,
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
            "HKDF-SHA512", salt, salt_file, ikm, ikm_file, additional_input, additional_input_file,
            *len, *x,
        ),
        Some(Subcommands::RNG { len, x }) => rng_cmd::rng_cmd(*len, *x),
        Some(Subcommands::AES128_CBC { action, key, key_file, x }) => {
            aes_cbc_cmd::aes128_cbc_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES192_CBC { action, key, key_file, x }) => {
            aes_cbc_cmd::aes192_cbc_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES256_CBC { action, key, key_file, x }) => {
            aes_cbc_cmd::aes256_cbc_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES128_CFB { action, key, key_file, x }) => {
            aes_cfb_cmd::aes128_cfb_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES192_CFB { action, key, key_file, x }) => {
            aes_cfb_cmd::aes192_cfb_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES256_CFB { action, key, key_file, x }) => {
            aes_cfb_cmd::aes256_cfb_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES128_CFB8 { action, key, key_file, x }) => {
            aes_cfb8_cmd::aes128_cfb8_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES192_CFB8 { action, key, key_file, x }) => {
            aes_cfb8_cmd::aes192_cfb8_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES256_CFB8 { action, key, key_file, x }) => {
            aes_cfb8_cmd::aes256_cfb8_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES128_CTR { action, key, key_file, x }) => {
            aes_ctr_cmd::aes128_ctr_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES192_CTR { action, key, key_file, x }) => {
            aes_ctr_cmd::aes192_ctr_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES256_CTR { action, key, key_file, x }) => {
            aes_ctr_cmd::aes256_ctr_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES128_ECB { action, key, key_file, x }) => {
            aes_ecb_cmd::aes128_ecb_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES192_ECB { action, key, key_file, x }) => {
            aes_ecb_cmd::aes192_ecb_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::AES256_ECB { action, key, key_file, x }) => {
            aes_ecb_cmd::aes256_ecb_cmd(action, key, key_file, *x);
        }
        Some(Subcommands::MLKEM512 { action, skfile, pkfile, ctfile, x }) => {
            mlkem_cmd::mlkem512_cmd(action, skfile, pkfile, ctfile, *x);
        }
        Some(Subcommands::MLKEM768 { action, skfile, pkfile, ctfile, x }) => {
            mlkem_cmd::mlkem768_cmd(action, skfile, pkfile, ctfile, *x);
        }
        Some(Subcommands::MLKEM1024 { action, skfile, pkfile, ctfile, x }) => {
            mlkem_cmd::mlkem1024_cmd(action, skfile, pkfile, ctfile, *x);
        }
        Some(Subcommands::MLDSA44 { action, ctxfile, skfile, pkfile, sigfile, x }) => {
            mldsa_cmd::mldsa44_cmd(action, ctxfile, skfile, pkfile, sigfile, *x);
        }
        Some(Subcommands::MLDSA65 { action, ctxfile, skfile, pkfile, sigfile, x }) => {
            mldsa_cmd::mldsa65_cmd(action, ctxfile, skfile, pkfile, sigfile, *x);
        }
        Some(Subcommands::MLDSA87 { action, ctxfile, skfile, pkfile, sigfile, x }) => {
            mldsa_cmd::mldsa87_cmd(action, ctxfile, skfile, pkfile, sigfile, *x);
        }
        Some(Subcommands::HashMLDSA44 { action, ctxfile, skfile, pkfile, sigfile, x }) => {
            mldsa_cmd::hash_mldsa44_sha512_cmd(action, ctxfile, skfile, pkfile, sigfile, *x);
        }
        Some(Subcommands::HashMLDSA65 { action, ctxfile, skfile, pkfile, sigfile, x }) => {
            mldsa_cmd::hash_mldsa65_sha512_cmd(action, ctxfile, skfile, pkfile, sigfile, *x);
        }
        Some(Subcommands::HashMLDSA87 { action, ctxfile, skfile, pkfile, sigfile, x }) => {
            mldsa_cmd::hash_mldsa87_sha512_cmd(action, ctxfile, skfile, pkfile, sigfile, *x);
        }
        None => {
            eprintln!("No command provided. See -h")
        }
    }
}
