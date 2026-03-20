mod sha3_cmd;
mod encoders_cmd;
mod sha2_cmd;
mod mac_cmd;
mod hkdf_cmd;
mod rng_cmd;
mod mldsa_cmd;

use clap::{Parser, Subcommand, ValueEnum};
use crate::mac_cmd::HMACVariant;

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

        #[arg(long)]
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

    /// The MLDSA44 signature algorithm.
    MLDSA44 {
        action: MLDSAAction,

        #[arg(short)]
        /// Output in hex format.
        x: bool,
    },
}

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum MLDSAAction {
    /// Generate and output a new private key
    Keygen,
    /// Generate and output a private key from a seed read from stdin
    KeygenFromSeed,
    /// Generate and output a new public key from a private key read from stdin
    PkFromSk,
    /// Sign a message read from stdin with a private key file and output the signature
    Sign,
    /// Verify a message read from stdin with a public key file and a signature file
    Verify,
}

fn main() {
    let cli = Cli::parse();

    match &cli.subcommands {
        Some(Subcommands::HexEncode) => { encoders_cmd::hex_encode_cmd(); }
        Some(Subcommands::HexDecode) => { encoders_cmd::hex_decode_cmd(); }
        Some(Subcommands::Base64Encode) => { encoders_cmd::base64_encode_cmd(); }
        Some(Subcommands::Base64Decode) => { encoders_cmd::base64_decode_cmd(); }
        Some(Subcommands::SHA224 { x}) => { sha2_cmd::sha2_cmd(224, *x); },
        Some(Subcommands::SHA256 { x}) => { sha2_cmd::sha2_cmd(256, *x); },
        Some(Subcommands::SHA384 { x}) => { sha2_cmd::sha2_cmd(384, *x); },
        Some(Subcommands::SHA512 { x}) => { sha2_cmd::sha2_cmd(512, *x); },
        Some(Subcommands::SHA3_224 { x}) => { sha3_cmd::sha3_cmd(224, *x); },
        Some(Subcommands::SHA3_256 { x}) => { sha3_cmd::sha3_cmd(256, *x); },
        Some(Subcommands::SHA3_384 { x}) => { sha3_cmd::sha3_cmd(384, *x); },
        Some(Subcommands::SHA3_512 { x}) => { sha3_cmd::sha3_cmd(512, *x); },
        Some(Subcommands::SHAKE128 { length, x}) => { sha3_cmd::shake_cmd(128, *length, *x); },
        Some(Subcommands::SHAKE256 { length, x}) => { sha3_cmd::shake_cmd(256, *length, *x); },
        Some(Subcommands::HMAC_SHA256 { key, key_file, verify, x}) => { mac_cmd::mac_cmd(HMACVariant::SHA256, key, key_file, verify, *x)},
        Some(Subcommands::HMAC_SHA512 { key, key_file, verify, x}) => { mac_cmd::mac_cmd(HMACVariant::SHA512, key, key_file, verify, *x)},
        Some(Subcommands::HKDF_SHA256 { salt, salt_file, ikm, ikm_file, additional_input, additional_input_file, len, x}) => { hkdf_cmd::hkdf_cmd("HKDF-SHA256", salt, salt_file, ikm, ikm_file, additional_input, additional_input_file, *len, *x)},
        Some(Subcommands::HKDF_SHA512 { salt, salt_file, ikm, ikm_file, additional_input, additional_input_file, len, x}) => { hkdf_cmd::hkdf_cmd("HKDF-SHA512", salt, salt_file, ikm, ikm_file, additional_input, additional_input_file, *len, *x)},
        Some(Subcommands::RNG {  len, x}) => { rng_cmd::rng_cmd(*len, *x)},
        Some(Subcommands::MLDSA44 { action, x }) => { mldsa_cmd::mldsa44_cmd(action, *x); }
        None => { eprintln!("No command provided. See -h") },
    }
}
