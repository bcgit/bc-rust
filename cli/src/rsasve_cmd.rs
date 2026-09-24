//! CLI wiring for RSASVE (SP 800-56B Rev. 2 §7.2.1), `bouncycastle_rsa`'s RSA KEM. There is one
//! command per modulus size, since the size fixes the key, ciphertext and shared-secret lengths
//! (the same split `rsa_cmd.rs` makes for signatures). A single generic [`rsasve_cmd`], bound over
//! the `KEMEncapsulator`/`KEMDecapsulator` traits, is monomorphised once per size.
//!
//! The shape follows `mlkem_cmd.rs`'s `Encaps`/`Decaps`. The shared secret always goes to stdout
//! and is never written to a file. `encaps` writes the ciphertext to `--ctfile` if one is given;
//! otherwise it prints the ciphertext and then the shared secret, both in hex, one per line.
//! `keygen` is `rsa_cmd.rs`'s: the private key to stdout, the public key to `--pkfile`. Nothing
//! else would work, because an RSA private key file does not carry `e`.
//!
//! These are separate subcommands from `rsa-<size>` because `bouncycastle_rsa` keeps
//! key-establishment and signing keys as separate types (see its `rsasve` module's
//! `# Key separation`). The file encodings are the same raw layouts, however, and nothing here
//! stops a caller from pointing one command at the other's key files. The encodings cannot tell
//! the two kinds of key apart.
//!
//! The shared secret is RSASVE's raw secret value `Z`, the modulus's full length. It still needs
//! a KDF (e.g. `hkdf`) before it can be used as a key.

use crate::helpers::{
    read_from_file, read_from_file_or_stdin, write_bytes_or_hex, write_bytes_or_hex_to_file,
};
use bouncycastle::core::errors::KEMError;
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::traits::{KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey};
use bouncycastle::rsa::{rsa_2048, rsa_3072, rsa_4096, rsa_8192};
use clap::ValueEnum;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RSASVEAction {
    /// Generate a key-establishment key pair: the private key to stdout, the public key to
    /// `--pkfile`.
    Keygen,
    /// Encapsulate to the public key in `--pkfile` (or read from stdin). With `--ctfile`, the
    /// ciphertext goes to that file and the shared secret to stdout. Without it, the ciphertext
    /// and then the shared secret go to stdout in hex, separated by a newline.
    Encaps,
    /// Decapsulate the ciphertext in `--ctfile` (or read from stdin) with the private key in
    /// `--skfile`, and write the shared secret to stdout.
    Decaps,
}

fn require_file(file: &Option<String>, flag_name: &str) -> Vec<u8> {
    match file {
        Some(f) => read_from_file(f),
        None => {
            eprintln!("Error: no {flag_name} provided.");
            exit(-1);
        }
    }
}

/// One modulus size's RSASVE, per `action`.
fn rsasve_cmd<
    PK: KEMPublicKey<PK_LEN>,
    SK: KEMPrivateKey<SK_LEN>,
    K: KEMEncapsulator<PK, PK_LEN, CT_LEN, SS_LEN> + KEMDecapsulator<SK, SK_LEN, CT_LEN, SS_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
>(
    action: &RSASVEAction,
    keygen: fn() -> Result<(PK, SK), KEMError>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
    alg_name: &str,
) {
    match action {
        RSASVEAction::Keygen => {
            let Some(pkfile) = pkfile else {
                eprintln!(
                    "Error: {alg_name} keygen needs --pkfile to receive the public key (an RSA \
                     private key file does not carry e, so it cannot be derived later)."
                );
                exit(-1);
            };
            let (pk, sk) = keygen().unwrap_or_else(|e| {
                eprintln!("Error: {alg_name} key generation failed: {e:?}");
                exit(-1);
            });
            write_bytes_or_hex_to_file(&pk.encode(), pkfile, output_hex);
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        RSASVEAction::Encaps => {
            let pk = PK::from_bytes(&read_from_file_or_stdin(pkfile)).unwrap_or_else(|e| {
                eprintln!(
                    "Error: couldn't parse the input as a valid {alg_name} public key (must be \
                     exactly {PK_LEN} bytes): {e:?}"
                );
                exit(-1);
            });
            let (ss, ct) = K::encaps(&pk).unwrap_or_else(|e| {
                eprintln!("Error: {alg_name} encapsulation failed: {e:?}");
                exit(-1);
            });
            match ctfile {
                Some(ctfile) => {
                    write_bytes_or_hex_to_file(&ct, ctfile, output_hex);
                    write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
                }
                None => {
                    write_bytes_or_hex(&ct, true);
                    println!();
                    write_bytes_or_hex(ss.ref_to_bytes(), true);
                }
            }
        }
        RSASVEAction::Decaps => {
            let sk = SK::from_bytes(&require_file(skfile, "skfile")).unwrap_or_else(|e| {
                eprintln!(
                    "Error: couldn't parse the input as a valid {alg_name} private key (must be \
                     exactly {SK_LEN} bytes): {e:?}"
                );
                exit(-1);
            });
            // `decaps` reports a wrong-length ciphertext itself (as `LengthError`).
            let ss = K::decaps(&sk, &read_from_file_or_stdin(ctfile)).unwrap_or_else(|e| {
                eprintln!("Error: {alg_name} decapsulation failed: {e:?}");
                exit(-1);
            });
            write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
        }
    }
}

pub(crate) fn rsasve_2048_cmd(
    action: &RSASVEAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
) {
    use rsa_2048::{
        CT_LEN, PK_LEN, RSA2048KEMPrivateKey, RSA2048KEMPublicKey, RSASVE, SK_LEN, SS_LEN,
    };
    rsasve_cmd::<RSA2048KEMPublicKey, RSA2048KEMPrivateKey, RSASVE, PK_LEN, SK_LEN, CT_LEN, SS_LEN>(
        action,
        RSASVE::keygen,
        skfile,
        pkfile,
        ctfile,
        output_hex,
        "RSASVE-2048",
    );
}

pub(crate) fn rsasve_3072_cmd(
    action: &RSASVEAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
) {
    use rsa_3072::{
        CT_LEN, PK_LEN, RSA3072KEMPrivateKey, RSA3072KEMPublicKey, RSASVE, SK_LEN, SS_LEN,
    };
    rsasve_cmd::<RSA3072KEMPublicKey, RSA3072KEMPrivateKey, RSASVE, PK_LEN, SK_LEN, CT_LEN, SS_LEN>(
        action,
        RSASVE::keygen,
        skfile,
        pkfile,
        ctfile,
        output_hex,
        "RSASVE-3072",
    );
}

pub(crate) fn rsasve_4096_cmd(
    action: &RSASVEAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
) {
    use rsa_4096::{
        CT_LEN, PK_LEN, RSA4096KEMPrivateKey, RSA4096KEMPublicKey, RSASVE, SK_LEN, SS_LEN,
    };
    rsasve_cmd::<RSA4096KEMPublicKey, RSA4096KEMPrivateKey, RSASVE, PK_LEN, SK_LEN, CT_LEN, SS_LEN>(
        action,
        RSASVE::keygen,
        skfile,
        pkfile,
        ctfile,
        output_hex,
        "RSASVE-4096",
    );
}

pub(crate) fn rsasve_8192_cmd(
    action: &RSASVEAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
) {
    use rsa_8192::{
        CT_LEN, PK_LEN, RSA8192KEMPrivateKey, RSA8192KEMPublicKey, RSASVE, SK_LEN, SS_LEN,
    };
    rsasve_cmd::<RSA8192KEMPublicKey, RSA8192KEMPrivateKey, RSASVE, PK_LEN, SK_LEN, CT_LEN, SS_LEN>(
        action,
        RSASVE::keygen,
        skfile,
        pkfile,
        ctfile,
        output_hex,
        "RSASVE-8192",
    );
}
