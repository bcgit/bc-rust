//! Generic CLI wiring for every curve in `bouncycastle-eccdh`: one instantiation of
//! [`eccdh_cmd`] per curve marker, as `ecdsa_cmd.rs` does for ECDSA. `agree` writes the raw shared secret `Z` of SP 800-56A Rev. 3
//! Section 5.7.1.2, which is keying material for a KDF (`hkdf-sha256` and friends take it from
//! a file through `--ikm-file`; the inline `--ikm` would leave it in the command history), not a
//! key.

use crate::helpers::{
    println_stdout, read_input_file, read_secret_file_or_stdin, write_bytes_or_hex,
};
use bouncycastle::core::agreement_key::AgreementKey;
use bouncycastle::core::errors::KeyAgreementError;
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey, RNG};
use bouncycastle::ec::curve::Curve;
use bouncycastle::ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle::eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey, keygen};
use bouncycastle::eccdh::keys_common::DerivePublicKey;
use bouncycastle::rng::HashDRBG_SHA512;
use clap::ValueEnum;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum ECCDHAction {
    /// Generate and output a new private key.
    Keygen,
    /// Derive and output the public key matching a private key read from stdin (raw bytes, or
    /// hex with --hex-input).
    PkFromSk,
    /// Accepts a private key (stdin) and a public key (--pkfile), and checks that they match.
    CheckConsistency,
    /// Compute the shared secret Z from the own private key (stdin or --skfile) and the peer's
    /// public key (--pkfile), and output it. Z is for a KDF, not a key.
    Agree,
}

#[allow(clippy::type_complexity)] // the keygen function pointer is the one per-curve input
pub(crate) fn eccdh_cmd<
    PK: KeyAgreementPublicKey<PK_LEN>,
    SK: KeyAgreementPrivateKey<SK_LEN>
        + DerivePublicKey<PK, PK_LEN>
        + AgreementKey<(), SS_LEN, PublicKey = PK>,
    const SK_LEN: usize,
    const PK_LEN: usize,
    const SS_LEN: usize,
>(
    action: &ECCDHAction,
    keygen: fn(&mut dyn RNG) -> Result<(PK, SK), KeyAgreementError>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    output_hex: bool,
    alg_name: &str,
) {
    match action {
        ECCDHAction::Keygen => {
            let (_pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap_or_else(|e| {
                eprintln!("Error: key generation failed: {e:?}");
                exit(-1);
            });
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        ECCDHAction::PkFromSk => {
            let sk =
                parse_sk::<SK, SK_LEN>(read_secret_file_or_stdin(skfile).ref_to_bytes(), alg_name);
            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        ECCDHAction::CheckConsistency => {
            let sk =
                parse_sk::<SK, SK_LEN>(read_secret_file_or_stdin(skfile).ref_to_bytes(), alg_name);
            let pk = parse_pk::<PK, PK_LEN>(&require_file(pkfile, "pkfile"), alg_name);
            // SP 800-56A Rev. 3 Section 5.6.2.1.4 method (b): recompute dG and compare.
            if sk.derive_pk() == pk {
                println_stdout("SUCCESS: pk and sk match.");
            } else {
                eprintln!("FAILURE: pk and sk do not match.");
                exit(-1);
            }
        }
        ECCDHAction::Agree => {
            let sk =
                parse_sk::<SK, SK_LEN>(read_secret_file_or_stdin(skfile).ref_to_bytes(), alg_name);
            let peer_pk = parse_pk::<PK, PK_LEN>(&require_file(pkfile, "pkfile"), alg_name);
            let z = sk.agree(&peer_pk, ()).unwrap_or_else(|e| {
                eprintln!("Error: key agreement failed: {e:?}");
                exit(-1);
            });
            write_bytes_or_hex(z.ref_to_bytes(), output_hex);
        }
    }
}

/// `--pkfile`, which cannot fall back to stdin (that carries the private key).
fn require_file(file: &Option<String>, flag_name: &str) -> Vec<u8> {
    match file {
        Some(f) => read_input_file(f),
        None => {
            eprintln!("Error: no {flag_name} provided.");
            exit(-1);
        }
    }
}

/// The key from its encoding; the bytes are what the file held, or its hex decoded under
/// `--hex-input`, with nothing guessed from their shape.
fn parse_sk<SK: KeyAgreementPrivateKey<SK_LEN>, const SK_LEN: usize>(
    bytes: &[u8],
    alg_name: &str,
) -> SK {
    match SK::from_bytes(bytes) {
        Ok(sk) => sk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid {alg_name} private key.");
            exit(-1);
        }
    }
}

/// See [`parse_sk`]. A public key that parses has passed full validation.
fn parse_pk<PK: KeyAgreementPublicKey<PK_LEN>, const PK_LEN: usize>(
    bytes: &[u8],
    alg_name: &str,
) -> PK {
    match PK::from_bytes(bytes) {
        Ok(pk) => pk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid {alg_name} public key.");
            exit(-1);
        }
    }
}

pub(crate) fn eccdh_p256_cmd(
    action: &ECCDHAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    output_hex: bool,
) {
    eccdh_cmd::<
        ECCDHPublicKey<P256>,
        ECCDHPrivateKey<P256>,
        { P256::SCALAR_LEN },
        { P256::PK_UNCOMPRESSED_LEN },
        { P256::FE_LEN },
    >(action, keygen::<P256>, skfile, pkfile, output_hex, "ECC CDH P-256")
}

pub(crate) fn eccdh_p384_cmd(
    action: &ECCDHAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    output_hex: bool,
) {
    eccdh_cmd::<
        ECCDHPublicKey<P384>,
        ECCDHPrivateKey<P384>,
        { P384::SCALAR_LEN },
        { P384::PK_UNCOMPRESSED_LEN },
        { P384::FE_LEN },
    >(action, keygen::<P384>, skfile, pkfile, output_hex, "ECC CDH P-384")
}

pub(crate) fn eccdh_p521_cmd(
    action: &ECCDHAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    output_hex: bool,
) {
    eccdh_cmd::<
        ECCDHPublicKey<P521>,
        ECCDHPrivateKey<P521>,
        { P521::SCALAR_LEN },
        { P521::PK_UNCOMPRESSED_LEN },
        { P521::FE_LEN },
    >(action, keygen::<P521>, skfile, pkfile, output_hex, "ECC CDH P-521")
}

pub(crate) fn eccdh_secp256k1_cmd(
    action: &ECCDHAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    output_hex: bool,
) {
    eccdh_cmd::<
        ECCDHPublicKey<Secp256K1>,
        ECCDHPrivateKey<Secp256K1>,
        { Secp256K1::SCALAR_LEN },
        { Secp256K1::PK_UNCOMPRESSED_LEN },
        { Secp256K1::FE_LEN },
    >(action, keygen::<Secp256K1>, skfile, pkfile, output_hex, "ECC CDH secp256k1")
}

pub(crate) fn eccdh_bp256r1_cmd(
    action: &ECCDHAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    output_hex: bool,
) {
    eccdh_cmd::<
        ECCDHPublicKey<Bp256r1>,
        ECCDHPrivateKey<Bp256r1>,
        { Bp256r1::SCALAR_LEN },
        { Bp256r1::PK_UNCOMPRESSED_LEN },
        { Bp256r1::FE_LEN },
    >(action, keygen::<Bp256r1>, skfile, pkfile, output_hex, "ECC CDH brainpoolP256r1")
}

pub(crate) fn eccdh_bp384r1_cmd(
    action: &ECCDHAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    output_hex: bool,
) {
    eccdh_cmd::<
        ECCDHPublicKey<Bp384r1>,
        ECCDHPrivateKey<Bp384r1>,
        { Bp384r1::SCALAR_LEN },
        { Bp384r1::PK_UNCOMPRESSED_LEN },
        { Bp384r1::FE_LEN },
    >(action, keygen::<Bp384r1>, skfile, pkfile, output_hex, "ECC CDH brainpoolP384r1")
}

pub(crate) fn eccdh_bp512r1_cmd(
    action: &ECCDHAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    output_hex: bool,
) {
    eccdh_cmd::<
        ECCDHPublicKey<Bp512r1>,
        ECCDHPrivateKey<Bp512r1>,
        { Bp512r1::SCALAR_LEN },
        { Bp512r1::PK_UNCOMPRESSED_LEN },
        { Bp512r1::FE_LEN },
    >(action, keygen::<Bp512r1>, skfile, pkfile, output_hex, "ECC CDH brainpoolP512r1")
}
