//! The `mlkem512`, `mlkem768` and `mlkem1024` subcommands: one body, [`mlkem_cmd`], over the
//! three parameter sets, which differ only in their key types, their lengths and the functions
//! that make and check a key pair. Those come in through a [`ParameterSet`], so a length or a
//! function can no longer be right for two sets and wrong for the third.

use crate::helpers::{
    parse_seed, read_from_file, read_from_file_or_stdin, write_bytes_or_hex,
    write_bytes_or_hex_to_file,
};
use bouncycastle::core::errors::KEMError;
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle::core::traits::{
    KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey, RNG,
};
use bouncycastle::hex;
use bouncycastle::mlkem::{
    MLKEM512, MLKEM512_CT_LEN, MLKEM512_PK_LEN, MLKEM512_SK_LEN, MLKEM512PrivateKey,
    MLKEM512PublicKey, MLKEM768, MLKEM768_CT_LEN, MLKEM768_PK_LEN, MLKEM768_SK_LEN,
    MLKEM768PrivateKey, MLKEM768PublicKey, MLKEM1024, MLKEM1024_CT_LEN, MLKEM1024_PK_LEN,
    MLKEM1024_SK_LEN, MLKEM1024PrivateKey, MLKEM1024PublicKey, MLKEMPrivateKeyTrait, MLKEMTrait,
};
use bouncycastle::rng::HashDRBG_SHA512;
use clap::ValueEnum;
use std::process::exit;

/// The ML-KEM seed is `d || z`, 64 bytes (FIPS 203 Algorithm 19).
const SEED_LEN: usize = 64;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum MLKEMAction {
    /// Generate and output a new private key
    Keygen,
    /// Generate and output a private key from a 64-byte seed (d || z) read from stdin.
    /// Accepts either binary or hex.
    KeygenFromSeed,
    /// Generate and output a new public key from a private key read from stdin.
    /// Accepts either binary or hex.
    PkFromSk,
    /// Accepts a sk and pk, and checks that they match.
    CheckConsistency,
    /// Perform an encapsulation with a public key and output the shared secret key and
    /// the ciphertext.
    /// If a ctfile is provided, then the shared secret key is output to std out in either binary or hex
    /// and the ciphertext to file also in binary or hex.
    /// If no ctfile is provided then ct followed by ss are output to stdout in hex, separated by a newline.
    /// The shared secret is always output to stdout to prevent it
    /// staying in a file longer than it should and causing a vulnerability.
    /// Accepts the public key as binary or hex.
    Encaps,
    /// Perform a decapsulation with a private key and ciphertext and output the shared secret key to stdout either in
    /// binary or hex.
    /// The ciphertext can be read either from ctfile or stdin, in binary or hex.
    /// Accepts the private key as full or seed, binary or hex.
    Decaps,
}

/// A parameter set as the command sees it: its name for messages, and the operations the key
/// types and the `KEM*` traits do not carry on their own. The three sets below are the only
/// instances.
pub(crate) struct ParameterSet<
    PK,
    SK,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
> {
    name: &'static str,
    keygen: fn(&mut dyn RNG) -> Result<(PK, SK), KEMError>,
    keygen_from_seed: fn(&KeyMaterial<SEED_LEN>) -> Result<(PK, SK), KEMError>,
    keypair_consistency_check: fn(&PK, &SK) -> Result<(), KEMError>,
    pk_of: fn(&SK) -> PK,
    encaps: fn(&PK) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError>,
    decaps: fn(&SK, &[u8]) -> Result<KeyMaterial<SS_LEN>, KEMError>,
}

pub(crate) const MLKEM512_SET: ParameterSet<
    MLKEM512PublicKey,
    MLKEM512PrivateKey,
    MLKEM512_PK_LEN,
    MLKEM512_SK_LEN,
    MLKEM512_CT_LEN,
    32,
> = ParameterSet {
    name: "ML-KEM-512",
    keygen: MLKEM512::keygen,
    keygen_from_seed: MLKEM512::keygen_from_seed,
    keypair_consistency_check: MLKEM512::keypair_consistency_check,
    pk_of: |sk| sk.pk().clone(),
    encaps: MLKEM512::encaps,
    decaps: MLKEM512::decaps,
};

pub(crate) const MLKEM768_SET: ParameterSet<
    MLKEM768PublicKey,
    MLKEM768PrivateKey,
    MLKEM768_PK_LEN,
    MLKEM768_SK_LEN,
    MLKEM768_CT_LEN,
    32,
> = ParameterSet {
    name: "ML-KEM-768",
    keygen: MLKEM768::keygen,
    keygen_from_seed: MLKEM768::keygen_from_seed,
    keypair_consistency_check: MLKEM768::keypair_consistency_check,
    pk_of: |sk| sk.pk().clone(),
    encaps: MLKEM768::encaps,
    decaps: MLKEM768::decaps,
};

pub(crate) const MLKEM1024_SET: ParameterSet<
    MLKEM1024PublicKey,
    MLKEM1024PrivateKey,
    MLKEM1024_PK_LEN,
    MLKEM1024_SK_LEN,
    MLKEM1024_CT_LEN,
    32,
> = ParameterSet {
    name: "ML-KEM-1024",
    keygen: MLKEM1024::keygen,
    keygen_from_seed: MLKEM1024::keygen_from_seed,
    keypair_consistency_check: MLKEM1024::keypair_consistency_check,
    pk_of: |sk| sk.pk().clone(),
    encaps: MLKEM1024::encaps,
    decaps: MLKEM1024::decaps,
};

pub(crate) fn mlkem_cmd<
    PK: KEMPublicKey<PK_LEN>,
    SK: KEMPrivateKey<SK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
>(
    set: &ParameterSet<PK, SK, PK_LEN, SK_LEN, CT_LEN, SS_LEN>,
    action: &MLKEMAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        MLKEMAction::Keygen => {
            let (_pk, sk) = (set.keygen)(&mut HashDRBG_SHA512::new_from_os()).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLKEMAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = match parse_seed::<SEED_LEN>(&buf) {
                Ok(seed) => seed,
                Err(()) => {
                    eprintln!(
                        "Error: input could not be parsed as a {SEED_LEN} byte seed in either hex or bin"
                    );
                    exit(-1);
                }
            };
            let (_pk, sk) = (set.keygen_from_seed)(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLKEMAction::PkFromSk => {
            let sk = parse_sk(set, &read_from_file_or_stdin(skfile));
            write_bytes_or_hex(&(set.pk_of)(&sk).encode(), output_hex);
        }
        MLKEMAction::CheckConsistency => {
            let sk = parse_sk(set, &read_from_file_or_stdin(skfile));
            let pk = parse_pk(set, &read_required_file(pkfile, "pkfile"));
            match (set.keypair_consistency_check)(&pk, &sk) {
                Ok(_) => crate::helpers::println_stdout("SUCCESS: pk and sk match."),
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        MLKEMAction::Encaps => {
            let pk = parse_pk(set, &read_from_file_or_stdin(pkfile));
            let (ss, ct) = (set.encaps)(&pk).unwrap();
            if let Some(ctfile) = ctfile {
                // write ct to file and ss to stdout
                write_bytes_or_hex_to_file(&ct, ctfile, output_hex);
                write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
            } else {
                // write both to stdout in hex, separated by a newline.
                write_bytes_or_hex(&ct, true);
                crate::helpers::write_stdout(b"\n");
                write_bytes_or_hex(ss.ref_to_bytes(), true);
            }
        }
        MLKEMAction::Decaps => {
            let sk = parse_sk(set, &read_from_file_or_stdin(skfile));
            let ct = read_from_file_or_stdin(ctfile);
            if ct.len() != CT_LEN {
                eprintln!("Error: ciphertexts is not the correct length.");
                exit(-1);
            }
            let ss = (set.decaps)(&sk, &ct).unwrap_or_else(|e| {
                eprintln!("{:?}", e);
                exit(-1);
            });
            write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
        }
    }
}

/// `--pkfile` and the like where the command cannot fall back to stdin.
fn read_required_file(file: &Option<String>, flag: &str) -> Vec<u8> {
    match file {
        Some(file) => read_from_file(file),
        None => {
            eprintln!("Error: no {flag} provided.");
            exit(-1);
        }
    }
}

/// A private key from its bytes: the hex of a full key, a full key, or a seed, tried in that
/// order (the hex case only arises when the file's hex-or-raw guess declined to decode it).
fn parse_sk<
    PK: KEMPublicKey<PK_LEN>,
    SK: KEMPrivateKey<SK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
>(
    set: &ParameterSet<PK, SK, PK_LEN, SK_LEN, CT_LEN, SS_LEN>,
    bytes: &[u8],
) -> SK {
    if bytes.len() >= 2 * SK_LEN
        && let Ok(decoded) = hex::decode(&bytes[..2 * SK_LEN])
        && let Ok(sk) = SK::from_bytes(&decoded)
    {
        return sk;
    }
    if bytes.len() == SK_LEN
        && let Ok(sk) = SK::from_bytes(bytes)
    {
        return sk;
    }
    if let Ok(seed) = parse_seed::<SEED_LEN>(bytes)
        && let Ok((_pk, sk)) = (set.keygen_from_seed)(&seed)
    {
        return sk;
    }
    eprintln!("Error: couldn't parse the input as a valid {} private key or seed.", set.name);
    exit(-1);
}

/// A public key from its bytes: the hex of a key or the key itself.
fn parse_pk<
    PK: KEMPublicKey<PK_LEN>,
    SK: KEMPrivateKey<SK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
>(
    set: &ParameterSet<PK, SK, PK_LEN, SK_LEN, CT_LEN, SS_LEN>,
    bytes: &[u8],
) -> PK {
    if bytes.len() >= 2 * PK_LEN
        && let Ok(decoded) = hex::decode(&bytes[..2 * PK_LEN])
        && let Ok(pk) = PK::from_bytes(&decoded)
    {
        return pk;
    }
    if bytes.len() == PK_LEN
        && let Ok(pk) = PK::from_bytes(bytes)
    {
        return pk;
    }
    eprintln!("Error: couldn't parse the input as a valid {} public key.", set.name);
    exit(-1);
}
