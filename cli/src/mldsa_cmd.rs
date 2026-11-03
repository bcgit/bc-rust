//! The `mldsa44`, `mldsa65`, `mldsa87` and `hash-mldsa*` subcommands: one body, [`mldsa_cmd`],
//! over the three parameter sets, which differ only in their key types, their lengths and the
//! functions that make and check a key pair. Those come in through a [`ParameterSet`], so a
//! length or a function can no longer be right for two sets and wrong for the third.

use crate::helpers::{parse_seed, read_from_file, read_from_file_or_stdin, write_bytes_or_hex};
use bouncycastle::core::errors::SignatureError;
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::signature_key::{
    PreHashSigningKey, PreHashVerifyingKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle::core::traits::{
    RNG, SignaturePrivateKey, SignaturePublicKey, SignatureSigner, SignatureVerifier,
};
use bouncycastle::hex;
use bouncycastle::mldsa::{
    MLDSA_SEED_LEN, MLDSA44, MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA44_SK_LEN, MLDSA44PrivateKey,
    MLDSA44PublicKey, MLDSA65, MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MLDSA65_SK_LEN, MLDSA65PrivateKey,
    MLDSA65PublicKey, MLDSA87, MLDSA87_PK_LEN, MLDSA87_SIG_LEN, MLDSA87_SK_LEN, MLDSA87PrivateKey,
    MLDSA87PublicKey, MLDSAPrivateKeyTrait, MLDSATrait,
};
use bouncycastle::rng::HashDRBG_SHA512;
use bouncycastle::sha2::SHA512;
use clap::ValueEnum;
use core::marker::PhantomData;
use std::io;
use std::io::Read;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum MLDSAAction {
    /// Generate and output a new private key
    Keygen,
    /// Generate and output a private key from a seed read from stdin.
    /// Accepts either binary or hex.
    KeygenFromSeed,
    /// Generate and output a new public key from a private key read from stdin.
    /// Accepts either binary or hex.
    PkFromSk,
    /// Accepts a sk and pk, and checks that they match.
    CheckConsistency,
    /// Sign a message read from stdin with a private key file and output the signature.
    /// Accepts private key as full or seed, binary or hex.
    Sign,
    /// Verify a message read from stdin with a public key file and a signature file
    /// Accepts the public key and signature as binary or hex.
    Verify,
}

/// A parameter set as the command sees it: its name for messages, the algorithm marker the
/// signing traits are keyed by, and the key-pair operations the core traits do not carry. The
/// three sets below are the only instances.
pub(crate) struct ParameterSet<
    A,
    PK,
    SK,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
> {
    name: &'static str,
    alg: PhantomData<A>,
    keygen: fn(&mut dyn RNG) -> Result<(PK, SK), SignatureError>,
    keygen_from_seed: fn(&KeyMaterial<MLDSA_SEED_LEN>) -> Result<(PK, SK), SignatureError>,
    keypair_consistency_check: fn(&PK, &SK) -> Result<(), SignatureError>,
    pk_of: fn(&SK) -> PK,
}

pub(crate) const MLDSA44_SET: ParameterSet<
    MLDSA44,
    MLDSA44PublicKey,
    MLDSA44PrivateKey,
    MLDSA44_PK_LEN,
    MLDSA44_SK_LEN,
    MLDSA44_SIG_LEN,
> = ParameterSet {
    name: "ML-DSA-44",
    alg: PhantomData,
    keygen: MLDSA44::keygen,
    keygen_from_seed: MLDSA44::keygen_from_seed,
    keypair_consistency_check: MLDSA44::keypair_consistency_check,
    pk_of: |sk| sk.derive_pk(),
};

pub(crate) const MLDSA65_SET: ParameterSet<
    MLDSA65,
    MLDSA65PublicKey,
    MLDSA65PrivateKey,
    MLDSA65_PK_LEN,
    MLDSA65_SK_LEN,
    MLDSA65_SIG_LEN,
> = ParameterSet {
    name: "ML-DSA-65",
    alg: PhantomData,
    keygen: MLDSA65::keygen,
    keygen_from_seed: MLDSA65::keygen_from_seed,
    keypair_consistency_check: MLDSA65::keypair_consistency_check,
    pk_of: |sk| sk.derive_pk(),
};

pub(crate) const MLDSA87_SET: ParameterSet<
    MLDSA87,
    MLDSA87PublicKey,
    MLDSA87PrivateKey,
    MLDSA87_PK_LEN,
    MLDSA87_SK_LEN,
    MLDSA87_SIG_LEN,
> = ParameterSet {
    name: "ML-DSA-87",
    alg: PhantomData,
    keygen: MLDSA87::keygen,
    keygen_from_seed: MLDSA87::keygen_from_seed,
    keypair_consistency_check: MLDSA87::keypair_consistency_check,
    pk_of: |sk| sk.derive_pk(),
};

/// `prehash` selects HashML-DSA with SHA-512 (FIPS 204 Section 5.4) over pure ML-DSA.
pub(crate) fn mldsa_cmd<
    A: SignatureAlgorithm,
    PK: SignaturePublicKey<PK_LEN> + VerifyingKey<A, SIG_LEN> + PreHashVerifyingKey<A, SIG_LEN>,
    SK: SignaturePrivateKey<SK_LEN> + SigningKey<A, SIG_LEN> + PreHashSigningKey<A, SIG_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
>(
    set: &ParameterSet<A, PK, SK, PK_LEN, SK_LEN, SIG_LEN>,
    action: &MLDSAAction,
    ctxfile: &Option<String>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    prehash: bool,
    output_hex: bool,
) {
    match action {
        MLDSAAction::Keygen => {
            let (_pk, sk) = (set.keygen)(&mut HashDRBG_SHA512::new_from_os()).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = match parse_seed::<MLDSA_SEED_LEN>(&buf) {
                Ok(seed) => seed,
                Err(()) => {
                    eprintln!(
                        "Error: input could not be parsed as a {MLDSA_SEED_LEN} byte seed in either hex or bin"
                    );
                    exit(-1);
                }
            };
            let (_pk, sk) = (set.keygen_from_seed)(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let sk = parse_sk(set, &read_from_file_or_stdin(skfile));
            write_bytes_or_hex(&(set.pk_of)(&sk).encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
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
        MLDSAAction::Sign => {
            let sk = parse_sk(set, &read_required_file(skfile, "skfile"));
            let ctx = read_ctx(ctxfile);
            let mut rng = HashDRBG_SHA512::new_from_os();
            if prehash {
                sign_stream(
                    sk.create_ph_signer::<SHA512>(&mut rng, Some(&ctx)).unwrap(),
                    output_hex,
                );
            } else {
                sign_stream(sk.create_signer(&mut rng, Some(&ctx)).unwrap(), output_hex);
            }
        }
        MLDSAAction::Verify => {
            let pk = parse_pk(set, &read_required_file(pkfile, "pkfile"));
            let ctx = read_ctx(ctxfile);
            let sig = read_required_file(sigfile, "sigfile");
            if prehash {
                verify_stream(pk.create_ph_verifier::<SHA512>(Some(&ctx)).unwrap(), &sig);
            } else {
                verify_stream(pk.create_verifier(Some(&ctx)).unwrap(), &sig);
            }
        }
    }
}

/// Streams stdin into `signer` and writes the signature.
fn sign_stream<const SIG_LEN: usize>(mut signer: impl SignatureSigner<SIG_LEN>, output_hex: bool) {
    let mut buf = [0u8; 1024];
    loop {
        let n = io::stdin().read(&mut buf).expect("Failed to read from stdin");
        if n == 0 {
            break;
        }
        signer.do_update(&buf[..n]);
    }
    let sig = signer.do_final().unwrap();
    write_bytes_or_hex(&sig, output_hex);
}

/// Streams stdin into `verifier` and reports whether `sig` verifies, through the exit status.
fn verify_stream(mut verifier: impl SignatureVerifier, sig: &[u8]) {
    let mut buf = [0u8; 1024];
    loop {
        let n = io::stdin().read(&mut buf).expect("Failed to read from stdin");
        if n == 0 {
            break;
        }
        verifier.do_update(&buf[..n]);
    }
    if verifier.do_verify_final(sig).is_ok() {
        crate::helpers::println_stdout("Signature is valid.");
    } else {
        eprintln!("Signature is invalid.");
        exit(-1);
    }
}

/// `--ctxfile`'s bytes, or the empty context (FIPS 204's default) without one.
fn read_ctx(ctxfile: &Option<String>) -> Vec<u8> {
    ctxfile.as_ref().map(|f| read_from_file(f)).unwrap_or_default()
}

/// `--skfile` and the like where the command cannot fall back to stdin.
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
    A,
    PK,
    SK: SignaturePrivateKey<SK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
>(
    set: &ParameterSet<A, PK, SK, PK_LEN, SK_LEN, SIG_LEN>,
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
    if let Ok(seed) = parse_seed::<MLDSA_SEED_LEN>(bytes)
        && let Ok((_pk, sk)) = (set.keygen_from_seed)(&seed)
    {
        return sk;
    }
    eprintln!("Error: couldn't parse the input as a valid {} private key or seed.", set.name);
    exit(-1);
}

/// A public key from its bytes: the hex of a key or the key itself.
fn parse_pk<
    A,
    PK: SignaturePublicKey<PK_LEN>,
    SK,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
>(
    set: &ParameterSet<A, PK, SK, PK_LEN, SK_LEN, SIG_LEN>,
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
