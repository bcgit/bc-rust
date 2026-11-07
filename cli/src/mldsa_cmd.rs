//! The `mldsa44`, `mldsa65`, `mldsa87` and `hash-mldsa*` subcommands: one body, [`mldsa_cmd`],
//! over the three parameter sets, which differ only in their key types, their lengths and the
//! functions that make and check a key pair. Those come in through a [`ParameterSet`], so a
//! length or a function can no longer be right for two sets and wrong for the third.
//!
//! Private keys and seeds are read through the zeroized secret path; public keys, signatures,
//! contexts and message representatives through the plain one. All of them are raw bytes, or
//! hex with `--hex-input`.

use crate::helpers::{
    parse_seed, read_input_file, read_input_file_or_stdin, read_secret_file,
    read_secret_file_or_stdin, seed_error, stream_stdin, write_bytes_or_hex,
};
use bouncycastle::core::errors::SignatureError;
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle::core::signature_key::{
    DeterministicPreHashSigningKey, DeterministicSigningKey, PreHashSigningKey,
    PreHashVerifyingKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle::core::traits::{
    RNG, SignaturePrivateKey, SignaturePublicKey, SignatureSigner, SignatureVerifier,
};
use bouncycastle::mldsa::{
    MLDSA_MU_LEN, MLDSA_SEED_LEN, MLDSA44, MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA44_SK_LEN,
    MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65, MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MLDSA65_SK_LEN,
    MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87, MLDSA87_PK_LEN, MLDSA87_SIG_LEN, MLDSA87_SK_LEN,
    MLDSA87PrivateKey, MLDSA87PublicKey, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MLDSATrait,
    MuBuilder,
};
use bouncycastle::rng::HashDRBG_SHA512;
use bouncycastle::sha2::{SHA256, SHA512};
use bouncycastle::sha3::{SHAKE128, SHAKE256};
use clap::ValueEnum;
use core::marker::PhantomData;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum MLDSAAction {
    /// Generate and output a new private key
    Keygen,
    /// Generate and output a private key from a 32-byte seed read from stdin (or --skfile).
    KeygenFromSeed,
    /// Generate and output a new public key from a private key read from stdin (or --skfile).
    PkFromSk,
    /// Accepts a sk (stdin or --skfile) and a pk (--pkfile), and checks that they match.
    CheckConsistency,
    /// Sign a message read from stdin with the private key in --skfile and output the signature.
    /// Accepts the private key as full or seed. Hedged (FIPS 204 Section 3.4) unless
    /// --deterministic.
    Sign,
    /// Verify a message read from stdin against the public key in --pkfile and the signature in
    /// --sigfile.
    Verify,
    /// Output the 64-byte message representative mu (FIPS 204 Algorithm 7 line 6) of the
    /// message on stdin under the public key in --pkfile and the context, for signing elsewhere
    /// with sign-mu. Not for hash-mldsa*, whose representative frames the digest differently.
    ComputeMu,
    /// Sign a message representative (64 bytes, from --mufile or stdin) with the private key in
    /// --skfile: the external-mu interface. The signature verifies as an ordinary one.
    SignMu,
    /// Verify the signature in --sigfile against a message representative (64 bytes, from
    /// --mufile or stdin) under the public key in --pkfile.
    VerifyMu,
}

/// The pre-hash of HashML-DSA (FIPS 204 Section 5.4): the hash must carry at least the
/// parameter set's strength, so SHA-256 and SHAKE128 (RFC 8702's 32-byte digest) fit ML-DSA-44
/// only.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum PreHashAlg {
    Sha256,
    Sha512,
    Shake128,
    Shake256,
}

/// The files a command names.
pub(crate) struct Files<'a> {
    pub(crate) ctx: &'a Option<String>,
    pub(crate) sk: &'a Option<String>,
    pub(crate) pk: &'a Option<String>,
    pub(crate) sig: &'a Option<String>,
    pub(crate) mu: &'a Option<String>,
}

/// A parameter set as the command sees it: its name for messages, the algorithm marker the
/// signing traits are keyed by, and the operations the core traits do not carry: the key pair's,
/// and the external-mu interface of the ML-DSA key traits. The three sets below are the only
/// instances.
#[allow(clippy::type_complexity)] // the function-pointer fields are the table's point
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
    mu_builder: fn(&PK, Option<&[u8]>) -> Result<MuBuilder, SignatureError>,
    sign_mu: fn(&SK, &[u8; MLDSA_MU_LEN], &mut dyn RNG) -> Result<[u8; SIG_LEN], SignatureError>,
    sign_mu_deterministic: fn(&SK, &[u8; MLDSA_MU_LEN]) -> Result<[u8; SIG_LEN], SignatureError>,
    verify_mu: fn(&PK, &[u8; MLDSA_MU_LEN], &[u8; SIG_LEN]) -> Result<(), SignatureError>,
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
    mu_builder: |pk, ctx| pk.create_mu_builder(ctx),
    sign_mu: |sk, mu, rng| sk.sign_mu(mu, rng),
    sign_mu_deterministic: |sk, mu| sk.sign_mu_deterministic(mu),
    verify_mu: |pk, mu, sig| pk.verify_mu(mu, sig),
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
    mu_builder: |pk, ctx| pk.create_mu_builder(ctx),
    sign_mu: |sk, mu, rng| sk.sign_mu(mu, rng),
    sign_mu_deterministic: |sk, mu| sk.sign_mu_deterministic(mu),
    verify_mu: |pk, mu, sig| pk.verify_mu(mu, sig),
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
    mu_builder: |pk, ctx| pk.create_mu_builder(ctx),
    sign_mu: |sk, mu, rng| sk.sign_mu(mu, rng),
    sign_mu_deterministic: |sk, mu| sk.sign_mu_deterministic(mu),
    verify_mu: |pk, mu, sig| pk.verify_mu(mu, sig),
};

/// `prehash` selects HashML-DSA with that hash (FIPS 204 Section 5.4) over pure ML-DSA;
/// `deterministic` the variant with `rnd` all zero (Section 3.4) over the hedged one.
pub(crate) fn mldsa_cmd<
    A: SignatureAlgorithm,
    PK: SignaturePublicKey<PK_LEN> + VerifyingKey<A, SIG_LEN> + PreHashVerifyingKey<A, SIG_LEN>,
    SK: SignaturePrivateKey<SK_LEN>
        + SigningKey<A, SIG_LEN>
        + DeterministicSigningKey<A, SIG_LEN>
        + PreHashSigningKey<A, SIG_LEN>
        + DeterministicPreHashSigningKey<A, SIG_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
>(
    set: &ParameterSet<A, PK, SK, PK_LEN, SK_LEN, SIG_LEN>,
    action: &MLDSAAction,
    files: &Files,
    prehash: Option<PreHashAlg>,
    deterministic: bool,
    output_hex: bool,
) {
    match action {
        MLDSAAction::Keygen => {
            let (_pk, sk) = (set.keygen)(&mut HashDRBG_SHA512::new_from_os())
                .unwrap_or_else(|e| keygen_error(e));
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::KeygenFromSeed => {
            let input = read_secret_file_or_stdin(files.sk);
            let seed = parse_seed::<MLDSA_SEED_LEN>(input.ref_to_bytes())
                .unwrap_or_else(|e| seed_error::<MLDSA_SEED_LEN>(e));
            let (_pk, sk) = (set.keygen_from_seed)(&seed).unwrap_or_else(|e| keygen_error(e));
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let sk = parse_sk(set, read_secret_file_or_stdin(files.sk).ref_to_bytes());
            write_bytes_or_hex(&(set.pk_of)(&sk).encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let sk = parse_sk(set, read_secret_file_or_stdin(files.sk).ref_to_bytes());
            let pk = parse_pk(set, &read_required_file(files.pk, "pkfile"));
            match (set.keypair_consistency_check)(&pk, &sk) {
                Ok(_) => crate::helpers::println_stdout("SUCCESS: pk and sk match."),
                Err(_) => {
                    eprintln!("Error: the public and private keys do not match.");
                    exit(-1);
                }
            }
        }
        MLDSAAction::Sign => {
            let sk = parse_sk(set, read_required_secret(files.sk, "skfile").ref_to_bytes());
            let ctx = read_ctx(files.ctx);
            let ctx = Some(ctx.as_slice());
            let mut rng = HashDRBG_SHA512::new_from_os();
            match (prehash, deterministic) {
                (None, false) => {
                    let s = sk.create_signer(&mut rng, ctx).unwrap_or_else(|e| signer_error(e));
                    sign_stream(s, output_hex)
                }
                (None, true) => {
                    let s = sk.create_signer_deterministic(ctx).unwrap_or_else(|e| signer_error(e));
                    sign_stream(s, output_hex)
                }
                (Some(PreHashAlg::Sha256), false) => {
                    let s = sk.create_ph_signer::<SHA256>(&mut rng, ctx);
                    sign_stream(s.unwrap_or_else(|e| signer_error(e)), output_hex)
                }
                (Some(PreHashAlg::Sha512), false) => {
                    let s = sk.create_ph_signer::<SHA512>(&mut rng, ctx);
                    sign_stream(s.unwrap_or_else(|e| signer_error(e)), output_hex)
                }
                (Some(PreHashAlg::Shake128), false) => {
                    let s = sk.create_ph_signer::<SHAKE128>(&mut rng, ctx);
                    sign_stream(s.unwrap_or_else(|e| signer_error(e)), output_hex)
                }
                (Some(PreHashAlg::Shake256), false) => {
                    let s = sk.create_ph_signer::<SHAKE256>(&mut rng, ctx);
                    sign_stream(s.unwrap_or_else(|e| signer_error(e)), output_hex)
                }
                (Some(PreHashAlg::Sha256), true) => {
                    let s = sk.create_ph_signer_deterministic::<SHA256>(ctx);
                    sign_stream(s.unwrap_or_else(|e| signer_error(e)), output_hex)
                }
                (Some(PreHashAlg::Sha512), true) => {
                    let s = sk.create_ph_signer_deterministic::<SHA512>(ctx);
                    sign_stream(s.unwrap_or_else(|e| signer_error(e)), output_hex)
                }
                (Some(PreHashAlg::Shake128), true) => {
                    let s = sk.create_ph_signer_deterministic::<SHAKE128>(ctx);
                    sign_stream(s.unwrap_or_else(|e| signer_error(e)), output_hex)
                }
                (Some(PreHashAlg::Shake256), true) => {
                    let s = sk.create_ph_signer_deterministic::<SHAKE256>(ctx);
                    sign_stream(s.unwrap_or_else(|e| signer_error(e)), output_hex)
                }
            }
        }
        MLDSAAction::Verify => {
            let pk = parse_pk(set, &read_required_file(files.pk, "pkfile"));
            let ctx = read_ctx(files.ctx);
            let ctx = Some(ctx.as_slice());
            let sig = read_required_file(files.sig, "sigfile");
            match prehash {
                None => {
                    let v = pk.create_verifier(ctx).unwrap_or_else(|e| signer_error(e));
                    verify_stream(v, &sig)
                }
                Some(PreHashAlg::Sha256) => {
                    let v = pk.create_ph_verifier::<SHA256>(ctx);
                    verify_stream(v.unwrap_or_else(|e| signer_error(e)), &sig)
                }
                Some(PreHashAlg::Sha512) => {
                    let v = pk.create_ph_verifier::<SHA512>(ctx);
                    verify_stream(v.unwrap_or_else(|e| signer_error(e)), &sig)
                }
                Some(PreHashAlg::Shake128) => {
                    let v = pk.create_ph_verifier::<SHAKE128>(ctx);
                    verify_stream(v.unwrap_or_else(|e| signer_error(e)), &sig)
                }
                Some(PreHashAlg::Shake256) => {
                    let v = pk.create_ph_verifier::<SHAKE256>(ctx);
                    verify_stream(v.unwrap_or_else(|e| signer_error(e)), &sig)
                }
            }
        }
        MLDSAAction::ComputeMu => {
            refuse_mu_with_prehash(prehash);
            let pk = parse_pk(set, &read_required_file(files.pk, "pkfile"));
            let ctx = read_ctx(files.ctx);
            let mut mb = (set.mu_builder)(&pk, Some(&ctx)).unwrap_or_else(|e| signer_error(e));
            stream_stdin(|chunk| mb.do_update(chunk));
            write_bytes_or_hex(&mb.do_final(), output_hex);
        }
        MLDSAAction::SignMu => {
            refuse_mu_with_prehash(prehash);
            let sk = parse_sk(set, read_required_secret(files.sk, "skfile").ref_to_bytes());
            let mu = read_mu(files.mu);
            let sig = if deterministic {
                (set.sign_mu_deterministic)(&sk, &mu)
            } else {
                (set.sign_mu)(&sk, &mu, &mut HashDRBG_SHA512::new_from_os())
            };
            let sig = sig.unwrap_or_else(|e| {
                eprintln!("Error: signing failed: {e:?}");
                exit(-1);
            });
            write_bytes_or_hex(&sig, output_hex);
        }
        MLDSAAction::VerifyMu => {
            refuse_mu_with_prehash(prehash);
            let pk = parse_pk(set, &read_required_file(files.pk, "pkfile"));
            let sig = read_required_file(files.sig, "sigfile");
            let sig: &[u8; SIG_LEN] = sig.as_slice().try_into().unwrap_or_else(|_| {
                eprintln!(
                    "Error: the signature is {} bytes; an {} signature is {SIG_LEN}.",
                    sig.len(),
                    set.name
                );
                exit(-1);
            });
            let mu = read_mu(files.mu);
            if (set.verify_mu)(&pk, &mu, sig).is_ok() {
                crate::helpers::println_stdout("Signature is valid.");
            } else {
                eprintln!("Error: the signature is invalid.");
                exit(-1);
            }
        }
    }
}

/// The mu actions are pure ML-DSA's: HashML-DSA's representative frames the digest and the
/// hash's OID (FIPS 204 Algorithm 4 line 23), which `compute-mu` does not produce.
fn refuse_mu_with_prehash(prehash: Option<PreHashAlg>) {
    if prehash.is_some() {
        eprintln!("Error: the mu actions are for the mldsa* commands, not hash-mldsa*.");
        exit(-1);
    }
}

/// The 64-byte message representative from `--mufile` or stdin.
fn read_mu(mufile: &Option<String>) -> [u8; MLDSA_MU_LEN] {
    let mu = read_input_file_or_stdin(mufile);
    mu.as_slice().try_into().unwrap_or_else(|_| {
        eprintln!("Error: mu must be {MLDSA_MU_LEN} bytes, got {}.", mu.len());
        exit(-1);
    })
}

fn keygen_error(e: SignatureError) -> ! {
    eprintln!("Error: key generation failed: {e:?}");
    exit(-1);
}

/// A signer or verifier refused to start: the context is over 255 bytes (FIPS 204 Algorithm 2
/// line 1), the pre-hash is too weak for the parameter set, or the RNG failed.
fn signer_error(e: SignatureError) -> ! {
    eprintln!("Error: couldn't start the signature: {e:?}");
    exit(-1);
}

/// Streams stdin into `signer` and writes the signature.
fn sign_stream<const SIG_LEN: usize>(mut signer: impl SignatureSigner<SIG_LEN>, output_hex: bool) {
    stream_stdin(|chunk| signer.do_update(chunk));
    let sig = signer.do_final().unwrap_or_else(|e| {
        eprintln!("Error: signing failed: {e:?}");
        exit(-1);
    });
    write_bytes_or_hex(&sig, output_hex);
}

/// Streams stdin into `verifier` and reports whether `sig` verifies, through the exit status.
fn verify_stream(mut verifier: impl SignatureVerifier, sig: &[u8]) {
    stream_stdin(|chunk| verifier.do_update(chunk));
    if verifier.do_verify_final(sig).is_ok() {
        crate::helpers::println_stdout("Signature is valid.");
    } else {
        eprintln!("Error: the signature is invalid.");
        exit(-1);
    }
}

/// `--ctxfile`'s bytes, or the empty context (FIPS 204's default) without one.
fn read_ctx(ctxfile: &Option<String>) -> Vec<u8> {
    ctxfile.as_ref().map(|f| read_input_file(f)).unwrap_or_default()
}

/// `--pkfile` and the like where the command cannot fall back to stdin.
fn read_required_file(file: &Option<String>, flag: &str) -> Vec<u8> {
    match file {
        Some(file) => read_input_file(file),
        None => {
            eprintln!("Error: no {flag} provided.");
            exit(-1);
        }
    }
}

/// `--skfile` where signing cannot take the key from stdin, which carries the message.
fn read_required_secret(file: &Option<String>, flag: &str) -> crate::helpers::SecretBytes {
    match file {
        Some(file) => read_secret_file(file),
        None => {
            eprintln!("Error: no {flag} provided.");
            exit(-1);
        }
    }
}

/// A private key from its bytes: a full key, or a seed.
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
    eprintln!(
        "Error: couldn't parse the input as a valid {} private key or seed (raw bytes; hex needs --hex-input).",
        set.name
    );
    exit(-1);
}

/// A public key from its bytes.
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
    if bytes.len() == PK_LEN
        && let Ok(pk) = PK::from_bytes(bytes)
    {
        return pk;
    }
    eprintln!(
        "Error: couldn't parse the input as a valid {} public key (raw bytes; hex needs --hex-input).",
        set.name
    );
    exit(-1);
}
