//! CLI wiring for RSAES-OAEP key transport (RFC 8017 §7.1; SP 800-56B Rev. 2 §7.2.2 and §9.2.3),
//! one command per modulus size, on the same key-establishment keys and key files as
//! `rsasve_cmd.rs`. The label hash and the MGF1 hash are `--hash` and `--mgf-hash` (the same
//! hash unless given), and the label is `--label`, in hex.
//!
//! Two pairs of actions over the one scheme. `encaps` / `decaps` are the KEM: the command
//! draws a 32-byte key and transports it. `transport` / `recover` carry a key the caller
//! supplies on stdin, of any length the modulus and hash allow.

use crate::helpers::{
    WriteError, decode_hex_arg, finish_stdout, read_input_file, read_input_file_or_stdin,
    read_secret_file, read_secret_stdin, try_write_bytes_or_hex, try_write_bytes_or_hex_to_file,
    try_write_stdout, write_bytes_or_hex, write_bytes_or_hex_to_file, write_private_key,
    write_secret_bytes_or_hex,
};
use bouncycastle::core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle::core::key_transport_key::{KeyTransportDecryptingKey, KeyTransportEncryptingKey};
use bouncycastle::core::traits::{PrivateKey, PublicKey};
use bouncycastle::digest::sha1::SHA1;
use bouncycastle::digest::sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle::modexp::rsa::rsaes_oaep::{OaepHash, OaepParams};
use bouncycastle::modexp::rsa::rsasve::{RSASVE, RsaKEMPrivateKey, RsaKEMPublicKey};
use bouncycastle::modexp::rsa::size::{RsaSigningSize, RsaSize};
use bouncycastle::modexp::rsa::{RSA2048, RSA3072, RSA4096, RSA8192};
use bouncycastle::rng::HashDRBG_SHA512;
use clap::ValueEnum;
use std::process::exit;

/// The length of the key `encaps` draws and `decaps` expects.
const KEM_KEY_LEN: usize = 32;

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RSAOAEPAction {
    /// Generate a key-establishment key pair: the private key to stdout, the public key to
    /// `--pkfile`. The keys are rsasve's.
    Keygen,
    /// Draw a 32-byte key and transport it to the public key in `--pkfile` (or on stdin). With
    /// `--ctfile`, the ciphertext goes to that file and the key to stdout. Without it, the
    /// ciphertext and then the key go to stdout in hex, separated by a newline.
    Encaps,
    /// Recover the 32-byte key in the ciphertext in `--ctfile` (or on stdin) with the private
    /// key in `--skfile`, and write it to stdout.
    Decaps,
    /// Transport the key on stdin to the public key in `--pkfile`: the ciphertext to stdout,
    /// or to `--ctfile`.
    Transport,
    /// Recover the key in the ciphertext in `--ctfile` (or on stdin) with the private key in
    /// `--skfile`, whatever its length, and write it to stdout.
    Recover,
}

/// A hash for the label and for MGF1.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum RSAOAEPHash {
    /// For peers that use it; prefer SHA-256 or longer.
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    #[value(name = "sha512-224")]
    Sha512_224,
    #[value(name = "sha512-256")]
    Sha512_256,
}

/// What the command line gives a size's command.
pub(crate) struct OaepArgs<'a> {
    pub(crate) action: &'a RSAOAEPAction,
    pub(crate) hash: RSAOAEPHash,
    pub(crate) mgf_hash: Option<RSAOAEPHash>,
    pub(crate) label: &'a Option<String>,
    pub(crate) skfile: &'a Option<String>,
    pub(crate) pkfile: &'a Option<String>,
    pub(crate) ctfile: &'a Option<String>,
    pub(crate) output_hex: bool,
}

/// A file a flag must name.
fn required<'a>(file: &'a Option<String>, flag_name: &str) -> &'a str {
    match file {
        Some(f) => f,
        None => {
            eprintln!("Error: no {flag_name} provided.");
            exit(-1);
        }
    }
}

/// One size, label hash and MGF1 hash, per the action.
fn run<K, H, M, const N: usize, const PK_LEN: usize, const SK_LEN: usize>(
    args: &OaepArgs,
    alg_name: &str,
) where
    K: RsaSigningSize
        + RsaSize<
            Modulus = [u8; N],
            PublicKeyEncoded = [u8; PK_LEN],
            PrivateKeyEncoded = [u8; SK_LEN],
        >,
    H: OaepHash,
    M: OaepHash,
{
    let label = args.label.as_ref().map(|l| decode_hex_arg(l, "label")).unwrap_or_default();
    let params = OaepParams::<H, M, KEM_KEY_LEN>::new(&label);
    let load_pk = |bytes: Vec<u8>| {
        RsaKEMPublicKey::<K>::from_bytes(&bytes).unwrap_or_else(|e| {
            eprintln!(
                "Error: couldn't parse the input as a valid {alg_name} public key (must be \
                 exactly {PK_LEN} bytes): {e:?}"
            );
            exit(-1);
        })
    };
    // The key file's bytes go out of scope, and so are wiped, before a failure exits.
    let load_sk = || {
        let parsed = {
            let bytes = read_secret_file(required(args.skfile, "skfile"));
            RsaKEMPrivateKey::<K>::from_bytes(bytes.ref_to_bytes())
        };
        parsed.unwrap_or_else(|e| {
            eprintln!(
                "Error: couldn't parse the input as a valid {alg_name} private key (must be \
                 exactly {SK_LEN} bytes): {e:?}"
            );
            exit(-1);
        })
    };
    let load_ct = || {
        let ct = read_input_file_or_stdin(args.ctfile);
        <[u8; N]>::try_from(ct.as_slice()).unwrap_or_else(|_| {
            eprintln!(
                "Error: the ciphertext is {} bytes; an {alg_name} ciphertext is {N}.",
                ct.len()
            );
            exit(-1);
        })
    };

    match args.action {
        RSAOAEPAction::Keygen => {
            let pkfile = required(args.pkfile, "pkfile");
            let (pk, sk) =
                RSASVE::<K>::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap_or_else(|e| {
                    eprintln!("Error: {alg_name} key generation failed: {e:?}");
                    exit(-1);
                });
            let written = try_write_bytes_or_hex_to_file(&pk.encode(), pkfile, args.output_hex)
                .and_then(|()| write_private_key(&sk, args.output_hex).map_err(WriteError::from));
            // `exit` runs no destructors, so the key is dropped before a failed write exits.
            drop(sk);
            finish_stdout(written);
        }
        RSAOAEPAction::Encaps => {
            let pk = load_pk(read_input_file_or_stdin(args.pkfile));
            let (key, ct) =
                pk.encaps(&mut HashDRBG_SHA512::new_from_os(), params).unwrap_or_else(|e| {
                    eprintln!("Error: {alg_name} encapsulation failed: {e:?}");
                    exit(-1);
                });
            let written = match args.ctfile {
                Some(ctfile) => try_write_bytes_or_hex_to_file(&ct, ctfile, args.output_hex)
                    .and_then(|()| {
                        write_secret_bytes_or_hex(key.ref_to_bytes(), args.output_hex)
                            .map_err(WriteError::from)
                    }),
                None => try_write_bytes_or_hex(&ct, true)
                    .and_then(|()| try_write_stdout(b"\n"))
                    .and_then(|()| write_secret_bytes_or_hex(key.ref_to_bytes(), true))
                    .map_err(WriteError::from),
            };
            // `exit` runs no destructors, so the key is dropped before a failed write exits.
            drop(key);
            finish_stdout(written);
        }
        RSAOAEPAction::Decaps => {
            let ct = load_ct();
            // `exit` runs no destructors, so the key is dropped before the result is looked at.
            let key = {
                let sk = load_sk();
                sk.decaps(&ct, params)
            };
            let key = key.unwrap_or_else(|_| {
                eprintln!("Error: {alg_name} decryption failed.");
                exit(-1);
            });
            let written = write_secret_bytes_or_hex(key.ref_to_bytes(), args.output_hex);
            drop(key);
            finish_stdout(written);
        }
        RSAOAEPAction::Transport => {
            // stdin carries the key, so the public key must come from its file.
            let pk = load_pk(read_input_file(required(args.pkfile, "pkfile")));
            let ct = {
                let key = read_secret_stdin();
                pk.transport(&mut HashDRBG_SHA512::new_from_os(), params, &key)
            };
            let ct = ct.unwrap_or_else(|e| {
                eprintln!(
                    "Error: {alg_name} key transport failed (the key may be at most {} bytes): {e:?}",
                    pk.max_key_len(params)
                );
                exit(-1);
            });
            match args.ctfile {
                Some(ctfile) => write_bytes_or_hex_to_file(&ct, ctfile, args.output_hex),
                None => write_bytes_or_hex(&ct, args.output_hex),
            }
        }
        RSAOAEPAction::Recover => {
            let ct = load_ct();
            let mut key = KeyMaterial::<1024>::new();
            let result = {
                let sk = load_sk();
                sk.recover_out(&ct, params, &mut key)
            };
            if result.is_err() {
                eprintln!("Error: {alg_name} decryption failed.");
                exit(-1);
            }
            let written = write_secret_bytes_or_hex(key.ref_to_bytes(), args.output_hex);
            drop(key);
            finish_stdout(written);
        }
    }
}

/// The MGF1 hash.
fn with_mgf<K, H, const N: usize, const PK_LEN: usize, const SK_LEN: usize>(
    args: &OaepArgs,
    alg_name: &str,
) where
    K: RsaSigningSize
        + RsaSize<
            Modulus = [u8; N],
            PublicKeyEncoded = [u8; PK_LEN],
            PrivateKeyEncoded = [u8; SK_LEN],
        >,
    H: OaepHash,
{
    match args.mgf_hash.unwrap_or(args.hash) {
        RSAOAEPHash::Sha1 => run::<K, H, SHA1, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha224 => run::<K, H, SHA224, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha256 => run::<K, H, SHA256, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha384 => run::<K, H, SHA384, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha512 => run::<K, H, SHA512, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha512_224 => run::<K, H, SHA512_224, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha512_256 => run::<K, H, SHA512_256, N, PK_LEN, SK_LEN>(args, alg_name),
    }
}

/// The label hash.
fn with_hash<K, const N: usize, const PK_LEN: usize, const SK_LEN: usize>(
    args: &OaepArgs,
    alg_name: &str,
) where
    K: RsaSigningSize
        + RsaSize<
            Modulus = [u8; N],
            PublicKeyEncoded = [u8; PK_LEN],
            PrivateKeyEncoded = [u8; SK_LEN],
        >,
{
    match args.hash {
        RSAOAEPHash::Sha1 => with_mgf::<K, SHA1, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha224 => with_mgf::<K, SHA224, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha256 => with_mgf::<K, SHA256, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha384 => with_mgf::<K, SHA384, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha512 => with_mgf::<K, SHA512, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha512_224 => with_mgf::<K, SHA512_224, N, PK_LEN, SK_LEN>(args, alg_name),
        RSAOAEPHash::Sha512_256 => with_mgf::<K, SHA512_256, N, PK_LEN, SK_LEN>(args, alg_name),
    }
}

pub(crate) fn rsa_oaep_2048_cmd(args: &OaepArgs) {
    with_hash::<RSA2048, { RSA2048::K_LEN }, { RSA2048::PK_LEN }, { RSA2048::SK_LEN }>(
        args, "RSAES-OAEP-2048",
    );
}

pub(crate) fn rsa_oaep_3072_cmd(args: &OaepArgs) {
    with_hash::<RSA3072, { RSA3072::K_LEN }, { RSA3072::PK_LEN }, { RSA3072::SK_LEN }>(
        args, "RSAES-OAEP-3072",
    );
}

pub(crate) fn rsa_oaep_4096_cmd(args: &OaepArgs) {
    with_hash::<RSA4096, { RSA4096::K_LEN }, { RSA4096::PK_LEN }, { RSA4096::SK_LEN }>(
        args, "RSAES-OAEP-4096",
    );
}

pub(crate) fn rsa_oaep_8192_cmd(args: &OaepArgs) {
    with_hash::<RSA8192, { RSA8192::K_LEN }, { RSA8192::PK_LEN }, { RSA8192::SK_LEN }>(
        args, "RSAES-OAEP-8192",
    );
}
