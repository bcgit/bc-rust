//! `encaps` and `decaps` for a KEM whose keys take no parameters: the two actions of the DHKEM
//! commands (`x25519`, `eccdh-p256` and its siblings), written once over the key roles.

use crate::helpers::{
    read_input_file_or_stdin, read_secret_file, write_bytes_or_hex, write_bytes_or_hex_to_file,
    write_secret_bytes_or_hex, write_stdout,
};
use bouncycastle::core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::traits::{PrivateKey, PublicKey};
use bouncycastle::rng::HashDRBG_SHA512;
use std::process::exit;

/// Encapsulation against the public key in `--pkfile` or on stdin. With `--ctfile` the
/// ciphertext goes to the file and the shared secret to stdout; without it both go to stdout in
/// hex, the ciphertext first, separated by a newline.
pub(crate) fn encaps_cmd<PK, const PK_LEN: usize, const CT_LEN: usize, const SS_LEN: usize>(
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
    alg_name: &str,
) where
    PK: PublicKey<PK_LEN> + EncapsulatingKey<(), CT_LEN, SS_LEN>,
{
    let pk = PK::from_bytes(&read_input_file_or_stdin(pkfile)).unwrap_or_else(|_| {
        eprintln!("Error: couldn't parse the input as a valid {alg_name} public key.");
        exit(-1);
    });
    let (ss, ct) = pk.encaps(&mut HashDRBG_SHA512::new_from_os(), ()).unwrap_or_else(|e| {
        eprintln!("Error: encapsulation failed: {e:?}");
        exit(-1);
    });
    if let Some(ctfile) = ctfile {
        write_bytes_or_hex_to_file(&ct, ctfile, output_hex);
        write_secret_bytes_or_hex(ss.ref_to_bytes(), output_hex);
    } else {
        write_bytes_or_hex(&ct, true);
        write_stdout(b"\n");
        write_secret_bytes_or_hex(ss.ref_to_bytes(), true);
    }
}

/// Decapsulation of the ciphertext in `--ctfile` or on stdin with the private key in
/// `--skfile`; the shared secret goes to stdout.
pub(crate) fn decaps_cmd<SK, const SK_LEN: usize, const CT_LEN: usize, const SS_LEN: usize>(
    skfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
    alg_name: &str,
) where
    SK: PrivateKey<SK_LEN> + DecapsulatingKey<(), CT_LEN, SS_LEN>,
{
    let Some(skfile) = skfile else {
        eprintln!("Error: no skfile provided.");
        exit(-1);
    };
    // The ciphertext is checked before the private key is read.
    let ct = read_input_file_or_stdin(ctfile);
    let Ok(ct) = <[u8; CT_LEN]>::try_from(ct.as_slice()) else {
        eprintln!("Error: ciphertext is not the correct length.");
        exit(-1);
    };
    // `exit` runs no destructors, so the key file's bytes and the key are dropped, and so
    // wiped, before either result is looked at.
    let ss = {
        let sk = {
            let bytes = read_secret_file(skfile);
            SK::from_bytes(bytes.ref_to_bytes())
        };
        sk.as_ref().map(|sk| sk.decaps(&ct, ())).map_err(|_| ())
    };
    let ss = ss.unwrap_or_else(|_| {
        eprintln!("Error: couldn't parse the input as a valid {alg_name} private key.");
        exit(-1);
    });
    let ss = ss.unwrap_or_else(|e| {
        eprintln!("Error: decapsulation failed: {e:?}");
        exit(-1);
    });
    write_secret_bytes_or_hex(ss.ref_to_bytes(), output_hex);
}
