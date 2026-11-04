//! The MAC subcommands: `hmac-*`, `kmac*` and `kmacxof*`, `aes*-cmac` and `aes*-gmac`. A MAC
//! over stdin, computed or verified.

use crate::helpers::block_mode_helpers::{load_iv, load_key_object_typed};
use crate::helpers::{
    SecretBytes, decode_hex_arg, load_secret, stream_stdin, stream_xof, write_bytes_or_hex,
    write_stdout,
};
use crate::sha3_cmd::{MAX_FIXED_OUTPUT_LEN, Strength};
use bouncycastle::aes::hazmat::AESInternal;
use bouncycastle::aes::{AES128Key, AES192Key, AES256Key, AESKey, AESParams};
use bouncycastle::cipher::modes::{CMAC, GMAC, ModeNames};
use bouncycastle::core::errors::MACError;
use bouncycastle::core::hazmat::{BlockPermutation, do_hazardous_operations};
use bouncycastle::core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle::core::symmetric_key::{FromAnyKeyMaterial, FromKeyMaterial, MacGenerationKey};
use bouncycastle::core::traits::MAC;
use bouncycastle::hmac::HmacKey;
use bouncycastle::rng::HashDRBG_SHA512;
use bouncycastle::sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle::sha3::kmac::{KMAC128Key, KMAC256Key, KMACXOF128, KMACXOF256};
use bouncycastle::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use bouncycastle::sm3::SM3;
use std::process::exit;

#[allow(non_camel_case_types)]
pub(crate) enum HMACVariant {
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SM3,
}

/// The MAC key from `--key-file` or `--key`, tagged as a MAC key. Any length the secret buffer
/// holds is accepted: HMAC hashes a key longer than its block (RFC 2104 Section 2), and KMAC
/// encodes the key's length (SP 800-185 Section 4.2).
fn load_mac_key(key: &Option<String>, key_file: &Option<String>) -> SecretBytes {
    let mut key = load_secret(key, key_file, "key");
    if key.key_type() == KeyType::Zeroized {
        // Same stance as the cipher loaders: warn, then do what was asked. A CLI is used for
        // test vectors and scripting, where an all-zero key is a legitimate thing to want.
        eprintln!(
            "Warning: all-zero (or otherwise zeroized) key provided. Proceeding, but this is not secure."
        );
    }
    do_hazardous_operations(&mut key, |key| key.set_key_type(KeyType::MACKey)).unwrap_or_else(
        |e| {
            eprintln!("Error: couldn't load the key: {e:?}");
            exit(-1);
        },
    );
    key
}

fn mac_key_error(e: MACError) -> ! {
    eprintln!("Error: couldn't build the MAC key: {e:?}");
    exit(-1)
}

/// HMAC over `H` with the allow-weak key form, as every `hmac-*` command uses: a CLI is used for
/// test vectors and scripting, where a short or all-zero key is a legitimate thing to want.
fn hmac<H: bouncycastle::hmac::HMACParams>(
    key: &SecretBytes,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let hmac_key =
        HmacKey::<H>::from_key_material_allow_weak(key).unwrap_or_else(|e| mac_key_error(e));
    do_mac(hmac_key.create_generator(), verify_val, output_hex);
}

pub(crate) fn mac_cmd(
    hmac_variant: HMACVariant,
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key = load_mac_key(key, key_file);
    match hmac_variant {
        HMACVariant::SHA224 => hmac::<SHA224>(&key, verify_val, output_hex),
        HMACVariant::SHA256 => hmac::<SHA256>(&key, verify_val, output_hex),
        HMACVariant::SHA384 => hmac::<SHA384>(&key, verify_val, output_hex),
        HMACVariant::SHA512 => hmac::<SHA512>(&key, verify_val, output_hex),
        HMACVariant::SHA512_224 => hmac::<SHA512_224>(&key, verify_val, output_hex),
        HMACVariant::SHA512_256 => hmac::<SHA512_256>(&key, verify_val, output_hex),
        HMACVariant::SHA3_224 => hmac::<SHA3_224>(&key, verify_val, output_hex),
        HMACVariant::SHA3_256 => hmac::<SHA3_256>(&key, verify_val, output_hex),
        HMACVariant::SHA3_384 => hmac::<SHA3_384>(&key, verify_val, output_hex),
        HMACVariant::SHA3_512 => hmac::<SHA3_512>(&key, verify_val, output_hex),
        HMACVariant::SM3 => hmac::<SM3>(&key, verify_val, output_hex),
    }
}

/// KMAC (NIST SP 800-185 Sec 4), which unlike HMAC takes a customization string and a caller-
/// chosen tag length -- both are bound into the computation, so the verifier must use the same.
pub(crate) fn kmac_cmd(
    strength: Strength,
    length: usize,
    customization: &[u8],
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    if length > MAX_FIXED_OUTPUT_LEN {
        eprintln!(
            "Error: a KMAC tag is computed whole; this command takes at most {MAX_FIXED_OUTPUT_LEN} bytes. Use kmacxof* for a long, streamed output."
        );
        exit(-1);
    }
    let key = load_mac_key(key, key_file);
    match strength {
        Strength::Bits128 => {
            let kmac_key = KMAC128Key::with_params_allow_weak(&key, customization, length)
                .unwrap_or_else(|e| mac_key_error(e));
            do_mac(kmac_key.create_generator(), verify_val, output_hex)
        }
        Strength::Bits256 => {
            let kmac_key = KMAC256Key::with_params_allow_weak(&key, customization, length)
                .unwrap_or_else(|e| mac_key_error(e));
            do_mac(kmac_key.create_generator(), verify_val, output_hex)
        }
    }
}

/// KMACXOF (SP 800-185 Sec 4.3.1): KMAC with the length not bound in, so the output is a
/// stream of any length. There is nothing to verify against: a reader squeezes the same stream.
pub(crate) fn kmacxof_cmd(
    strength: Strength,
    output_len: usize,
    customization: &[u8],
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_mac_key(key, key_file);
    match strength {
        Strength::Bits128 => {
            let x = KMACXOF128::new(&key, customization, true).unwrap_or_else(|e| mac_key_error(e));
            stream_xof(x, output_len, output_hex);
        }
        Strength::Bits256 => {
            let x = KMACXOF256::new(&key, customization, true).unwrap_or_else(|e| mac_key_error(e));
            stream_xof(x, output_len, output_hex);
        }
    }
}

/// AES-CMAC (NIST SP 800-38B) under the key the command's length selects.
pub(crate) fn cmac_cmd<K: FromKeyMaterial<KEY_LEN> + MacGenerationKey, const KEY_LEN: usize>(
    alg: &str,
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key: K = load_key_object_typed(key, key_file, alg, KeyType::MACKey);
    do_mac(key.create_generator(), verify_val, output_hex);
}

pub(crate) fn aes128_cmac_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    cmac_cmd::<AES128Key<CMAC>, 16>("AES-128", key, key_file, verify_val, output_hex);
}

pub(crate) fn aes192_cmac_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    cmac_cmd::<AES192Key<CMAC>, 24>("AES-192", key, key_file, verify_val, output_hex);
}

pub(crate) fn aes256_cmac_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    cmac_cmd::<AES256Key<CMAC>, 32>("AES-256", key, key_file, verify_val, output_hex);
}

/// The GMAC nonce length: GCM's 12 bytes (SP 800-38D Sec 5.2.1.1's recommended IV length).
const GMAC_NONCE_LEN: usize = 12;
/// The GMAC tag length the `aes*-gmac` commands fix, as `aes*-gcm` do: the full 128 bits.
const GMAC_TAG_LEN: usize = 16;

/// AES-GMAC (NIST SP 800-38D Sec 5.2): a GCM tag over the data as AAD. A tag is bound to a
/// nonce, so the shape is the MAC commands' with the IV flags of `aes*-gcm` added. Without
/// `--iv` the nonce is drawn from the OS-backed DRBG and written ahead of the tag, so the
/// output is `nonce || tag` and a reader has what it needs; with `--iv` only the tag is
/// written. `--verify` takes the tag, with `--iv`, or the 28-byte `nonce || tag` without it.
///
/// The GMAC workers have no trait: their generator and verifier are inherent on the key, so
/// this is generic over the AES parameter set the way the key's own impl is.
fn gmac_run<P: AESParams>(
    key: &AESKey<P, GMAC<GMAC_TAG_LEN>>,
    iv: Option<[u8; GMAC_NONCE_LEN]>,
    verify_val: &Option<String>,
    output_hex: bool,
) where
    AESInternal<P>: BlockPermutation<16> + ModeNames + Clone,
{
    match verify_val {
        None => {
            let (mut mac, generated) = match iv {
                Some(iv) => (key.create_generator_nonce(&iv), None),
                None => key
                    .create_generator(&mut HashDRBG_SHA512::new_from_os())
                    .map(|(mac, nonce)| (mac, Some(nonce)))
                    .unwrap_or_else(|e| {
                        eprintln!("Error: couldn't draw the nonce: {e:?}");
                        exit(-1);
                    }),
            };
            stream_stdin(|chunk| mac.do_update(chunk));
            let tag = mac.do_final();
            if let Some(nonce) = generated {
                write_bytes_or_hex(&nonce, output_hex);
            }
            write_bytes_or_hex(&tag, output_hex);
            write_stdout(b"\n");
        }
        Some(verify_val) => {
            let given = decode_hex_arg(verify_val, "verify");
            let (nonce, tag): ([u8; GMAC_NONCE_LEN], &[u8]) = match iv {
                Some(iv) => (iv, &given),
                None => {
                    if given.len() != GMAC_NONCE_LEN + GMAC_TAG_LEN {
                        eprintln!(
                            "Error: without --iv, --verify takes the {GMAC_NONCE_LEN}-byte nonce followed by the {GMAC_TAG_LEN}-byte tag."
                        );
                        exit(-1);
                    }
                    let (nonce, tag) = given.split_at(GMAC_NONCE_LEN);
                    (nonce.try_into().expect("split at the nonce length"), tag)
                }
            };
            let tag: &[u8; GMAC_TAG_LEN] = tag.try_into().unwrap_or_else(|_| {
                eprintln!("Error: the tag must be {GMAC_TAG_LEN} bytes, got {}.", tag.len());
                exit(-1);
            });
            let mut mac = key.create_verifier(&nonce);
            stream_stdin(|chunk| mac.do_update(chunk));
            if mac.do_verify_final(tag) {
                exit(0)
            }
            eprintln!("Error: MAC verification failed.");
            exit(-1)
        }
    }
}

pub(crate) fn aes128_gmac_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key: AES128Key<GMAC> = load_key_object_typed(key, key_file, "AES-128", KeyType::MACKey);
    gmac_run(&key, load_iv::<GMAC_NONCE_LEN>(iv, iv_file), verify_val, output_hex);
}

pub(crate) fn aes192_gmac_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key: AES192Key<GMAC> = load_key_object_typed(key, key_file, "AES-192", KeyType::MACKey);
    gmac_run(&key, load_iv::<GMAC_NONCE_LEN>(iv, iv_file), verify_val, output_hex);
}

pub(crate) fn aes256_gmac_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key: AES256Key<GMAC> = load_key_object_typed(key, key_file, "AES-256", KeyType::MACKey);
    gmac_run(&key, load_iv::<GMAC_NONCE_LEN>(iv, iv_file), verify_val, output_hex);
}

/// Streams stdin into `mac`, then writes the tag, or verifies `--verify` against it and reports
/// the outcome through the exit status (0 verified, 255 not) and an `Error:` line.
pub(crate) fn do_mac(mut mac: impl MAC, verify_val: &Option<String>, output_hex: bool) {
    stream_stdin(|chunk| mac.do_update(chunk));

    match verify_val {
        None => {
            let out = mac.do_final();
            write_bytes_or_hex(&out, output_hex);
            write_stdout(b"\n");
        }
        Some(verify_val) => {
            let expected = decode_hex_arg(verify_val, "verify");
            if mac.do_verify_final(&expected) {
                exit(0)
            }
            eprintln!("Error: MAC verification failed.");
            exit(-1)
        }
    }
}
