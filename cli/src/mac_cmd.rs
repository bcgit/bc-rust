//! The MAC subcommands: `hmac-*`, `kmac*` and `kmacxof*`, `aes*-cmac` and `aes*-gmac`, and
//! `poly1305`. A MAC over stdin, computed or verified.

use crate::helpers::block_mode_helpers::{load_iv, load_key_object_typed};
use crate::helpers::{
    SecretBytes, decode_hex_arg, load_mac_key, stream_stdin, stream_xof, write_bytes_or_hex,
    write_stdout,
};
use crate::sha3_cmd::{MAX_FIXED_OUTPUT_LEN, Strength};
use bouncycastle::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle::cipher::modes::{CMAC, GMAC};
use bouncycastle::core::errors::MACError;
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::core::symmetric_key::{
    FromAnyKeyMaterial, FromKeyMaterial, MacGenerationKey, MacVerificationKey,
    NonceMacGenerationKey, NonceMacVerificationKey,
};
use bouncycastle::core::traits::{MACGenerator, MACVerifier, XOF, XOFSqueezer};
use bouncycastle::hmac::{HMACParams, HmacKey};
use bouncycastle::poly1305;
use bouncycastle::poly1305::hazmat::key_from_bytes;
use bouncycastle::rng::HashDRBG_SHA512;
use bouncycastle::sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle::sha3::kmac::{KMAC_MAX_OUTPUT_LEN, KMAC_MIN_OUTPUT_LEN, KMACXOF128, KMACXOF256};
use bouncycastle::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use bouncycastle::sm3::SM3;
use bouncycastle_utils::ct::ct_eq_bytes;
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

fn mac_key_error(e: MACError) -> ! {
    eprintln!("Error: couldn't build the MAC key: {e:?}");
    exit(-1)
}

/// HMAC over `H`, whose tags are `N` bytes, with the allow-weak key form, as every `hmac-*`
/// command uses: a CLI is used for test vectors and scripting, where a short or all-zero key is a
/// legitimate thing to want.
fn hmac<const N: usize, H>(key: &SecretBytes, verify_val: &Option<String>, output_hex: bool)
where
    H: HMACParams<MACKey = KeyMaterial<N>>,
{
    let hmac_key =
        HmacKey::<H>::from_key_material_allow_weak(key).unwrap_or_else(|e| mac_key_error(e));
    do_mac_with_key(&hmac_key, verify_val, output_hex);
}

pub(crate) fn mac_cmd(
    hmac_variant: HMACVariant,
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key = load_mac_key(key, key_file, None);
    match hmac_variant {
        HMACVariant::SHA224 => hmac::<28, SHA224>(&key, verify_val, output_hex),
        HMACVariant::SHA256 => hmac::<32, SHA256>(&key, verify_val, output_hex),
        HMACVariant::SHA384 => hmac::<48, SHA384>(&key, verify_val, output_hex),
        HMACVariant::SHA512 => hmac::<64, SHA512>(&key, verify_val, output_hex),
        HMACVariant::SHA512_224 => hmac::<28, SHA512_224>(&key, verify_val, output_hex),
        HMACVariant::SHA512_256 => hmac::<32, SHA512_256>(&key, verify_val, output_hex),
        HMACVariant::SHA3_224 => hmac::<28, SHA3_224>(&key, verify_val, output_hex),
        HMACVariant::SHA3_256 => hmac::<32, SHA3_256>(&key, verify_val, output_hex),
        HMACVariant::SHA3_384 => hmac::<48, SHA3_384>(&key, verify_val, output_hex),
        HMACVariant::SHA3_512 => hmac::<64, SHA3_512>(&key, verify_val, output_hex),
        HMACVariant::SM3 => hmac::<32, SM3>(&key, verify_val, output_hex),
    }
}

/// KMAC (NIST SP 800-185 Sec 4), which unlike HMAC takes a customization string and a caller-
/// chosen tag length -- both are bound into the computation, so the verifier must use the same.
///
/// The library's KMAC key types carry the tag length as a const parameter, which a command-line
/// argument cannot name, so the command runs KMACXOF and binds the length at its final read:
/// SP 800-185 Sec 4.3.1 differs from Sec 4.3 only in the `right_encode` the final read absorbs,
/// so `KMACXOF`'s final read of `L` bytes is `KMAC(K, X, 8L, S)` exactly, which the sha3 crate's
/// sample-value tests pin against the published vectors.
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
    if !(KMAC_MIN_OUTPUT_LEN..=KMAC_MAX_OUTPUT_LEN).contains(&length) {
        eprintln!(
            "Error: a KMAC tag is from {KMAC_MIN_OUTPUT_LEN} bytes (SP 800-185 Sec 8.4.2) to {KMAC_MAX_OUTPUT_LEN}, got {length}."
        );
        exit(-1);
    }
    let key = load_mac_key(key, key_file, None);
    match strength {
        Strength::Bits128 => {
            let x = KMACXOF128::new(&key, customization, true).unwrap_or_else(|e| mac_key_error(e));
            kmac_run(x, length, verify_val, output_hex)
        }
        Strength::Bits256 => {
            let x = KMACXOF256::new(&key, customization, true).unwrap_or_else(|e| mac_key_error(e));
            kmac_run(x, length, verify_val, output_hex)
        }
    }
}

/// Streams stdin into `kmac` and binds `length` at the final read, then writes the tag or
/// verifies `--verify` against it in constant time, reporting through the exit status and an
/// `Error:` line as [`do_mac`] does; as there, a `--verify` of the wrong length is refused before
/// any input is read.
fn kmac_run(mut kmac: impl XOF, length: usize, verify_val: &Option<String>, output_hex: bool) {
    let expected = verify_val.as_ref().map(|verify_val| {
        let expected = decode_hex_arg(verify_val, "verify");
        if expected.len() != length {
            eprintln!("Error: the MAC must be {length} bytes, got {}.", expected.len());
            exit(-1)
        }
        expected
    });
    stream_stdin(|chunk| kmac.do_update(chunk));
    let mut tag = vec![0u8; length];
    kmac.into_squeezer().do_output_final_out(&mut tag);
    match expected {
        None => {
            write_bytes_or_hex(&tag, output_hex);
            write_stdout(b"\n");
        }
        Some(expected) => {
            if ct_eq_bytes(&expected, &tag) {
                exit(0)
            }
            eprintln!("Error: MAC verification failed.");
            exit(-1)
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
    let key = load_mac_key(key, key_file, None);
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
pub(crate) fn cmac_cmd<K, const KEY_LEN: usize>(
    alg: &str,
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) where
    K: FromKeyMaterial<KEY_LEN> + MacGenerationKey<16> + MacVerificationKey<16>,
{
    let key: K = load_key_object_typed(key, key_file, alg, KeyType::MACKey);
    do_mac_with_key(&key, verify_val, output_hex);
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
fn gmac_run<K>(
    key: &K,
    iv: Option<[u8; GMAC_NONCE_LEN]>,
    verify_val: &Option<String>,
    output_hex: bool,
) where
    K: NonceMacGenerationKey<GMAC_NONCE_LEN, GMAC_TAG_LEN>
        + NonceMacVerificationKey<GMAC_NONCE_LEN, GMAC_TAG_LEN>,
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
            if mac.do_verify_final(tag).is_ok() {
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

/// Poly1305 (RFC 8439 Sec 2.5) under a 32-byte one-time key, which must never MAC a second
/// message. The tag is always the full 16 bytes.
pub(crate) fn poly1305_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key = load_mac_key(key, key_file, None);
    // No key policy, as the other MAC commands take their allow-weak forms: a CLI is used for test
    // vectors and scripting, where a weak or all-zero key is a legitimate thing to want.
    let Ok(bytes) = <&[u8; poly1305::KEY_LEN]>::try_from(key.ref_to_bytes()) else {
        eprintln!("Error: Poly1305 needs a 32-byte one-time key, got {} bytes.", key.key_len());
        exit(-1)
    };
    // One key, one worker: whichever direction the command runs makes the one worker.
    do_mac(
        || key_from_bytes(bytes).into_generator(),
        || key_from_bytes(bytes).into_verifier(),
        verify_val,
        output_hex,
    );
}

/// [`do_mac`] over the workers a reusable MAC key hands out.
pub(crate) fn do_mac_with_key<const N: usize, K>(
    key: &K,
    verify_val: &Option<String>,
    output_hex: bool,
) where
    K: MacGenerationKey<N> + MacVerificationKey<N>,
{
    do_mac(|| key.create_generator(), || key.create_verifier(), verify_val, output_hex)
}

/// Streams stdin into a generator and writes the tag, or into a verifier and checks `--verify`
/// against it, reporting the outcome through the exit status (0 verified, 255 not) and an
/// `Error:` line. Only the direction the command runs is made.
pub(crate) fn do_mac<const N: usize, G: MACGenerator<N>, V: MACVerifier<N>>(
    make_generator: impl FnOnce() -> G,
    make_verifier: impl FnOnce() -> V,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    match verify_val {
        None => {
            let mut mac = make_generator();
            stream_stdin(|chunk| mac.do_update(chunk));
            write_bytes_or_hex(&mac.do_final(), output_hex);
            write_stdout(b"\n");
        }
        Some(verify_val) => {
            let expected = decode_hex_arg(verify_val, "verify");
            let Ok(expected) = <&[u8; N]>::try_from(expected.as_slice()) else {
                eprintln!("Error: the MAC must be {N} bytes, got {}.", expected.len());
                exit(-1)
            };
            let mut mac = make_verifier();
            stream_stdin(|chunk| mac.do_update(chunk));
            if mac.do_verify_final(expected).is_ok() {
                exit(0)
            }
            eprintln!("Error: MAC verification failed.");
            exit(-1)
        }
    }
}
