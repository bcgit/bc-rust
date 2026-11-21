//! Tests for the `aes128-xts` and `aes256-xts` subcommands: the library's answer at every offered
//! data-unit length, and an OpenSSL known answer, through the command; consecutive tweaks across
//! data units, including a carry; the refusals of partial data units, a wrapping tweak and bad
//! arguments; and the help listing.

mod common;
use bouncycastle::aes::{XTS_AES_128, XTS_AES_256};
use common::{
    KEY32, key_object, listed_in_help, pseudo_random, run, run_err_silent, run_ok, unhex,
};

/// `Key_1 | Key_2` for XTS-AES-256: counting bytes, whose halves differ. XTS-AES-128 takes
/// [`KEY32`].
const KEY64: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                     202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

const TWEAK: &str = "f0e1d2c3b4a5968778695a4b3c2d1e0f";

/// The library's answer for `data` as consecutive `N`-byte data units from the tweak `first`.
fn library_128<const N: usize>(key: &str, first: &str, data: &[u8], encrypt: bool) -> Vec<u8> {
    let key: XTS_AES_128<N> = key_object::<32, _>(key);
    let first = u128::from_le_bytes(unhex(first).try_into().unwrap());
    let mut out = data.to_vec();
    for (n, unit) in (first..).zip(out.as_chunks_mut::<N>().0) {
        if encrypt {
            key.encrypt_inplace(&n.to_le_bytes(), unit);
        } else {
            key.decrypt_inplace(&n.to_le_bytes(), unit);
        }
    }
    out
}

/// As [`library_128`], for XTS-AES-256.
fn library_256<const N: usize>(key: &str, first: &str, data: &[u8], encrypt: bool) -> Vec<u8> {
    let key: XTS_AES_256<N> = key_object::<64, _>(key);
    let first = u128::from_le_bytes(unhex(first).try_into().unwrap());
    let mut out = data.to_vec();
    for (n, unit) in (first..).zip(out.as_chunks_mut::<N>().0) {
        if encrypt {
            key.encrypt_inplace(&n.to_le_bytes(), unit);
        } else {
            key.decrypt_inplace(&n.to_le_bytes(), unit);
        }
    }
    out
}

/// The arguments of `cmd` in `direction` under `key`, from `tweak`, in `len`-byte data units.
fn xts(cmd: &str, direction: &str, key: &str, tweak: &str, len: usize) -> Vec<String> {
    let len = len.to_string();
    [cmd, "-d", direction, "--key", key, "--tweak", tweak, "--data-unit-len", &len]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn args(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// Three data units through `cmd`, both directions, against the library's `expected`.
fn agrees(cmd: &str, key: &str, len: usize, data: &[u8], expected: &[u8]) {
    let ct = run_ok(&args(&xts(cmd, "encrypt", key, TWEAK, len)), data);
    assert_eq!(ct, expected, "{cmd} at {len}: encrypt");
    let mut hex_args = xts(cmd, "encrypt", key, TWEAK, len);
    hex_args.push("-x".to_string());
    let hex = run_ok(&args(&hex_args), data);
    assert_eq!(unhex(String::from_utf8_lossy(&hex).trim()), expected, "{cmd} at {len}: -x");
    let pt = run_ok(&args(&xts(cmd, "decrypt", key, TWEAK, len)), &ct);
    assert_eq!(pt, data, "{cmd} at {len}: decrypt");
}

#[test]
fn the_commands_agree_with_the_library_at_every_data_unit_length() {
    for len in [512, 1024, 2048, 4096] {
        let data = pseudo_random(3 * len, len as u32);
        let expected = match len {
            512 => library_128::<512>(KEY32, TWEAK, &data, true),
            1024 => library_128::<1024>(KEY32, TWEAK, &data, true),
            2048 => library_128::<2048>(KEY32, TWEAK, &data, true),
            _ => library_128::<4096>(KEY32, TWEAK, &data, true),
        };
        agrees("aes128-xts", KEY32, len, &data, &expected);
    }
    for len in [512, 4096] {
        let data = pseudo_random(3 * len, len as u32 + 1);
        let expected = match len {
            512 => library_256::<512>(KEY64, TWEAK, &data, true),
            _ => library_256::<4096>(KEY64, TWEAK, &data, true),
        };
        agrees("aes256-xts", KEY64, len, &data, &expected);
        assert_eq!(
            match len {
                512 => library_256::<512>(KEY64, TWEAK, &expected, false),
                _ => library_256::<4096>(KEY64, TWEAK, &expected, false),
            },
            data
        );
    }
}

/// A 512-byte data unit whose byte k is k mod 251, under the key 01 02 .. and `TWEAK`, against
/// OpenSSL 3.5.0: the first block and the last 32 bytes of the known answers in
/// `crypto/aes/tests/xts_tests.rs`, through the commands.
#[test]
fn an_openssl_known_answer_through_the_commands() {
    let pt: Vec<u8> = (0..512).map(|k| (k % 251) as u8).collect();
    let key_128: String = (1..=32u8).map(|b| format!("{b:02x}")).collect();
    let key_256: String = (1..=64u8).map(|b| format!("{b:02x}")).collect();

    let ct = run_ok(&args(&xts("aes128-xts", "encrypt", &key_128, TWEAK, 512)), &pt);
    assert_eq!(ct[..16], unhex("b9606f8b4bcb9a6990a511c8e0b07aa6"));
    assert_eq!(
        ct[480..],
        unhex("f47d6467859b134958f1504d4f19524687d16d4fe39d8f3c3c812695dcfbd91e")
    );
    assert_eq!(run_ok(&args(&xts("aes128-xts", "decrypt", &key_128, TWEAK, 512)), &ct), pt);

    let ct = run_ok(&args(&xts("aes256-xts", "encrypt", &key_256, TWEAK, 512)), &pt);
    assert_eq!(ct[..16], unhex("965c8f85ac79930ac1e8b46eb069dbe9"));
    assert_eq!(
        ct[480..],
        unhex("61102f0e9dbdcdd4821d60f2b3ea839cff6330cee358a6b8e3d8376df070295e")
    );
    assert_eq!(run_ok(&args(&xts("aes256-xts", "decrypt", &key_256, TWEAK, 512)), &ct), pt);
}

/// The second data unit is processed under the first one's tweak plus one, as a little-endian
/// integer: from 255 (`ff 00 ..`) to 256 (`00 01 00 ..`), a carry into the second byte.
#[test]
fn consecutive_data_units_take_consecutive_tweaks() {
    let data = pseudo_random(2 * 512, 7);
    let both = run_ok(
        &args(&xts("aes128-xts", "encrypt", KEY32, "ff000000000000000000000000000000", 512)),
        &data,
    );
    let second = run_ok(
        &args(&xts("aes128-xts", "encrypt", KEY32, "00010000000000000000000000000000", 512)),
        &data[512..],
    );
    assert_eq!(both[512..], second[..]);
    assert_eq!(both, library_128::<512>(KEY32, "ff000000000000000000000000000000", &data, true));
}

/// Input that is not a whole number of data units is refused; the whole ones before the
/// remainder have already been written, as the command streams.
#[test]
fn the_input_must_be_a_whole_number_of_data_units() {
    let out = run(&args(&xts("aes128-xts", "encrypt", KEY32, TWEAK, 512)), &[0x42; 512 + 100]);
    assert!(!out.status.success());
    assert_eq!(out.stdout.len(), 512, "the first data unit is written before the refusal");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("whole number of 512-byte data units"), "stderr: {err}");
    assert!(err.contains("100 trailing byte(s)"), "stderr: {err}");

    let err = run_err_silent(&args(&xts("aes256-xts", "decrypt", KEY64, TWEAK, 4096)), &[1; 15]);
    assert!(err.contains("whole number of 4096-byte data units"), "stderr: {err}");

    // No input is no data units: nothing to do, and nothing written.
    assert!(run_ok(&args(&xts("aes128-xts", "encrypt", KEY32, TWEAK, 512)), &[]).is_empty());
}

/// The tweak is not allowed to wrap from 2^128 - 1 to 0, where it could repeat one in use.
#[test]
fn the_tweak_does_not_wrap() {
    let out = run(
        &args(&xts("aes128-xts", "encrypt", KEY32, "ffffffffffffffffffffffffffffffff", 512)),
        &[0x42; 2 * 512],
    );
    assert!(!out.status.success());
    assert_eq!(out.stdout.len(), 512, "the first data unit is written before the refusal");
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot go past 2^128 - 1"));
}

/// A wrong key length, equal key halves, a malformed tweak and an unsupported data-unit length
/// are all refused before anything is written.
#[test]
fn bad_arguments_are_refused() {
    let short_key = &KEY32[..62];
    let equal_halves = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let cases: [(&str, &str, &str, usize, &str); 6] = [
        ("aes128-xts", short_key, TWEAK, 512, "needs a 32-byte key"),
        ("aes256-xts", KEY32, TWEAK, 512, "needs a 64-byte key"),
        ("aes128-xts", equal_halves, TWEAK, 512, "Key_1 != Key_2"),
        ("aes128-xts", KEY32, &TWEAK[..30], 512, "the tweak is 15 bytes"),
        ("aes128-xts", KEY32, "not hex", 512, "`--tweak` must be hex"),
        ("aes256-xts", KEY64, TWEAK, 1000, "--data-unit-len must be 512, 1024, 2048 or 4096"),
    ];
    for (cmd, key, tweak, len, msg) in cases {
        let err = run_err_silent(&args(&xts(cmd, "encrypt", key, tweak, len)), &[0x42; 512]);
        assert!(err.contains(msg), "{cmd} {key} {tweak} {len}: stderr was: {err}");
    }
}

#[test]
fn the_commands_are_listed_in_help() {
    listed_in_help(&["aes128-xts", "aes256-xts"]);
}
