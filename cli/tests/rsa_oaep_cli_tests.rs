//! Tests for the `rsa-oaep-2048` .. `rsa-oaep-8192` subcommands, driving the built `bc-rust`
//! binary as a subprocess with the harness in `common`. The known answers are three cases of
//! Wycheproof's `rsa_oaep_2048_sha256_mgf1sha256_test.json` under that file's key, which pin
//! `recover`; `transport`, `encaps` and `decaps` are checked against it and each other.

mod common;
use common::{BC_RUST, run_err, run_ok, tohex, unhex};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The RSA-2048 key of Wycheproof's `rsa_oaep_2048_sha256_mgf1sha256_test.json`, in the CLI's
/// `p || q || dP || dQ || qInv || e` key-file layout, hex.
const SK_HEX: &str = concat!(
    "dc431050f782e894fb5248247d98cb7d58b8d1e24f3b55d041c56e4de086b0d5",
    "bb028bda42eeb5d234d5681e5809d415e6a289ad4cfbf78f978f6c35814f50ee",
    "bff1c5b80a69f788e81e6bab5ddaa78369d659d143ec6f17e79813a575cfad9c",
    "569156b90113e2e9110ad9e7b48a1c9348a6e653321191290ea36cfb3a5b18f1",
    "bd1a81e7977f9898122273ae3222b598ea5fb19eb4eabc38308a5e32196603b2",
    "e500ffb79f5b886816611debc472fac45544070beb057c941378a6868af3b7a0",
    "3d3f9880ec47d5e089b94fbde542aba9ae8d72c57088d7abf5b131f39098f7bc",
    "160f90536abc9492fd4e06f3ed7299d4b97bb03677207d95669f140cfbc20f25",
    "a94b528b28f291599121d91952ffd1c7f21d7c1479d99d478885fb161870ee12",
    "18bf08472612dbe5497e8d9c650688e09c786961ae3e2c354dc48ae34514759c",
    "4c23c4588488961dc06b414e61c0e1e7fbbd2923d31532fe289f96da220711e5",
    "8c14019808e00414276933bb07e4efb9b4a9b37656917205209f33f09515d7c1",
    "3af0e72a933aef09ff2503df78bafed531c02ff1a2bc437c540cdcbd4ad35435",
    "cf511763596543480629b114ca7f780ff7efa32ea0cb6e000d6d9ea1f2ef71fd",
    "9cf9948422a165557e37e755edfe70d90b920502eb478bc98a63f788ce3a0f85",
    "6d6ede7251a383bfa8fa480a81a925af7b3cc538c4bab8c9f7597ffb68011d8d",
    "2640fbfbcfefb163ee7a87b6483a66ee41f956d90fa8a7939bfc042ee0924b1b",
    "7993d0445f758d51933e85179c0320b0c968b48a91c38b5be923e1097c0c562f",
    "88d42294b6a2759bafa5428a74f1270874e45f6fcc60f21602de5eccd143cf31",
    "241f5921b5ad3983fb54ef17be3b285367e50c999c67247b552fe4bfce945f7b",
    "0000000000010001",
);
/// Its public key, `n || e`.
const PK_HEX: &str = concat!(
    "a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e6",
    "37f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097",
    "b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e",
    "254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d981",
    "4c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b",
    "4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a19",
    "69816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a4",
    "5d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d5",
    "0000000000010001",
);
/// tcId 2 of that file: a ciphertext of `MSG_HEX` under the empty label.
const CT_HEX: &str = concat!(
    "207180c340658b5154ae45d2e4e7326a0997c683a26b595e536a29333c4b6614",
    "9af85e029d5419a39e3a147b221516ffd86b6b4b66c3e0c4c49fe8c57a2f5c37",
    "b8704b9b592b80db9cd788a4ed51ab4f0a1cbed63bd18d1f06a22f225866b0c2",
    "c417cb23473b7ba4250b1353bd2e5b4f0f937cd2efe5fa38db3c295f7748b970",
    "088657db4aa9a76e1ee6fbff166ec1861d00d085326c7384bdd1bc2f400d4f74",
    "dbdfadaf3fdc46073e668573e02030b9eb5af58eb540c66677a771194479ec00",
    "98d858a2ea45d0ba1e6b32440dfbac745000554d51a17684ca964b02a74d479f",
    "1d432ef763ef4059715a4348cfe36a215359712f25b6977903be4adb92febbf6",
);
const MSG_HEX: &str = "0000000000000000000000000000000000000000";
/// tcId 8: a ciphertext of `LABELLED_MSG_HEX` under `LABEL_HEX`.
const LABELLED_CT_HEX: &str = concat!(
    "6583e2f176aa7e7f655d2c53497349c156c8851fb23325589e85fb83bfa85734",
    "6caba222cdaa3234e71564154298c24dbb85e18822a1d5e7faa47863a64d7687",
    "4a3cbc70f4d9f137426a344c473fac1dd7008a9973765e9f66c5b492535a647c",
    "273c4f78ceb5aa7ba963a2142f2ce4a81f804c002b9b2eabb3c75e80a3c6ceaf",
    "e5384a544c672a5d28d32bb87115f43eb79775fd9b3f4a2f6e6a89368bdd95ef",
    "1d014877b60afdb1234acd57653a65459f01b2fbe381f22a739504b4897a7e6c",
    "33b6349b276db6083abad9c169405859b800c812237634b503de6ada43013c1d",
    "86697a135be78a9784576d796d62aa7819e2ea0e2d902ffdd9cfdd1ae66212ee",
);
const LABELLED_MSG_HEX: &str = "313233343030";
const LABEL_HEX: &str = "0000000000000000";
/// tcId 12: "first byte of l_hash modified".
const INVALID_CT_HEX: &str = concat!(
    "287d7108a1c6e7a18acb0045b20c57cdf2ac03456b44942764a7a9e9fdf3db48",
    "1d7e202e4c8d733b56b9c1e93d71e791af8325c9363df789b252a5ed0eddc79e",
    "76fa41c2cb0a35618398217a390a5e6d99eed905d5554d19c1cf4e30bdf1c2fc",
    "c5148b641d71b3f1977b63d232648ddd935ec9499a53ac2fbcac55f462e91065",
    "adaa018a39c453ba759bd68b454074153421e2ce75cf149f748b5b84758df8a4",
    "23d1c50c880af863f2a6df3cd465ca36aa2152b5771f3d507f4a4dd9f8006d80",
    "eca23537092287976f218a90df1e16d889fe31e79f7309f3224f613e9b52479f",
    "e73b7aad915319a3b62a5936649f7d015d7b09f7fa9f454f78a7c3dd4bf791e0",
);

/// A fresh scratch file path holding `bytes`.
fn temp_file(name: &str, bytes: &[u8]) -> String {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path: PathBuf =
        std::env::temp_dir().join(format!("bc-rust-oaep-{}-{n}-{name}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    path.to_string_lossy().into_owned()
}

fn sk_file() -> String {
    temp_file("sk", &unhex(SK_HEX))
}

fn pk_file() -> String {
    temp_file("pk", &unhex(PK_HEX))
}

#[test]
fn recover_matches_the_wycheproof_vectors() {
    let sk = sk_file();
    let ct = temp_file("ct", &unhex(CT_HEX));
    let out = run_ok(&["rsa-oaep-2048", "recover", "--skfile", &sk, "--ctfile", &ct, "-x"], b"");
    assert_eq!(String::from_utf8(out).unwrap(), MSG_HEX);
    // The ciphertext on stdin, and raw output.
    let out = run_ok(&["rsa-oaep-2048", "recover", "--skfile", &sk], &unhex(CT_HEX));
    assert_eq!(tohex(&out), MSG_HEX);

    // A labelled ciphertext recovers under its label and under no other.
    let ct = temp_file("ct-label", &unhex(LABELLED_CT_HEX));
    let args = ["rsa-oaep-2048", "recover", "--skfile", &sk, "--ctfile", &ct, "-x"];
    let out = run_ok(&[&args[..], &["--label", LABEL_HEX]].concat(), b"");
    assert_eq!(String::from_utf8(out).unwrap(), LABELLED_MSG_HEX);
    assert!(run_err(&args, b"").contains("decryption failed"));
    assert!(run_err(&[&args[..], &["--label", "00"]].concat(), b"").contains("decryption failed"));
}

/// Every failure reads the same, whatever was wrong with the ciphertext.
#[test]
fn a_bad_ciphertext_is_one_error() {
    let sk = sk_file();
    for ct in [unhex(INVALID_CT_HEX), vec![0xFFu8; 256]] {
        let ct = temp_file("bad", &ct);
        for action in ["recover", "decaps"] {
            let err = run_err(&["rsa-oaep-2048", action, "--skfile", &sk, "--ctfile", &ct], b"");
            assert_eq!(err.trim(), "Error: RSAES-OAEP-2048 decryption failed.", "{action}");
        }
    }
    // Under another hash the valid ciphertext is a bad one too.
    let ct = temp_file("ct", &unhex(CT_HEX));
    for extra in [["--hash", "sha384"], ["--mgf-hash", "sha1"]] {
        let args = ["rsa-oaep-2048", "recover", "--skfile", &sk, "--ctfile", &ct];
        let err = run_err(&[&args[..], &extra[..]].concat(), b"");
        assert_eq!(err.trim(), "Error: RSAES-OAEP-2048 decryption failed.");
    }
    // A ciphertext of the wrong length is refused before the key is used.
    let short = temp_file("short", &[0u8; 255]);
    let err = run_err(&["rsa-oaep-2048", "recover", "--skfile", &sk, "--ctfile", &short], b"");
    assert!(err.contains("255 bytes"), "{err}");
}

#[test]
fn transport_and_recover_round_trip() {
    let (sk, pk) = (sk_file(), pk_file());
    let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    for extra in [
        vec![],
        vec!["--label", "6c6162656c"],
        vec!["--hash", "sha1"],
        vec!["--hash", "sha512", "--mgf-hash", "sha1"],
        vec!["--hash", "sha512-256", "--mgf-hash", "sha224"],
    ] {
        let transport = ["rsa-oaep-2048", "transport", "--pkfile", &pk];
        let ct = run_ok(&[&transport[..], &extra[..]].concat(), &key);
        assert_eq!(ct.len(), 256, "{extra:?}");
        // Two transports of one key are two ciphertexts.
        assert_ne!(ct, run_ok(&[&transport[..], &extra[..]].concat(), &key), "{extra:?}");
        let recover = ["rsa-oaep-2048", "recover", "--skfile", &sk];
        assert_eq!(run_ok(&[&recover[..], &extra[..]].concat(), &ct), key, "{extra:?}");
    }
    // To a file, in hex, and back with --hex-input.
    let ct = temp_file("ct-out", b"");
    run_ok(&["rsa-oaep-2048", "transport", "--pkfile", &pk, "--ctfile", &ct, "-x"], &key);
    assert_eq!(std::fs::read(&ct).unwrap().len(), 512);
    let args = ["--hex-input", "rsa-oaep-2048", "recover", "--ctfile", &ct, "--skfile"];
    let sk_hex = temp_file("sk-hex", SK_HEX.as_bytes());
    assert_eq!(run_ok(&[&args[..], &[sk_hex.as_str()]].concat(), b""), key);
}

/// SHA-256 at RSA-2048 carries k - 2hLen - 2 = 190 bytes and no more.
#[test]
fn the_longest_key_is_190_bytes() {
    let (sk, pk) = (sk_file(), pk_file());
    let key = vec![0x5Au8; 190];
    let ct = run_ok(&["rsa-oaep-2048", "transport", "--pkfile", &pk], &key);
    assert_eq!(run_ok(&["rsa-oaep-2048", "recover", "--skfile", &sk], &ct), key);
    let err = run_err(&["rsa-oaep-2048", "transport", "--pkfile", &pk], &[0x5Au8; 191]);
    assert!(err.contains("at most 190 bytes"), "{err}");
}

#[test]
fn encaps_and_decaps_agree_and_interoperate_with_recover() {
    let (sk, pk) = (sk_file(), pk_file());
    // Without --ctfile: the ciphertext and then the key, in hex, one per line.
    let out =
        String::from_utf8(run_ok(&["rsa-oaep-2048", "encaps", "--pkfile", &pk], b"")).unwrap();
    let (ct_hex, key_hex) = out.split_once('\n').expect("two lines");
    assert_eq!((ct_hex.len(), key_hex.len()), (512, 64));
    let ct = temp_file("kem-ct", &unhex(ct_hex));
    let key = run_ok(&["rsa-oaep-2048", "decaps", "--skfile", &sk, "--ctfile", &ct, "-x"], b"");
    assert_eq!(String::from_utf8(key).unwrap(), key_hex);
    // The KEM's ciphertext is a transported 32-byte key.
    let key = run_ok(&["rsa-oaep-2048", "recover", "--skfile", &sk, "--ctfile", &ct, "-x"], b"");
    assert_eq!(String::from_utf8(key).unwrap(), key_hex);
    // And a transported key of another length is not one the KEM accepts.
    let ct = run_ok(&["rsa-oaep-2048", "transport", "--pkfile", &pk], &[7u8; 16]);
    let err = run_err(&["rsa-oaep-2048", "decaps", "--skfile", &sk], &ct);
    assert_eq!(err.trim(), "Error: RSAES-OAEP-2048 decryption failed.");
}

#[test]
fn the_files_each_action_needs_are_asked_for() {
    let pk = pk_file();
    assert!(run_err(&["rsa-oaep-2048", "keygen"], b"").contains("no pkfile"));
    assert!(run_err(&["rsa-oaep-2048", "transport"], b"key").contains("no pkfile"));
    assert!(run_err(&["rsa-oaep-2048", "recover"], &[0u8; 256]).contains("no skfile"));
    assert!(run_err(&["rsa-oaep-2048", "decaps"], &[0u8; 256]).contains("no skfile"));
    let err = run_err(&["rsa-oaep-2048", "transport", "--pkfile", &pk, "--label", "xyz"], b"key");
    assert!(err.contains("`--label` must be hex"), "{err}");
    // The four sizes are listed.
    let help = String::from_utf8(run_ok(&["--help"], b"")).unwrap();
    for size in ["2048", "3072", "4096", "8192"] {
        assert!(help.contains(&format!("rsa-oaep-{size}")), "{size}");
    }
    let _ = BC_RUST;
}
