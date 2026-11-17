//! SHA-1 through the `Hash` trait: the shared conformance suite, known answers that run without
//! bc-test-data, bit-oriented messages and the suspended state.
//!
//! The printed known answers are RFC 3174 Section 7.3's four test results and entries of NIST's
//! CAVP `SHA1ShortMsg.rsp` (byte- and bit-oriented), copied from those files, at the lengths
//! where the padding changes shape.

use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, AlgorithmOID, Hash, HashAlgParams, HashOneShot,
};
use bouncycastle_core_test_framework::hash::TestFrameworkHash;
use bouncycastle_hex as hex;
use bouncycastle_sha1::*;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// RFC 3174 Section 7.3: TEST1, TEST2, and TEST4 repeated ten times.
const RFC_3174: [(&str, usize, &str); 3] = [
    ("abc", 1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        1,
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
    ),
    (
        "0123456701234567012345670123456701234567012345670123456701234567",
        10,
        "dea356a2cddd90c7a7ecedc5ebb563934f460452",
    ),
];

/// CAVP byte-oriented `SHA1ShortMsg.rsp`: the empty message and messages of 55, 56, 63 and 64
/// bytes, around the points where the length field does and does not fit the last block.
const CAVP_BYTES: [(&str, &str); 5] = [
    ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    (
        "ec6b4a88713df27c0f2d02e738b69db43abda3921317259c864c1c386e9a5a3f533dc05f3beeb2bec2aac8e06db4c6cb3cddcf697e03d5",
        "a7272e2308622ff7a339460adc61efd0ea8dabdc",
    ),
    (
        "0321736beba578e90abc1a90aa56157d871618f6de0d764cc8c91e06c68ecd3b9de3824064503384db67beb7fe012232dacaef93a000fba7",
        "aef843b86916c16f66c84d83a6005d23fd005c9e",
    ),
    (
        "f2c76ef617fa2bfc8a4d6bcbb15fe88436fdc2165d3074629579079d4d5b86f5081ab177b4c3f530376c9c924cbd421a8daf8830d0940c4fb7589865830699",
        "9f3ea255f6af95c5454e55d7354cabb45352ea0b",
    ),
    (
        "45927e32ddf801caf35e18e7b5078b7f5435278212ec6bb99df884f49b327c6486feae46ba187dc1cc9145121e1492e6b06e9007394dc33b7748f86ac3207cfe",
        "a70cfbfe7563dd0e665c7c6715a96a8d756950c0",
    ),
];

/// CAVP bit-oriented `SHA1ShortMsg.rsp`: `(Len in bits, Msg, MD)`, the trailing bits
/// left-justified in the last byte of `Msg`.
const CAVP_BITS: [(usize, &str, &str); 6] = [
    (1, "00", "bb6b3e18f0115b57925241676f5b1ae88747b08a"),
    (5, "48", "3320540d1c28b96ddd03eee1b186a8f2ae883fbe"),
    (13, "de08", "5eb340c7214e400f8cd5782e9afb62c6f9afab57"),
    (
        447,
        "de11fa659cc16ad64de598bf7403be07b14d1b7de62f3b0f98247a3c98cdc4cce2449ebec5ae6a82440fe668bd63f759c8eaa5c562c366dc",
        "14c764e1369c26aa6a92e75384ea6394986d706b",
    ),
    (
        449,
        "e41de51ef465e8c8209f3a16aed159db3303bc07f145c2cb62f4e9fe153a40c0b9d41f5d7818157486362258f9be26b6db629a787dfe7eea00",
        "5b9800a8c20f91575446c707f78ea09d35d708ac",
    ),
    (
        511,
        "99afae9df7a6cf61760a455cb11433b58445e21d29fc0804a1484b0d56fb01c0fe003a80c2ee00bca0dcdd690e789eafe05357e26b7fa7b5eb5c3daa22af9bcc",
        "cc58d7a6dd5b77d61d069bf3ecd0c9a7ae01098d",
    ),
];

/// Runs the shared Hash-trait conformance suite against the known answers.
#[test]
fn core_test_framework_hash() {
    let test_framework = TestFrameworkHash::new();
    for (msg, repeat, md) in RFC_3174 {
        test_framework.test_hash::<SHA1>(msg.repeat(repeat).as_bytes(), &h(md));
    }
    for (msg, md) in CAVP_BYTES {
        test_framework.test_hash::<SHA1>(&h(msg), &h(md));
    }
}

/// RFC 3174 Section 7.3's TEST3: one million repetitions of "a", streamed.
#[test]
fn rfc_3174_one_million_a() {
    let mut sha1 = SHA1::new();
    for _ in 0..1000 {
        sha1.do_update(&[b'a'; 1000]);
    }
    assert_eq!(sha1.do_final(), h("34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
}

/// The known answers again a byte at a time, which exercises every buffer offset.
#[test]
fn streaming_a_byte_at_a_time() {
    for (msg, md) in CAVP_BYTES {
        let mut sha1 = SHA1::new();
        for b in h(msg) {
            sha1.do_update(core::slice::from_ref(&b));
        }
        assert_eq!(sha1.do_final(), h(md), "len={}", msg.len() / 2);
    }
}

/// A short output buffer truncates the digest and a long one is zero-filled past it.
#[test]
fn output_buffer_lengths() {
    let md = h(RFC_3174[0].2);
    for len in [0usize, 1, 3, 4, 5, 19, 20, 21, 32] {
        let mut out = vec![0xFFu8; len];
        let mut sha1 = SHA1::new();
        sha1.do_update(b"abc");
        let n = sha1.do_final_out(&mut out);
        assert_eq!(n, len.min(20), "len={len}");
        assert_eq!(&out[..n], &md[..n], "len={len}");
        assert!(out[n..].iter().all(|b| *b == 0), "len={len}");
    }
}

#[test]
fn test_constants() {
    assert_eq!(SHA1::OUTPUT_LEN, 20);
    assert_eq!(SHA1::BLOCK_LEN, 64);
    assert_eq!(SHA1::new().block_bitlen(), 512);
    assert_eq!(SHA1::new().output_len(), 20);
    // The crate docs' Memory Usage table.
    assert_eq!(core::mem::size_of::<SHA1>(), 104);
}

#[test]
fn test_algorithm() {
    assert_eq!(SHA1::ALG_NAME, SHA1_NAME);
    assert_eq!(SHA1_NAME, "SHA1");
    assert_eq!(SHA1::OID, &[1, 3, 14, 3, 2, 26]);
    assert_eq!(SHA1::OID_DER, &[0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A]);
}

/// SHA-1 is credited with no security strength.
#[test]
fn test_security_strength() {
    assert_eq!(SHA1::MAX_SECURITY_STRENGTH, SecurityStrength::None);
    assert_eq!(SHA1::default().max_security_strength(), SecurityStrength::None);
}

/// FIPS 180-4 s. 5.1: bit-oriented messages. Zero partial bits is the byte-oriented digest, more
/// than 7 is rejected, and only the top bits of the partial byte matter.
#[test]
fn partial_bits() {
    let mut a = SHA1::new();
    a.do_update(b"abc");
    assert_eq!(a.do_final_partial_bits(0xFF, 0).unwrap(), SHA1::hash(b"abc"));

    for bad in [8usize, 9, 16, 64, usize::MAX] {
        let mut sha1 = SHA1::new();
        sha1.do_update(b"abc");
        assert!(
            matches!(sha1.do_final_partial_bits(0xFF, bad), Err(HashError::InvalidLength(_))),
            "n={bad}"
        );
        let mut out = [0u8; 20];
        assert!(matches!(
            SHA1::new().do_final_partial_bits_out(0xFF, bad, &mut out),
            Err(HashError::InvalidLength(_))
        ));
    }

    for n in 1..=7usize {
        let mask = (0xFF00u16 >> n) as u8;
        let x = SHA1::new().do_final_partial_bits(0xA5, n).unwrap();
        let y = SHA1::new().do_final_partial_bits(0xA5 & mask, n).unwrap();
        let z = SHA1::new().do_final_partial_bits(0xA5 ^ 0x80, n).unwrap();
        assert_eq!(x, y, "n={n}");
        assert_ne!(x, z, "n={n}: the leading bit must change the digest");
        assert_ne!(x, SHA1::hash(&[]), "n={n}");
        assert_ne!(x, SHA1::hash(&[0xA5 & mask]), "n={n}");
    }
}

/// Bit-oriented known answers from CAVP, including the lengths either side of the 448-bit point
/// where the padding takes a second block.
#[test]
fn partial_bits_known_answers() {
    for (len_bits, msg, md) in CAVP_BITS {
        let msg = h(msg);
        let (whole, partial) = (len_bits / 8, len_bits % 8);
        let mut sha1 = SHA1::new();
        sha1.do_update(&msg[..whole]);
        assert_eq!(sha1.do_final_partial_bits(msg[whole], partial).unwrap(), h(md), "{len_bits}");
        // The out form reports the digest's length.
        let mut sha1 = SHA1::new();
        sha1.do_update(&msg[..whole]);
        let mut out = [0u8; 20];
        assert_eq!(sha1.do_final_partial_bits_out(msg[whole], partial, &mut out), Ok(20));
        assert_eq!(out.as_slice(), h(md), "{len_bits}");
    }
}

#[test]
fn suspendable_state() {
    use bouncycastle_core::traits::Suspendable;
    use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

    let str = "Colorless green ideas sleep furiously";

    let mut sha1 = SHA1::new();
    sha1.do_update(str.as_bytes());

    // do the default tests
    let test_framework = TestFrameworkSuspendableState::new();
    test_framework.test(&sha1);

    // serialize the in-progress state
    let serialized_state = sha1.clone().suspend();
    assert_eq!(serialized_state.len(), SUSPENDED_SHA1_STATE_LEN);
    assert_eq!(SUSPENDED_SHA1_STATE_LEN, 96);

    // finish the hash, then load from the state and finish again
    let output = sha1.do_final();
    let output2 = SHA1::from_suspended(serialized_state).unwrap().do_final();
    assert_eq!(output, output2);

    // A state suspended across a block boundary resumes to the same digest as the unbroken hash.
    let msg = [0x5Au8; 150];
    let mut first = SHA1::new();
    first.do_update(&msg[..100]);
    let mut resumed = SHA1::from_suspended(first.suspend()).unwrap();
    resumed.do_update(&msg[100..]);
    assert_eq!(resumed.do_final(), SHA1::hash(&msg));

    // an x_buf_off past the block
    let mut busted_state = serialized_state;
    busted_state[3 + 92] = 65;
    assert!(matches!(SHA1::from_suspended(busted_state), Err(SuspendableError::InvalidData)));
    busted_state[3 + 92] = 64;
    assert!(matches!(SHA1::from_suspended(busted_state), Err(SuspendableError::InvalidData)));

    // byte_count must agree with x_buf_off modulo the block length, and stay within the longest
    // message the 64-bit length field can encode, 2^61 - 1 bytes.
    let with_counts = |byte_count: u64, x_buf_off: u8| {
        let mut state = serialized_state;
        state[3 + 20..3 + 28].copy_from_slice(&byte_count.to_le_bytes());
        state[3 + 92] = x_buf_off;
        SHA1::from_suspended(state)
    };
    let off = serialized_state[3 + 92];
    assert!(with_counts(str.len() as u64 + 64, off).is_ok());
    assert!(matches!(with_counts(str.len() as u64 + 1, off), Err(SuspendableError::InvalidData)));
    let max: u64 = (1 << 61) - 1;
    assert!(with_counts(max, 63).is_ok());
    assert!(matches!(with_counts(max + 1, 0), Err(SuspendableError::InvalidData)));
    assert!(matches!(with_counts(u64::MAX, 63), Err(SuspendableError::InvalidData)));
}
