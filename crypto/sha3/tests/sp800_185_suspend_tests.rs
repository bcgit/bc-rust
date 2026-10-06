//! Suspend/resume for the SP 800-185 functions: round trips in each phase, the rejections that
//! keep one function's state out of another, and the field checks of each layout.
//!
//! Offsets used below, from the layouts in the crate: 3 version bytes, then the variant tag at
//! 3, the sponge's `squeezing` flag at 404 (tag + 400 bytes of Keccak state), the cSHAKE
//! `customized` byte at 415, and whatever the function adds from 416.

use bouncycastle_core::errors::SuspendableError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{Hash, MAC, Suspendable, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;
use bouncycastle_sha3::*;

const PART1: &[u8] = b"Colorless green ideas";
const PART2: &[u8] = b" sleep furiously";

const SQUEEZING_FLAG: usize = 3 + 1 + 400;
const CUSTOMIZED: usize = 3 + 412;

fn key() -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(&[0x42u8; 32], KeyType::MACKey).expect("a MAC key")
}

/// Feeds `PART1`, suspends, resumes, feeds `PART2`: the digest must match the uninterrupted one.
/// For TupleHash the two parts are two elements, on both sides.
fn hash_round_trip<const N: usize, H: Hash + Suspendable<N> + Clone>(make: impl Fn() -> H) {
    let mut h = make();
    h.do_update(PART1);
    TestFrameworkSuspendableState::new().test(&h);
    let state = h.clone().suspend();
    h.do_update(PART2);
    let expected = h.do_final();

    let mut resumed = H::from_suspended(state).expect("a state resumes as its own type");
    resumed.do_update(PART2);
    assert_eq!(resumed.do_final(), expected);
}

/// Suspends the squeezer before its first read and again after a streamed read. The first state
/// still has the fixed-length choice open, so a final read after resume is the fixed-length
/// function and a streamed read is the XOF; the second continues the stream.
fn squeezer_round_trip<const N: usize, X>(make: impl Fn() -> X)
where
    X: XOF + Clone,
    X::Squeezer: Suspendable<N> + Clone,
{
    let mut x = make();
    x.do_update(PART1);
    let fixed = x.clone().into_squeezer().do_output_final(32);
    let mut stream = x.into_squeezer();
    TestFrameworkSuspendableState::new().test(&stream);
    let unbound_state = stream.clone().suspend();
    let first = stream.do_output(16);

    let resumed = X::Squeezer::from_suspended(unbound_state).expect("an unbound squeezer resumes");
    assert_eq!(resumed.do_output_final(32), fixed, "a final read after resume binds its length");
    let mut resumed = X::Squeezer::from_suspended(unbound_state).unwrap();
    assert_eq!(resumed.do_output(16), first, "a streamed read after resume is the XOF");

    TestFrameworkSuspendableState::new().test(&stream);
    let squeezing_state = stream.clone().suspend();
    let more = stream.do_output(100);
    let mut resumed = X::Squeezer::from_suspended(squeezing_state).expect("a squeezing one too");
    assert_eq!(resumed.do_output(100), more, "the resumed stream continues where it stopped");
}

#[test]
fn cshake_round_trips() {
    hash_round_trip(|| CSHAKE128::new(b"", b"Email Signature"));
    hash_round_trip(|| CSHAKE256::new(b"", b"Email Signature"));
    // Uncustomized cSHAKE is SHAKE, and must come back that way.
    hash_round_trip(|| CSHAKE128::new(b"", b""));
    squeezer_round_trip(|| CSHAKE128::new(b"", b"Email Signature"));
    squeezer_round_trip(|| CSHAKE256::new(b"", b""));
}

#[test]
fn kmac_round_trips() {
    fn mac_round_trip<const N: usize, M: MAC + Suspendable<N> + Clone>(make: impl Fn() -> M) {
        let mut m = make();
        m.do_update(PART1);
        TestFrameworkSuspendableState::new().test(&m);
        let state = m.clone().suspend();
        m.do_update(PART2);
        let expected = m.do_final();

        let mut resumed = M::from_suspended(state).expect("a KMAC state resumes");
        assert_eq!(resumed.output_len(), expected.len(), "the output length is part of the state");
        resumed.do_update(PART2);
        assert!(resumed.do_verify_final(&expected));
    }
    mac_round_trip(|| KMAC128::new(&key()).unwrap());
    mac_round_trip(|| KMAC256::new(&key()).unwrap());
    mac_round_trip(|| {
        KMAC128::new_with_params(&key(), b"My Tagged Application", 16, false).unwrap()
    });
}

#[test]
fn kmacxof_round_trips() {
    hash_round_trip(|| KMACXOF128::new(&key(), b"", false).unwrap());
    hash_round_trip(|| KMACXOF256::new(&key(), b"S", false).unwrap());
    squeezer_round_trip(|| KMACXOF128::new(&key(), b"", false).unwrap());
    squeezer_round_trip(|| KMACXOF256::new(&key(), b"S", false).unwrap());
}

#[test]
fn tuplehash_round_trips() {
    hash_round_trip(|| TUPLEHASH128::new(b"", 32));
    hash_round_trip(|| TUPLEHASH256::new(b"My Tuple App", 48));
    hash_round_trip(|| TUPLEHASHXOF128::new(b""));
    hash_round_trip(|| TUPLEHASHXOF256::new(b"My Tuple App"));
    squeezer_round_trip(|| TUPLEHASHXOF128::new(b""));
    squeezer_round_trip(|| TUPLEHASHXOF256::new(b"My Tuple App"));
}

#[test]
fn parallelhash_round_trips() {
    // PART1 is 21 bytes: a block size of 8 suspends five bytes into a block, 7 suspends exactly
    // on a block boundary, and 64 suspends before the first block completes.
    for block_size in [8usize, 7, 64] {
        hash_round_trip(|| PARALLELHASH128::new(block_size, b"", 32));
        hash_round_trip(|| PARALLELHASH256::new(block_size, b"Parallel Data", 64));
        hash_round_trip(|| PARALLELHASHXOF128::new(block_size, b""));
        hash_round_trip(|| PARALLELHASHXOF256::new(block_size, b"Parallel Data"));
        squeezer_round_trip(|| PARALLELHASHXOF128::new(block_size, b""));
        squeezer_round_trip(|| PARALLELHASHXOF256::new(block_size, b"Parallel Data"));
    }
}

/// A state is accepted only by the type that wrote it, even where the layouts are identical.
#[test]
fn each_type_rejects_the_others() {
    fn rejected<const N: usize, T: Suspendable<N>>(state: [u8; N], what: &str) {
        assert!(
            matches!(T::from_suspended(state), Err(SuspendableError::InvalidData)),
            "{what} must be rejected"
        );
    }
    let mut x = CSHAKE128::new(b"", b"S");
    x.do_update(PART1);
    rejected::<_, CSHAKE256>(x.clone().suspend(), "a cSHAKE128 state in cSHAKE256");
    rejected::<_, KMACXOF128>(x.clone().suspend(), "a cSHAKE128 state in KMACXOF128");
    rejected::<_, TUPLEHASHXOF128>(x.clone().suspend(), "a cSHAKE128 state in TupleHashXOF128");
    rejected::<_, LengthBoundSqueezer<SHAKE128Params>>(
        x.suspend(),
        "a cSHAKE128 state in a squeezer",
    );

    let mut k = KMACXOF128::new(&key(), b"", false).unwrap();
    k.do_update(PART1);
    rejected::<_, CSHAKE128>(k.clone().suspend(), "a KMACXOF128 state in cSHAKE128");
    rejected::<_, TUPLEHASHXOF128>(k.clone().suspend(), "a KMACXOF128 state in TupleHashXOF128");
    rejected::<_, KMACXOF256>(k.clone().suspend(), "a KMACXOF128 state in KMACXOF256");
    let squeezer = k.into_squeezer();
    rejected::<_, KMACXOF128>(squeezer.clone().suspend(), "an unbound squeezer in KMACXOF128");
    rejected::<_, CSHAKE128>(squeezer.suspend(), "an unbound squeezer in cSHAKE128");

    let mut k = KMAC128::new(&key()).unwrap();
    k.do_update(PART1);
    rejected::<_, TUPLEHASH128>(k.clone().suspend(), "a KMAC128 state in TupleHash128");
    rejected::<_, KMAC256>(k.suspend(), "a KMAC128 state in KMAC256");
    let mut t = TUPLEHASH128::new(b"", 32);
    t.do_update(PART1);
    rejected::<_, KMAC128>(t.suspend(), "a TupleHash128 state in KMAC128");

    let mut p = PARALLELHASH128::new(8, b"", 32);
    p.do_update(PART1);
    rejected::<_, PARALLELHASH256>(p.suspend(), "a ParallelHash128 state in ParallelHash256");
    let mut p = PARALLELHASHXOF128::new(8, b"");
    p.do_update(PART1);
    rejected::<_, PARALLELHASHXOF256>(p.suspend(), "a ParallelHashXOF128 state in 256");
}

#[test]
fn corrupt_fields_are_rejected() {
    fn rejected<const N: usize, T: Suspendable<N>>(state: [u8; N], what: &str) {
        assert!(
            matches!(T::from_suspended(state), Err(SuspendableError::InvalidData)),
            "{what} must be rejected"
        );
    }

    let mut c = CSHAKE128::new(b"", b"S");
    c.do_update(PART1);
    let good = c.suspend();
    let mut bad = good;
    bad[CUSTOMIZED] = 2;
    rejected::<_, CSHAKE128>(bad, "a customized byte that is neither 0 nor 1");
    let mut bad = good;
    bad[SQUEEZING_FLAG] = 1;
    rejected::<_, CSHAKE128>(bad, "a squeezing sponge in an absorbing cSHAKE");

    let mut k = KMAC128::new(&key()).unwrap();
    k.do_update(PART1);
    let mut bad = k.suspend();
    bad[CUSTOMIZED] = 0;
    rejected::<_, KMAC128>(bad, "a KMAC claiming an empty function name");

    let mut k = KMACXOF128::new(&key(), b"", false).unwrap();
    k.do_update(PART1);
    let mut bad = k.into_squeezer().suspend();
    bad[CUSTOMIZED] = 0;
    rejected::<_, LengthBoundSqueezer<SHAKE128Params>>(bad, "a squeezer claiming no function name");

    // ParallelHash: outer cSHAKE 3..416, inner SHAKE 416..828, then block_size, block_fill, blocks.
    const INNER_SQUEEZING_FLAG: usize = 416 + 1 + 400;
    const BLOCK_SIZE: usize = 416 + 412;
    const BLOCK_FILL: usize = BLOCK_SIZE + 8;
    let mut p = PARALLELHASH128::new(8, b"", 32);
    p.do_update(PART1);
    let good = p.suspend();
    assert_eq!(&good[BLOCK_SIZE..BLOCK_SIZE + 8], &8u64.to_le_bytes(), "layout check");
    assert_eq!(&good[BLOCK_FILL..BLOCK_FILL + 8], &5u64.to_le_bytes(), "21 bytes = 2 blocks + 5");
    let mut bad = good;
    bad[BLOCK_SIZE..BLOCK_SIZE + 8].copy_from_slice(&0u64.to_le_bytes());
    rejected::<_, PARALLELHASH128>(bad, "a block size of zero");
    let mut bad = good;
    bad[BLOCK_FILL..BLOCK_FILL + 8].copy_from_slice(&8u64.to_le_bytes());
    rejected::<_, PARALLELHASH128>(bad, "a fill equal to the block size");
    let mut bad = good;
    bad[INNER_SQUEEZING_FLAG] = 1;
    rejected::<_, PARALLELHASH128>(bad, "an inner sponge that is squeezing");
    let mut bad = good;
    bad[CUSTOMIZED] = 0;
    rejected::<_, PARALLELHASH128>(bad, "a ParallelHash claiming an empty function name");
}

/// Every type in the crate writes a different variant tag, so no state can be misread as
/// another's: the six FIPS 202 types and the eight SP 800-185 types at each width.
#[test]
fn state_tags_are_distinct() {
    fn tag<const N: usize, T: Suspendable<N>>(t: T) -> u8 {
        t.suspend()[3]
    }
    let mut tags = vec![
        tag(SHA3_224::new()),
        tag(SHA3_256::new()),
        tag(SHA3_384::new()),
        tag(SHA3_512::new()),
        tag(SHAKE128::new()),
        tag(SHAKE256::new()),
        tag(CSHAKE128::new(b"", b"S")),
        tag(KMAC128::new(&key()).unwrap()),
        tag(KMACXOF128::new(&key(), b"", false).unwrap()),
        tag(TUPLEHASH128::new(b"", 32)),
        tag(TUPLEHASHXOF128::new(b"")),
        tag(PARALLELHASH128::new(8, b"", 32)),
        tag(PARALLELHASHXOF128::new(8, b"")),
        tag(TUPLEHASHXOF128::new(b"").into_squeezer()),
        tag(CSHAKE256::new(b"", b"S")),
        tag(KMAC256::new(&key()).unwrap()),
        tag(KMACXOF256::new(&key(), b"", false).unwrap()),
        tag(TUPLEHASH256::new(b"", 32)),
        tag(TUPLEHASHXOF256::new(b"")),
        tag(PARALLELHASH256::new(8, b"", 32)),
        tag(PARALLELHASHXOF256::new(8, b"")),
        tag(TUPLEHASHXOF256::new(b"").into_squeezer()),
    ];
    let n = tags.len();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), n, "two types share a state tag");
}

#[test]
fn pin_state_lengths() {
    assert_eq!(SUSPENDED_CSHAKE_STATE_LEN, 416, "3 (version) + 412 (family) + 1 (customized)");
    assert_eq!(SUSPENDED_LENGTH_BOUND_SQUEEZER_STATE_LEN, 416);
    assert_eq!(SUSPENDED_KMACXOF_STATE_LEN, 416);
    assert_eq!(SUSPENDED_TUPLEHASHXOF_STATE_LEN, 416);
    assert_eq!(SUSPENDED_KMAC_STATE_LEN, 424, "416 + 8 (output length)");
    assert_eq!(SUSPENDED_TUPLEHASH_STATE_LEN, 424);
    assert_eq!(SUSPENDED_PARALLELHASHXOF_STATE_LEN, 852, "416 + 412 (inner) + 3 * 8");
    assert_eq!(SUSPENDED_PARALLELHASH_STATE_LEN, 860, "852 + 8 (output length)");
}
