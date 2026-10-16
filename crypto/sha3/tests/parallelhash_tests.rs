//! ParallelHash and ParallelHashXOF behaviour tests. The SP 800-185 sample values are in
//! `parallelhash_bc-test-data.rs`.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::hash::TestFrameworkHash;
use bouncycastle_sha3::parallelhash::{
    ParallelHash128, ParallelHash256, ParallelHashXOF128, ParallelHashXOF256,
};

/// Unlike TupleHash, ParallelHash *is* ordinary byte-wise streaming: the blocks come from `B`, not
/// from how the caller chunks its `do_update` calls. Chunkings that straddle block boundaries are
/// the interesting ones, so this walks a range of chunk sizes against a block size of 8.
#[test]
fn chunking_does_not_change_the_result() {
    let msg: Vec<u8> = (0..=200u8).collect();
    let one = ParallelHash128::new(8, b"S", 32).hash(&msg);

    for chunk in [1usize, 3, 7, 8, 9, 16, 64, 201] {
        let mut p = ParallelHash128::new(8, b"S", 32);
        for piece in msg.chunks(chunk) {
            p.do_update(piece);
        }
        assert_eq!(p.do_final(), one, "chunk size {chunk} must not change the result");
    }
}

/// Sec 6.2: `B` is a parameter of the function. The same message under a different block size is a
/// different hash, not a re-arrangement of the same work.
#[test]
fn the_block_size_is_part_of_the_hash() {
    let msg: Vec<u8> = (0..=100u8).collect();
    let b8 = ParallelHash128::new(8, b"", 32).hash(&msg);
    let b12 = ParallelHash128::new(12, b"", 32).hash(&msg);
    let b16 = ParallelHash128::new(16, b"", 32).hash(&msg);
    assert_ne!(b8, b12);
    assert_ne!(b8, b16);
    assert_ne!(b12, b16);
}

/// A short final block, an exactly-full final block, and an empty message are the boundary cases
/// of the block loop.
///
/// This test matters more than it looks: **every published ParallelHash sample value has a
/// block-aligned message** (24 bytes at B = 8, 72 at B = 12), so the NIST vectors never exercise a
/// short final block at all. Deleting the flush of the partial buffer passes all twelve of them
/// and fails only here.
#[test]
fn block_boundary_cases() {
    // exactly one full block, versus one full block plus one byte
    let full = ParallelHash128::new(8, b"", 32).hash(&[0xAAu8; 8]);
    let plus = ParallelHash128::new(8, b"", 32).hash(&[0xAAu8; 9]);
    assert_ne!(full, plus);

    // two full blocks versus one short block: different block counts, so different output
    let two = ParallelHash128::new(8, b"", 32).hash(&[0xAAu8; 16]);
    assert_ne!(two, full);

    // an empty message is zero blocks, and must still produce a hash
    let empty = ParallelHash128::new(8, b"", 32).hash(b"");
    assert_eq!(empty.len(), 32);
    assert_ne!(empty, full);
}

/// The XOF's output at one length is a prefix of its output at a longer one; the fixed-length
/// function's is not.
#[test]
fn length_binding_differs_between_the_two() {
    let msg = b"parallel";
    let short = ParallelHash128::new(4, b"", 16).hash(msg);
    let long = ParallelHash128::new(4, b"", 32).hash(msg);
    assert_ne!(&long[..16], &short[..], "ParallelHash: a different length is a different function");

    let squeeze = |n| {
        let mut p = ParallelHashXOF128::new(4, b"");
        p.do_update(msg);
        p.into_squeezer().do_output(n)
    };
    let short = squeeze(16);
    let long = squeeze(32);
    assert_eq!(&long[..16], &short[..], "ParallelHashXOF: one stream, so shorter is a prefix");
}

/// A partial final byte cannot be expressed: the block count and length encodings must follow.
#[test]
fn partial_final_byte_is_refused() {
    let mut p = ParallelHash128::new(8, b"", 32);
    p.do_update(b"abc");
    assert!(matches!(p.do_final_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));

    let mut p = ParallelHashXOF128::new(8, b"");
    p.do_update(b"abc");
    assert!(matches!(p.into_squeezer_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));
}

/// Sec 6.2 forbids a zero block size.
#[test]
#[should_panic(expected = "block size B must be positive")]
fn zero_block_size_is_rejected() {
    let _ = ParallelHash128::new(0, b"", 32);
}

#[test]
fn algorithm_names() {
    assert_eq!(ParallelHash128::ALG_NAME, "ParallelHash128");
    assert_eq!(ParallelHash256::ALG_NAME, "ParallelHash256");
    assert_eq!(ParallelHashXOF128::ALG_NAME, "ParallelHashXOF128");
    assert_eq!(ParallelHashXOF256::ALG_NAME, "ParallelHashXOF256");
}

/// Sponge rates from FIPS 202 Table 3, the nominal lengths of the XOF forms, and the constructed
/// length of the fixed forms. The generic checks elsewhere only require these to be positive.
#[test]
fn metadata() {
    assert_eq!(ParallelHash128::new(8, b"", 32).block_bitlen(), 1344, "cSHAKE128 rate");
    assert_eq!(ParallelHash256::new(8, b"", 64).block_bitlen(), 1088, "cSHAKE256 rate");
    assert_eq!(ParallelHashXOF128::new(8, b"").block_bitlen(), 1344);
    assert_eq!(ParallelHashXOF256::new(8, b"").block_bitlen(), 1088);

    assert_eq!(ParallelHash128::new(8, b"", 17).output_len(), 17, "whatever was asked for");
    assert_eq!(ParallelHash256::new(8, b"", 100).output_len(), 100);
    assert_eq!(ParallelHashXOF128::new(8, b"").output_len(), 32, "the nominal length");
    assert_eq!(ParallelHashXOF256::new(8, b"").output_len(), 64);
}

/// Every output-buffer length, at both strengths and a non-default output length.
///
/// As for TupleHash: `output_len` is bound into the computation, so a short buffer truncates this
/// ParallelHash rather than computing a shorter one, and must not panic.
#[test]
fn output_buffers_of_every_length() {
    let framework = TestFrameworkHash::new();
    let input = b"the quick brown fox jumps over the lazy dog";

    framework.test_hash_output_buffers(|| ParallelHash128::new(8, b"", 32), input);
    framework.test_hash_output_buffers(|| ParallelHash256::new(8, b"", 64), input);

    // A block size that does not divide the input, a customization string, odd output lengths.
    framework.test_hash_output_buffers(|| ParallelHash128::new(12, b"Parallel Data", 17), input);
    framework.test_hash_output_buffers(|| ParallelHash256::new(5, b"Parallel Data", 5), input);
}
