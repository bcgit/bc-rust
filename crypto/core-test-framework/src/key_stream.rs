//! Shared conformance tests for [`KeyStream`] implementors.

use crate::DUMMY_SEED;
use bouncycastle_core::hazmat::KeyStream;

/// Instance of the test framework.
pub struct TestFrameworkKeyStream {
    // Put any config options here
}

impl Default for TestFrameworkKeyStream {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFrameworkKeyStream {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Exercises the trait contract for one implementor, built by `new` over the init data it is
    /// given, over a permutation the caller keys once.
    ///
    /// Checks, in order:
    /// * `apply_blocks` XORs: applied to [`DUMMY_SEED`] it gives `DUMMY_SEED` XOR the keystream it
    ///   writes into zeros, and that keystream is not all zeros;
    /// * the keystream is a function of the key and init data alone: the same pair gives the same
    ///   keystream, and different init data a different one;
    /// * every chunking of the blocks into `apply_blocks` calls gives the one-call answer --
    ///   including chunk sizes that are not multiples of any batch width the implementor uses;
    /// * `remaining_blocks` goes down by exactly one per block applied (a keystream that reports
    ///   `u64::MAX`, no practical limit, may stay there).
    ///
    /// The key-policy checks (type, strength, binding) belong to the key object that owns the
    /// permutation, and are `TestFrameworkFromKeyMaterial`'s.
    pub fn test<
        const INIT_DATA_LEN: usize,
        const BLOCK_LEN: usize,
        KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN>,
    >(
        &self,
        new: impl Fn(&[u8; INIT_DATA_LEN]) -> KS,
    ) {
        let init_data = [0xA5u8; INIT_DATA_LEN];
        let blocks = DUMMY_SEED.as_chunks::<BLOCK_LEN>().0;
        let n = blocks.len();

        // The keystream itself: XORed into zeros.
        let mut keystream = vec![[0u8; BLOCK_LEN]; n];
        new(&init_data).apply_blocks(&mut keystream);
        assert!(
            keystream.iter().any(|b| b.iter().any(|&x| x != 0)),
            "apply_blocks must produce keystream, not leave its input unchanged"
        );

        // XOR semantics: applied to data, the result is data XOR keystream.
        let mut data = blocks.to_vec();
        new(&init_data).apply_blocks(&mut data);
        for ((d, k), p) in data.iter().zip(keystream.iter()).zip(blocks.iter()) {
            let expected: [u8; BLOCK_LEN] = core::array::from_fn(|i| p[i] ^ k[i]);
            assert_eq!(d, &expected, "apply_blocks must XOR the keystream into its input");
        }

        // Deterministic in (key, init data), and dependent on the init data.
        let mut again = vec![[0u8; BLOCK_LEN]; n];
        new(&init_data).apply_blocks(&mut again);
        assert_eq!(again, keystream, "the same key and init data must give the same keystream");
        if INIT_DATA_LEN > 0 {
            let mut other = vec![[0u8; BLOCK_LEN]; n];
            new(&[0x5Au8; INIT_DATA_LEN]).apply_blocks(&mut other);
            assert_ne!(other, keystream, "different init data must give a different keystream");
        }

        // Every chunking agrees with the single call, and `remaining_blocks` counts down by one per
        // block. The chunk sizes straddle the batch widths an implementor is likely to use.
        for chunk in [1usize, 2, 3, 4, 5, 7, 8, 9, n - 1, n] {
            let mut ks = new(&init_data);
            let mut chunked = vec![[0u8; BLOCK_LEN]; n];
            for piece in chunked.chunks_mut(chunk) {
                let before = ks.remaining_blocks();
                ks.apply_blocks(piece);
                let after = ks.remaining_blocks();
                if before != u64::MAX {
                    assert_eq!(
                        after,
                        before - piece.len() as u64,
                        "remaining_blocks must drop by exactly the blocks applied"
                    );
                }
            }
            assert_eq!(chunked, keystream, "chunk size {chunk} must give the one-call keystream");
        }

        // An empty call produces nothing and consumes nothing.
        let mut ks = new(&init_data);
        let before = ks.remaining_blocks();
        ks.apply_blocks(&mut []);
        assert_eq!(ks.remaining_blocks(), before, "an empty call must not consume keystream");
        let mut first = [[0u8; BLOCK_LEN]];
        ks.apply_blocks(&mut first);
        assert_eq!(first[0], keystream[0], "an empty call must not advance the keystream");
    }
}
