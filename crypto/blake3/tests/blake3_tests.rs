//! Tests for [`BLAKE3`] (`hash` and `derive_key` modes) and [`BLAKE3Squeezer`].
//!
//! Vector sources: the official BLAKE3 test vectors (see `vectors/mod.rs`). bc-test-data has no
//! BLAKE3 data, and Wycheproof has no BLAKE vectors (C2SP/wycheproof testvectors_v1 has no blake*
//! file), so the "against bc-test-data and wycheproof" requirement is met vacuously.

mod vectors;

#[cfg(test)]
mod blake3_tests {
    use super::vectors::{CASES, CONTEXT, OUTPUT_LEN, input};
    use bouncycastle_blake3::*;
    use bouncycastle_core::errors::{HashError, SuspendableError};
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{
        Algorithm, Hash, HashAlgParams, Suspendable, XOF, XOFSqueezer,
    };
    use bouncycastle_core_test_framework::hash::TestFrameworkHash;
    use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;
    use bouncycastle_core_test_framework::xof::TestFrameworkXOF;
    use bouncycastle_hex as hex;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /* ----------------------------------- official vectors ----------------------------------- */

    /// Every `hash` case: the 32-byte default output, the full 131 bytes through every XOF entry
    /// point, and split reads across the 64-byte output block boundary.
    #[test]
    fn official_vectors_hash() {
        for case in CASES {
            let msg = input(case.input_len);
            let expected = h(case.hash);
            assert_eq!(expected.len(), OUTPUT_LEN);
            let len = case.input_len;

            assert_eq!(BLAKE3::new().hash(&msg), expected[..32], "hash / len {len}");
            assert_eq!(BLAKE3::new().xof(&msg, OUTPUT_LEN), expected, "xof / len {len}");

            let mut b = BLAKE3::new();
            b.do_update(&msg);
            assert_eq!(b.into_squeezer().do_output(OUTPUT_LEN), expected, "squeeze / len {len}");

            // Split reads: inside block 0, exactly at the block boundary, and across it.
            for split in [1usize, 31, 63, 64, 65, 128, 130] {
                let mut b = BLAKE3::new();
                b.do_update(&msg);
                let mut s = b.into_squeezer();
                let first = s.do_output(split);
                let second = s.do_output(OUTPUT_LEN - split);
                assert_eq!([first, second].concat(), expected, "split {split} / len {len}");
            }
        }
    }

    /// Every `derive_key` case, via [`BLAKE3::new_derive_key`], at 32 and 131 bytes.
    #[test]
    fn official_vectors_derive_key() {
        for case in CASES {
            let msg = input(case.input_len);
            let expected = h(case.derive_key);
            let len = case.input_len;

            assert_eq!(BLAKE3::new_derive_key(CONTEXT).hash(&msg), expected[..32], "len {len}");
            assert_eq!(
                BLAKE3::new_derive_key(CONTEXT).xof(&msg, OUTPUT_LEN),
                expected,
                "len {len}"
            );
        }
    }

    /// The derive_key context goes through the full tree, so a context longer than one chunk must
    /// differ from one that is merely a prefix of it, and the two modes must differ from `hash`.
    #[test]
    fn derive_key_context_is_bound() {
        let long_context = input(2049);
        let a = BLAKE3::new_derive_key(&long_context).hash(b"km");
        let b = BLAKE3::new_derive_key(&long_context[..2048]).hash(b"km");
        assert_ne!(a, b);
        assert_ne!(BLAKE3::new_derive_key(b"").hash(b"km"), BLAKE3::new().hash(b"km"));
    }

    /* --------------------------------- core-test-framework ---------------------------------- */

    #[test]
    fn core_test_framework_hash() {
        let tf = TestFrameworkHash { enable_partial_byte_tests: false };
        for case in CASES.iter().filter(|c| c.input_len <= 8193) {
            let msg = input(case.input_len);
            tf.test_hash::<BLAKE3>(&msg, &h(case.hash)[..32]);
        }
        for len in [0usize, 1, 64, 1024, 1025, 4097] {
            tf.test_hash_output_buffers(BLAKE3::new, &input(len));
            tf.test_hash_output_buffers(|| BLAKE3::new_derive_key(CONTEXT), &input(len));
        }
    }

    #[test]
    fn core_test_framework_xof() {
        let tf = TestFrameworkXOF {
            enable_partial_byte_tests: false,
            do_final_binds_output_length: false,
        };
        for case in CASES.iter().filter(|c| c.input_len <= 8193) {
            let msg = input(case.input_len);
            tf.test_xof(BLAKE3::new, &msg, &h(case.hash));
            tf.test_xof(|| BLAKE3::new_derive_key(CONTEXT), &msg, &h(case.derive_key));
        }
    }

    /* ------------------------------------- behaviour ---------------------------------------- */

    /// Streaming in odd piece sizes equals the one-shot, at every vector length around the chunk
    /// and tree boundaries.
    #[test]
    fn streaming_piece_sizes() {
        for case in CASES.iter().filter(|c| c.input_len >= 1023 && c.input_len <= 8193) {
            let msg = input(case.input_len);
            let expected = h(case.hash);
            for piece in [1usize, 63, 64, 65, 1023, 1024, 1025] {
                let mut b = BLAKE3::new();
                for chunk in msg.chunks(piece) {
                    b.do_update(chunk);
                }
                assert_eq!(
                    b.into_squeezer().do_output(OUTPUT_LEN),
                    expected,
                    "len {} piece {piece}",
                    case.input_len
                );
            }
        }
    }

    /// Empty updates are no-ops, wherever they fall.
    #[test]
    fn empty_updates() {
        let msg = input(1025);
        let mut b = BLAKE3::new();
        b.do_update(&[]);
        b.do_update(&msg[..1024]);
        b.do_update(&[]);
        b.do_update(&msg[1024..]);
        b.do_update(&[]);
        assert_eq!(b.do_final(), BLAKE3::new().hash(&msg));
    }

    /// A clone continues independently, including from a state with a non-empty CV stack.
    #[test]
    fn clone_forks() {
        let msg = input(3073);
        let mut a = BLAKE3::new();
        a.do_update(&msg[..2500]);
        let mut b = a.clone();
        a.do_update(&msg[2500..]);
        b.do_update(&msg[2500..]);
        let expected = BLAKE3::new().hash(&msg);
        assert_eq!(a.clone().do_final(), expected);
        assert_eq!(b.do_final(), expected);
        a.do_update(b"x");
        assert_ne!(a.do_final(), expected);

        // A squeezer clone continues the same stream.
        let mut s = BLAKE3::new().into_squeezer();
        let _ = s.do_output(70);
        let mut t = s.clone();
        assert_eq!(s.do_output(100), t.do_output(100));
    }

    /// The partial-bit policy: 0 is the whole-byte call, 1..=7 is InvalidInput (byte-oriented),
    /// and 8+ is InvalidLength. An `_out` call zeroizes the buffer first, even when it is
    /// rejected.
    #[test]
    fn partial_bits_policy() {
        let expected = BLAKE3::new().hash(b"abc");
        let mk = || {
            let mut b = BLAKE3::new();
            b.do_update(b"abc");
            b
        };

        for partial_byte in [0x00u8, 0xFF] {
            assert_eq!(mk().do_final_partial_bits(partial_byte, 0).unwrap(), expected);
            let mut out = [0xAAu8; 40];
            assert_eq!(mk().do_final_partial_bits_out(partial_byte, 0, &mut out).unwrap(), 32);
            assert_eq!(out[..32], expected);
            assert_eq!(out[32..], [0u8; 8]);
            let mut s = mk().into_squeezer_partial_bits(partial_byte, 0).unwrap();
            assert_eq!(s.do_output(32), expected);
        }

        for num_bits in 1..=7usize {
            assert!(matches!(
                mk().do_final_partial_bits(0x80, num_bits),
                Err(HashError::InvalidInput(_))
            ));
            let mut out = [0xA5u8; 32];
            assert!(matches!(
                mk().do_final_partial_bits_out(0x80, num_bits, &mut out),
                Err(HashError::InvalidInput(_))
            ));
            assert_eq!(out, [0u8; 32], "a rejected call must leave the buffer zeroized");
            assert!(matches!(
                mk().into_squeezer_partial_bits(0x80, num_bits),
                Err(HashError::InvalidInput(_))
            ));
        }

        // The frameworks' partial-bit tests are disabled for BLAKE3, so their > 7 values are pinned
        // here for every entry point.
        for num_bits in [8usize, 9, 15, 16, 64, usize::MAX] {
            assert!(matches!(
                mk().do_final_partial_bits(0, num_bits),
                Err(HashError::InvalidLength(_))
            ));
            let mut out = [0xA5u8; 32];
            assert!(matches!(
                mk().do_final_partial_bits_out(0, num_bits, &mut out),
                Err(HashError::InvalidLength(_))
            ));
            assert_eq!(out, [0u8; 32], "a rejected call must leave the buffer zeroized");
            assert!(matches!(
                mk().into_squeezer_partial_bits(0, num_bits),
                Err(HashError::InvalidLength(_))
            ));
        }
    }

    /// `Hash::do_final_out` writes at most 32 bytes and zeroizes the rest; a zero-length buffer
    /// gets nothing.
    #[test]
    fn hash_do_final_out_lengths() {
        let expected = BLAKE3::new().hash(b"abc");
        let mut out = [0xAAu8; 100];
        assert_eq!(BLAKE3::new().hash_out(b"abc", &mut out), 32);
        assert_eq!(out[..32], expected);
        assert!(out[32..].iter().all(|&b| b == 0));
        assert_eq!(BLAKE3::new().hash_out(b"abc", &mut []), 0);
        let mut out = [0u8; 5];
        assert_eq!(BLAKE3::new().hash_out(b"abc", &mut out), 5);
        assert_eq!(out, expected[..5]);
    }

    #[test]
    fn constants_and_params() {
        assert_eq!(BLAKE3_NAME, "BLAKE3");
        assert_eq!(BLAKE3::ALG_NAME, BLAKE3_NAME);
        assert_eq!(BLAKE3::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
        assert_eq!(BLAKE3::new().max_security_strength(), SecurityStrength::_128bit);
        assert_eq!(BLAKE3::OUTPUT_LEN, 32);
        assert_eq!(BLAKE3::BLOCK_LEN, 64);
        assert_eq!(BLAKE3::new().output_len(), 32);
        assert_eq!(BLAKE3::new().block_bitlen(), 512);
        assert_eq!(BLAKE3::default().hash(b"abc"), BLAKE3::new().hash(b"abc"));
        assert_eq!(SUSPENDED_BLAKE3_STATE_LEN, 1874);
        assert_eq!(SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN, 180);
    }

    /// Prints, and pins, the `size_of` figures quoted in the crate docs' Memory Usage table.
    #[test]
    fn print_sizes() {
        assert_eq!(size_of::<BLAKE3>(), 1880);
        assert_eq!(size_of::<BLAKE3KeyedHash>(), 1880);
        assert_eq!(size_of::<BLAKE3Squeezer>(), 192);
        assert_eq!(size_of::<BLAKE3KeyedSqueezer>(), 192);
        println!("size_of::<BLAKE3>() = {}", size_of::<BLAKE3>());
        println!("size_of::<BLAKE3KeyedHash>() = {}", size_of::<BLAKE3KeyedHash>());
        println!("size_of::<BLAKE3Squeezer>() = {}", size_of::<BLAKE3Squeezer>());
        println!("size_of::<BLAKE3KeyedSqueezer>() = {}", size_of::<BLAKE3KeyedSqueezer>());
    }

    /* ------------------------------------ suspend/resume ------------------------------------ */

    /// Suspends after `prefix` bytes of `msg`, resumes, absorbs the rest, and compares to the
    /// vector.
    fn round_trip(make: impl Fn() -> BLAKE3, msg: &[u8], prefix: usize, expected: &[u8]) {
        let mut b = make();
        b.do_update(&msg[..prefix]);
        let mut resumed = BLAKE3::from_suspended(b.suspend()).unwrap();
        resumed.do_update(&msg[prefix..]);
        assert_eq!(resumed.into_squeezer().do_output(OUTPUT_LEN), expected, "prefix {prefix}");
    }

    #[test]
    fn suspend_round_trip() {
        // 8193 bytes: past several chunk and tree boundaries, so the CV stack is non-empty.
        let case = CASES.iter().find(|c| c.input_len == 8193).unwrap();
        let msg = input(case.input_len);
        for prefix in [0usize, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3000, 4096, 7000, 8193] {
            round_trip(BLAKE3::new, &msg, prefix, &h(case.hash));
            round_trip(|| BLAKE3::new_derive_key(CONTEXT), &msg, prefix, &h(case.derive_key));
        }
    }

    #[test]
    fn core_test_framework_suspendable() {
        let tf = TestFrameworkSuspendableState::new();
        let msg = input(5000);
        for len in [0usize, 100, 1024, 1025, 5000] {
            let mut b = BLAKE3::new();
            b.do_update(&msg[..len]);
            tf.test(&b);
            let mut d = BLAKE3::new_derive_key(CONTEXT);
            d.do_update(&msg[..len]);
            tf.test(&d);
        }

        let mut b = BLAKE3::new();
        b.do_update(&msg);
        let mut s = b.into_squeezer();
        tf.test(&s);
        let _ = s.do_output(70);
        tf.test(&s);
    }

    /// A suspended squeezer resumes mid-stream, including exactly at and past a block boundary.
    #[test]
    fn squeezer_suspend_round_trip() {
        for case in CASES.iter().filter(|c| [0usize, 64, 1025, 4097].contains(&c.input_len)) {
            let msg = input(case.input_len);
            let expected = h(case.hash);
            for split in [0usize, 1, 63, 64, 65, 128, 131] {
                let mut b = BLAKE3::new();
                b.do_update(&msg);
                let mut s = b.into_squeezer();
                let first = s.do_output(split);
                let mut resumed = BLAKE3Squeezer::from_suspended(s.suspend()).unwrap();
                let second = resumed.do_output(OUTPUT_LEN - split);
                assert_eq!([first, second].concat(), expected, "split {split}");
            }

            let mut d = BLAKE3::new_derive_key(CONTEXT);
            d.do_update(&msg);
            let mut s = d.into_squeezer();
            let first = s.do_output(70);
            let mut resumed = BLAKE3Squeezer::from_suspended(s.suspend()).unwrap();
            assert_eq!([first, resumed.do_output(61)].concat(), h(case.derive_key));
        }
    }

    // Offsets into a BLAKE3 state, after the 3-byte version header (see
    // SUSPENDED_BLAKE3_STATE_LEN).
    const FLAGS: usize = 3;
    const KEY_WORDS: usize = 3 + 4;
    const CHUNK_CV: usize = 3 + 36;
    const CHUNK_COUNTER: usize = 3 + 68;
    const BLOCK: usize = 3 + 76;
    const BLOCK_LEN_AT: usize = 3 + 140;
    const BLOCKS_COMPRESSED: usize = 3 + 141;
    const CV_STACK_LEN: usize = 3 + 142;
    const CV_STACK: usize = 3 + 143;

    fn state_after(len: usize) -> [u8; SUSPENDED_BLAKE3_STATE_LEN] {
        let mut b = BLAKE3::new();
        b.do_update(&input(len));
        b.suspend()
    }

    fn rejected(state: [u8; SUSPENDED_BLAKE3_STATE_LEN]) -> bool {
        matches!(BLAKE3::from_suspended(state), Err(SuspendableError::InvalidData))
    }

    /// Pins the serialized layout: the hash-mode key words are IV, the chunk CV is zero before the
    /// first compression, stale bytes and stale stack entries are not written.
    #[test]
    fn suspend_layout() {
        let iv0 = 0x6a09e667u32.to_le_bytes();
        let s = state_after(0);
        assert_eq!(s[FLAGS..FLAGS + 4], [0u8; 4]);
        assert_eq!(s[KEY_WORDS..KEY_WORDS + 4], iv0);
        assert_eq!(s[CHUNK_CV..CHUNK_CV + 32], [0u8; 32], "chunk CV omitted while it is the key");
        assert!(s[CHUNK_COUNTER..].iter().all(|&b| b == 0));

        // 1100 bytes: one chunk on the stack, 76 bytes into chunk 1: one block compressed.
        let s = state_after(1100);
        assert_eq!(s[CHUNK_COUNTER..CHUNK_COUNTER + 8], 1u64.to_le_bytes());
        assert_eq!(s[BLOCK_LEN_AT], 12);
        assert_eq!(s[BLOCKS_COMPRESSED], 1);
        assert_eq!(s[CV_STACK_LEN], 1);
        assert_ne!(s[CHUNK_CV..CHUNK_CV + 32], [0u8; 32]);
        assert_eq!(s[BLOCK..BLOCK + 12], input(1100)[1088..1100]);
        assert!(s[BLOCK + 12..BLOCK + 64].iter().all(|&b| b == 0), "no stale block bytes");
        assert_ne!(s[CV_STACK..CV_STACK + 32], [0u8; 32]);
        assert!(s[CV_STACK + 32..].iter().all(|&b| b == 0), "no stale stack entries");

        // derive_key mode records its flag and context key.
        let mut d = BLAKE3::new_derive_key(CONTEXT);
        d.do_update(b"x");
        let s = d.suspend();
        assert_eq!(s[FLAGS..FLAGS + 4], 64u32.to_le_bytes());
        assert_ne!(s[KEY_WORDS..KEY_WORDS + 4], iv0);
    }

    /// Each InvalidData branch of `from_suspended`, with its boundary accepted.
    #[test]
    fn suspend_validation() {
        let good = state_after(3000); // chunk_counter 2 (0b10), one CV on the stack
        assert!(BLAKE3::from_suspended(good).is_ok());

        // flags: only 0 (with IV) and DERIVE_KEY_MATERIAL.
        for flags in [1u32, 16, 32, 64 | 1, 128] {
            let mut s = good;
            s[FLAGS..FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
            assert!(rejected(s), "flags {flags}");
        }
        let mut s = good;
        s[FLAGS..FLAGS + 4].copy_from_slice(&64u32.to_le_bytes());
        assert!(BLAKE3::from_suspended(s).is_ok(), "DERIVE_KEY_MATERIAL with any key words");
        // hash mode with key words other than IV.
        let mut s = good;
        s[KEY_WORDS] ^= 1;
        assert!(rejected(s), "hash mode requires IV key words");

        // block_len <= 64
        let mut s = good;
        s[BLOCK_LEN_AT] = 64;
        assert!(BLAKE3::from_suspended(s).is_ok());
        s[BLOCK_LEN_AT] = 65;
        assert!(rejected(s), "block_len 65");

        // blocks_compressed <= 15
        let mut s = good;
        s[BLOCKS_COMPRESSED] = 15;
        assert!(BLAKE3::from_suspended(s).is_ok());
        s[BLOCKS_COMPRESSED] = 16;
        assert!(rejected(s), "blocks_compressed 16");

        // cv_stack_len must equal chunk_counter.count_ones()
        let mut s = good;
        s[CV_STACK_LEN] = 2;
        assert!(rejected(s), "stack longer than the counter's 1-bits");
        s[CV_STACK_LEN] = 0;
        assert!(rejected(s), "stack shorter than the counter's 1-bits");

        // cv_stack_len <= 54, and chunk_counter < 2^54.
        let mut s = good;
        s[CHUNK_COUNTER..CHUNK_COUNTER + 8].copy_from_slice(&((1u64 << 54) - 1).to_le_bytes());
        s[CV_STACK_LEN] = 54;
        assert!(BLAKE3::from_suspended(s).is_ok(), "the largest valid counter");
        s[CHUNK_COUNTER..CHUNK_COUNTER + 8].copy_from_slice(&((1u64 << 55) - 1).to_le_bytes());
        s[CV_STACK_LEN] = 55;
        assert!(rejected(s), "cv_stack_len 55");
        // 54 one-bits, but not the low 54: the next chunk would push a 55th CV.
        s[CHUNK_COUNTER..CHUNK_COUNTER + 8]
            .copy_from_slice(&(((1u64 << 54) - 1) << 1).to_le_bytes());
        s[CV_STACK_LEN] = 54;
        assert!(rejected(s), "chunk_counter >= 2^54");
        s[CHUNK_COUNTER..CHUNK_COUNTER + 8].copy_from_slice(&(1u64 << 54).to_le_bytes());
        s[CV_STACK_LEN] = 1;
        assert!(rejected(s), "chunk_counter == 2^54");

        // A compressed block is always followed by at least one buffered byte.
        let mut s = good;
        s[BLOCK_LEN_AT] = 1;
        assert!(BLAKE3::from_suspended(s).is_ok());
        s[BLOCK_LEN_AT] = 0;
        assert!(rejected(s), "blocks_compressed > 0 with an empty block");
        s[BLOCKS_COMPRESSED] = 0;
        assert!(BLAKE3::from_suspended(s).is_ok(), "an empty chunk with nothing compressed");
    }

    /// While no block of the chunk is compressed, the chunk CV comes from the key words and the
    /// serialized bytes are ignored.
    #[test]
    fn suspend_ignores_chunk_cv_before_first_compression() {
        let msg = input(1030);
        let mut b = BLAKE3::new();
        b.do_update(&msg[..1025]); // chunk 1 holds 1 byte, nothing compressed
        let mut s = b.suspend();
        assert_eq!(s[BLOCKS_COMPRESSED], 0);
        s[CHUNK_CV..CHUNK_CV + 32].fill(0x5A);
        let mut resumed = BLAKE3::from_suspended(s).unwrap();
        resumed.do_update(&msg[1025..]);
        assert_eq!(resumed.do_final(), BLAKE3::new().hash(&msg));
    }

    /// The largest valid stack resumes and keeps absorbing: completing the current chunk merges
    /// all 54 entries without over- or underflowing.
    #[test]
    fn suspend_full_stack_resumes() {
        let mut s = state_after(0);
        s[CHUNK_COUNTER..CHUNK_COUNTER + 8].copy_from_slice(&((1u64 << 54) - 1).to_le_bytes());
        s[CV_STACK_LEN] = 54;
        let mut b = BLAKE3::from_suspended(s).unwrap();
        b.do_update(&input(2048));
        assert_eq!(b.do_final().len(), 32);
    }

    /// The 64-bit counter enters the compression as two words, t0 and t1 (spec s. 2.2). No real
    /// input reaches 2^32 chunks or output blocks, so the high word is exercised by resuming a
    /// squeezer at output block 2^32: with t1 dropped, that block would repeat block 0, and with
    /// t0 dropped, block 2^32 + 1 would repeat block 1.
    #[test]
    fn squeezer_counter_high_word() {
        let mut b = BLAKE3::new();
        b.do_update(b"abc");
        let s = b.into_squeezer();
        let blocks_0_1 = s.clone().do_output(128);
        let mut state = s.suspend();
        // output_block_counter = 2^32, buffer position 64 (the next read computes a new block).
        state[3 + 104..3 + 112].copy_from_slice(&(1u64 << 32).to_le_bytes());
        state[3 + 176] = 64;
        let mut far = BLAKE3Squeezer::from_suspended(state).unwrap();
        let far_blocks = far.do_output(128);
        assert_ne!(far_blocks[..64], blocks_0_1[..64], "block 2^32 must differ from block 0");
        assert_ne!(far_blocks[64..], blocks_0_1[64..], "block 2^32 + 1 must differ from block 1");
        assert_ne!(far_blocks[..64], far_blocks[64..]);
    }

    #[test]
    fn squeezer_suspend_validation() {
        let mut b = BLAKE3::new();
        b.do_update(b"abc");
        let mut s = b.into_squeezer();
        let _ = s.do_output(10);
        let state = s.suspend();
        assert_eq!(state[3 + 176], 10, "buffer position");

        let mut bad = state;
        bad[3 + 176] = 64;
        assert!(BLAKE3Squeezer::from_suspended(bad).is_ok());
        bad[3 + 176] = 65;
        assert!(matches!(BLAKE3Squeezer::from_suspended(bad), Err(SuspendableError::InvalidData)));

        // Root block_len <= 64 ("abc": 3).
        assert_eq!(state[3 + 96..3 + 100], 3u32.to_le_bytes());
        let mut bad = state;
        bad[3 + 96..3 + 100].copy_from_slice(&64u32.to_le_bytes());
        assert!(BLAKE3Squeezer::from_suspended(bad).is_ok());
        bad[3 + 96..3 + 100].copy_from_slice(&65u32.to_le_bytes());
        assert!(matches!(BLAKE3Squeezer::from_suspended(bad), Err(SuspendableError::InvalidData)));

        // output_block_counter == 0 is only valid at position 64 (nothing computed yet).
        assert_eq!(state[3 + 104..3 + 112], 1u64.to_le_bytes());
        let mut bad = state;
        bad[3 + 104..3 + 112].copy_from_slice(&0u64.to_le_bytes());
        assert!(matches!(BLAKE3Squeezer::from_suspended(bad), Err(SuspendableError::InvalidData)));
        bad[3 + 176] = 63;
        assert!(matches!(BLAKE3Squeezer::from_suspended(bad), Err(SuspendableError::InvalidData)));
        bad[3 + 176] = 64;
        assert!(BLAKE3Squeezer::from_suspended(bad).is_ok(), "a fresh squeezer");
        let fresh = BLAKE3::new().into_squeezer().suspend();
        assert_eq!(fresh[3 + 104..3 + 112], 0u64.to_le_bytes());
        assert_eq!(fresh[3 + 176], 64);
        assert!(BLAKE3Squeezer::from_suspended(fresh).is_ok());

        // Root flags: a node-type part plus mode 0 or DERIVE_KEY_MATERIAL; never ROOT or
        // KEYED_HASH.
        // "abc" is a one-block chunk root: CHUNK_START | CHUNK_END.
        assert_eq!(state[3 + 100..3 + 104], 3u32.to_le_bytes());
        let with_flags = |flags: u32| {
            let mut st = state;
            st[3 + 100..3 + 104].copy_from_slice(&flags.to_le_bytes());
            BLAKE3Squeezer::from_suspended(st)
        };
        for ok in [0u32, 1, 2, 3, 4, 64, 64 | 3, 64 | 4] {
            assert!(with_flags(ok).is_ok(), "flags {ok}");
        }
        for bad in [8u32, 16, 16 | 3, 32, 64 | 16, 64 | 8, 128, 1 << 31] {
            assert!(matches!(with_flags(bad), Err(SuspendableError::InvalidData)), "flags {bad}");
        }
    }
}
