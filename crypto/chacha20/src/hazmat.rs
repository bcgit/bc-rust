//! Raw primitives whose safe use is the caller's responsibility; see [`bouncycastle_core::hazmat`]
//! for what the path means and the supported uses.
//!
//! [`ChaCha20KeyState`] is the key, validated once, and [`ChaCha20KeyStream`] the keystream
//! positioned over it: the parts under [`ChaCha20Key`] and the
//! ChaCha20-Poly1305 key. Constructed directly, through [`ChaCha20KeyStream::start_at`] over a
//! state or [`keystream_at`] over a key, the keystream takes the nonce and initial block counter
//! from the caller; a key's `create_encryptor` draws the nonce, starts at counter 0 and refuses
//! to run past the counter, and is the cipher to use.

use crate::{BLOCK_LEN, ChaCha20Key, KEY_LEN, NONCE_LEN};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;
use bouncycastle_utils::secret::Secret;

/// One counter value per keystream block: RFC 8439 Sec 2.3, "Word 12 is a block counter".
const BLOCK_LIMIT: u64 = 1 << 32;

/// The 256-bit ChaCha20 key of RFC 8439 Sec 2.3 as the eight words of the cipher state it fills,
/// validated once: the keyed primitive under [`ChaCha20Key`] and the
/// ChaCha20-Poly1305 key, as an expanded schedule is under an AES key. The words live in a
/// [`Secret`], zeroized on drop, and a [`ChaCha20KeyStream`] borrows them rather than copying them.
///
/// # 🚨 Security Considerations 🚨
/// The material of a ChaCha20-Poly1305 key makes the same state, and a keystream over it under
/// that key's nonces is the AEAD's own keystream; see [`ChaCha20KeyStream`].
#[derive(Clone)]
pub struct ChaCha20KeyState {
    key: Secret<[u32; 8]>,
}

// `Secret`'s equality: every byte is inspected, so the time taken does not say where two keys
// differ.
impl PartialEq for ChaCha20KeyState {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for ChaCha20KeyState {}

impl ChaCha20KeyState {
    /// The key words of RFC 8439 Sec 2.3, "eight 32-bit little-endian integers".
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 32 bytes long.
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not a `SymmetricCipherKey`.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 256 bits.
    pub fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        if key.key_len() != KEY_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType(
                "ChaCha20 requires a symmetric cipher key",
            )
            .into());
        }
        if key.security_strength() < ChaCha20KeyStream::MAX_SECURITY_STRENGTH {
            return Err(
                KeyMaterialError::SecurityStrength("ChaCha20 requires a 256-bit key").into()
            );
        }
        let mut words: Secret<[u32; 8]> = Secret::new();
        let (key_words, _) = key.ref_to_bytes().as_chunks::<4>();
        for (word, bytes) in words.iter_mut().zip(key_words) {
            *word = u32::from_le_bytes(*bytes);
        }
        Ok(Self { key: words })
    }
}

/// The IETF ChaCha20 keystream of RFC 8439 Sec 2.4: the block function of Sec 2.3 run over
/// successive values of the 32-bit block counter, with a fixed key and 96-bit nonce. Use it
/// through [`ChaCha20`](crate::ChaCha20). Not `Clone`: two copies of a positioned keystream
/// would emit the same bytes twice.
///
/// ```compile_fail
/// # use bouncycastle_chacha20::hazmat::ChaCha20KeyStream;
/// fn cloneable<T: Clone>() {}
/// cloneable::<ChaCha20KeyStream<'static>>();
/// ```
///
/// # 🚨 Security Considerations 🚨
/// A raw [`KeyStream`]: constructed directly, it takes the nonce from the caller, and running it
/// past the counter panics rather than returning an error. In particular, never use it with the
/// key and nonce of a ChaCha20-Poly1305 message: block 0 of that pair is the message's one-time
/// Poly1305 key (RFC 8439 Sec 2.6). See [`KeyStream`]'s security notes and
/// [`bouncycastle_core::hazmat`] for the supported uses.
///
/// # State
///
/// A reference to the [`ChaCha20KeyState`], the nonce and the next block counter. The nonce and
/// the counter are both public, so they are plain fields; no keystream is kept between calls.
pub struct ChaCha20KeyStream<'k> {
    key: &'k ChaCha20KeyState,
    /// RFC 8439 Sec 2.3's words 13-15: the nonce, as little-endian words.
    nonce: [u32; 3],
    /// The counter of the *next* block. A `u64` so that the exhausted state, `2^32`, is
    /// representable without wrapping into the 32-bit word 12.
    next_counter: u64,
}

impl<'k> ChaCha20KeyStream<'k> {
    /// The keystream for `nonce` under `key`, whose first block uses the counter
    /// `initial_counter`: RFC 8439 Sec 2.4's "32-bit initial counter. This can be set to any
    /// number, but will usually be zero or one."
    pub fn start_at(
        key: &'k ChaCha20KeyState,
        nonce: &[u8; NONCE_LEN],
        initial_counter: u32,
    ) -> Self {
        let mut words = [0u32; 3];
        for (word, bytes) in words.iter_mut().zip(nonce.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        Self { key, nonce: words, next_counter: u64::from(initial_counter) }
    }
}

/// The keystream for `nonce` under `key`, positioned at `initial_counter`:
/// [`ChaCha20KeyStream::start_at`] over the state a [`ChaCha20Key`] holds, for a construction
/// that derives its own material from the keystream, as the ChaCha20-Poly1305 key does (RFC 8439
/// Sec 2.6.1 takes its one-time key from block 0).
///
/// # 🚨 Security Considerations 🚨
/// As [`ChaCha20KeyStream::start_at`]: the nonce and the counter range are the caller's to keep
/// from repeating under the key, and the keystream panics rather than errs past the counter.
pub fn keystream_at<'k>(
    key: &'k ChaCha20Key,
    nonce: &[u8; NONCE_LEN],
    initial_counter: u32,
) -> ChaCha20KeyStream<'k> {
    ChaCha20KeyStream::start_at(&key.state, nonce, initial_counter)
}

impl Algorithm for ChaCha20KeyStream<'_> {
    const ALG_NAME: &'static str = "ChaCha20";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

impl KeyStream<NONCE_LEN, BLOCK_LEN> for ChaCha20KeyStream<'_> {
    /// One block for every counter value left below `2^32`.
    fn remaining_blocks(&self) -> u64 {
        BLOCK_LIMIT.saturating_sub(self.next_counter)
    }

    /// RFC 8439 Sec 2.4.1, `block ^ key_stream` for the next `blocks.len()` counter values.
    fn apply_blocks(&mut self, blocks: &mut [[u8; BLOCK_LEN]]) {
        // `StreamCipher` calls this with no blocks whenever a call ends inside the pending one, and
        // then there is no state to build.
        if blocks.is_empty() {
            return;
        }
        // RFC 8439 Sec 2.3: constants, key, block counter, nonce, with word 12 rewritten for each
        // block. Built here for this call, so that the key's words stay in the key; a `Secret`,
        // since it holds them.
        let mut state: Secret<[u32; 16]> = Secret::new();
        state[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
        state[4..12].copy_from_slice(&*self.key.key);
        state[13..].copy_from_slice(&self.nonce);
        // Live keystream until it has been XORed in, so it is a `Secret`, one per call.
        let mut working: Secret<[u32; 16]> = Secret::new();
        for block in blocks.iter_mut() {
            // In release builds too: past the last counter, word 12 would wrap to 0 and repeat the
            // keystream, which the trait lets an implementor refuse by panicking.
            assert!(self.next_counter < BLOCK_LIMIT, "the caller checks remaining_blocks");
            state[12] = self.next_counter as u32;
            block_function(&state, &mut working);
            // Sec 2.3 serialises each word little-endian and Sec 2.4 XORs bytewise; XORing the
            // little-endian word of plaintext with the keystream word is the same operation.
            let (words, _) = block.as_chunks_mut::<4>();
            for (bytes, k) in words.iter_mut().zip(working.iter()) {
                *bytes = (u32::from_le_bytes(*bytes) ^ k).to_le_bytes();
            }
            self.next_counter += 1;
        }
    }
}

/// RFC 8439 Sec 2.3: `out` = 20 rounds over `state`, then the original input words added back,
/// modulo 2^32. Serialisation is left to the caller.
// Kept out of line for speed, not correctness: inlined into `apply_blocks`, whose input state is a
// local, it ran about 1.45x slower (16 KiB, x86-64, measured 2026-10-21); out of line it matches
// the keystream that kept its state in a field.
#[inline(never)]
fn block_function(state: &[u32; 16], out: &mut [u32; 16]) {
    out.copy_from_slice(state);
    for _ in 0..10 {
        quarter_round(out, 0, 4, 8, 12);
        quarter_round(out, 1, 5, 9, 13);
        quarter_round(out, 2, 6, 10, 14);
        quarter_round(out, 3, 7, 11, 15);
        quarter_round(out, 0, 5, 10, 15);
        quarter_round(out, 1, 6, 11, 12);
        quarter_round(out, 2, 7, 8, 13);
        quarter_round(out, 3, 4, 9, 14);
    }
    for (word, input) in out.iter_mut().zip(state.iter()) {
        *word = word.wrapping_add(*input);
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}
