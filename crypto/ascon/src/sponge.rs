//! The absorb/pad/squeeze sponge shared by Ascon-Hash256, Ascon-XOF128, and Ascon-CXOF128
//! (NIST SP 800-232 §5): a 64-bit rate over `Ascon-p[12]`. Each of those three types holds one
//! [`Sponge`] and differs only in its initial state and (for Ascon-CXOF128) an extra
//! customization-string absorption performed before message absorption begins.

use bouncycastle_utils::secret::Secret;

use crate::permutation::{AsconState, load_u64_le, p12, store_u64_le};

/// Rate in bytes for the Hash256/XOF128/CXOF128 sponge (64 bits, per SP 800-232 §5).
pub(crate) const RATE: usize = 8;

pub(crate) struct Sponge {
    // 320-bit sponge state (five 64-bit words S0..S4). Wrapped in `Secret` so the working state
    // -- which absorbs the message -- is scrubbed with volatile writes when dropped.
    s: Secret<AsconState>,
    // Rate buffer: partial input block while absorbing, or leftover squeezed bytes afterwards.
    buf: Secret<[u8; RATE]>,
    buf_pos: usize,
    squeezing: bool,
}

impl Sponge {
    /// Construct a sponge already in the given state (typically a function's precomputed
    /// post-initialization state, SP 800-232 Table 12), ready to absorb.
    pub(crate) fn from_state(state: AsconState) -> Self {
        let mut s: Secret<AsconState> = Secret::new();
        *s = state;
        Self { s, buf: Secret::new(), buf_pos: 0, squeezing: false }
    }

    /// Reconstruct a sponge from raw parts (used by `Suspendable::from_suspended`).
    pub(crate) fn from_parts(
        s: Secret<AsconState>,
        buf: Secret<[u8; RATE]>,
        buf_pos: usize,
        squeezing: bool,
    ) -> Self {
        Self { s, buf, buf_pos, squeezing }
    }

    pub(crate) fn state_words(&self) -> [u64; 5] {
        *self.s
    }

    pub(crate) fn buf_bytes(&self) -> [u8; RATE] {
        *self.buf
    }

    pub(crate) fn buf_pos(&self) -> usize {
        self.buf_pos
    }

    pub(crate) fn squeezing(&self) -> bool {
        self.squeezing
    }

    /// XOR `v` into the first state word. Used by Ascon-CXOF128 to absorb the customization
    /// string's bit length (SP 800-232 §5.3 Eq. 75) before the length-prefixed customization
    /// blocks are absorbed via [`Sponge::absorb`].
    pub(crate) fn xor_word0(&mut self, v: u64) {
        self.s[0] ^= v;
    }

    /// Apply `Ascon-p[12]` to the state directly. Used by Ascon-CXOF128 between customization
    /// blocks (SP 800-232 Algorithm 7).
    pub(crate) fn permute(&mut self) {
        p12(&mut self.s);
    }

    /// Reset the rate buffer to begin a fresh absorb phase. Used by Ascon-CXOF128 once the
    /// customization string has been fully absorbed, before message absorption begins.
    pub(crate) fn reset_buffer(&mut self) {
        self.buf.fill(0);
        self.buf_pos = 0;
    }

    /// Absorb input data. Panics if called after squeezing has begun.
    pub(crate) fn absorb(&mut self, input: &[u8]) {
        if self.squeezing {
            panic!("attempt to absorb while squeezing");
        }

        let available = RATE - self.buf_pos;
        if input.len() < available {
            self.buf[self.buf_pos..self.buf_pos + input.len()].copy_from_slice(input);
            self.buf_pos += input.len();
            return;
        }

        let mut input = input;

        if self.buf_pos > 0 {
            self.buf[self.buf_pos..].copy_from_slice(&input[..available]);
            self.s[0] ^= u64::from_le_bytes(*self.buf);
            p12(&mut self.s);
            input = &input[available..];
        }

        while input.len() >= RATE {
            self.s[0] ^= load_u64_le(input, 0);
            p12(&mut self.s);
            input = &input[RATE..];
        }

        self.buf[..input.len()].copy_from_slice(input);
        self.buf_pos = input.len();
    }

    // Pad the final absorbed block (SP 800-232 Appendix A.2, Algorithm 2) by XORing in the
    // buffered bytes (masked to `buf_pos` bytes -- any stale bytes beyond that in `buf` are
    // masked off) followed by the padding bit at byte position `buf_pos`. Deliberately does not
    // permute: the permutation is folded into the first block of `squeeze()` below, since Ascon-
    // Hash256's fixed 4-block output and Ascon-XOF128/CXOF128's streaming output both begin
    // their squeeze phase with a permute-then-read (SP 800-232 Algorithms 5-7).
    pub(crate) fn pad_and_absorb(&mut self) {
        let final_bits = (self.buf_pos << 3) as u32;
        let x = u64::from_le_bytes(*self.buf);
        let mask =
            if final_bits == 0 { 0u64 } else { 0x00FF_FFFF_FFFF_FFFF_u64 >> (56 - final_bits) };
        self.s[0] ^= x & mask;
        self.s[0] ^= 0x01u64 << final_bits;
    }

    /// Squeeze `output.len()` bytes. May be called multiple times; the first call must follow
    /// [`Sponge::pad_and_absorb`] and ends the absorb phase.
    pub(crate) fn squeeze(&mut self, output: &mut [u8]) {
        let mut output = output;

        if !self.squeezing {
            self.squeezing = true;
            self.buf_pos = RATE;
        } else if self.buf_pos < RATE {
            let available = RATE - self.buf_pos;
            if output.len() <= available {
                let end_pos = self.buf_pos + output.len();
                output.copy_from_slice(&self.buf[self.buf_pos..end_pos]);
                self.buf_pos = end_pos;
                return;
            }

            output[..available].copy_from_slice(&self.buf[self.buf_pos..]);
            output = &mut output[available..];
            self.buf_pos = RATE;
        }

        while output.len() >= RATE {
            p12(&mut self.s);
            store_u64_le(output, 0, self.s[0]);
            output = &mut output[RATE..];
        }

        if !output.is_empty() {
            p12(&mut self.s);
            *self.buf = self.s[0].to_le_bytes();
            output.copy_from_slice(&self.buf[..output.len()]);
            self.buf_pos = output.len();
        }
    }
}

impl Clone for Sponge {
    fn clone(&self) -> Self {
        Self {
            s: self.s.clone(),
            buf: self.buf.clone(),
            buf_pos: self.buf_pos,
            squeezing: self.squeezing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `xor_word0` cannot be exercised as an XOR (as opposed to e.g. an OR) via any published KAT:
    // its only caller (Ascon-CXOF128's customization-length absorption) combines a bit_length
    // value -- always a multiple of 8 -- with a state word whose low 3 bits happen to be the
    // only ones set for every customization length actually covered by NIST's KAT file (max 32
    // bytes). Pin the arithmetic directly instead.
    #[test]
    fn xor_word0_is_xor_not_or() {
        let mut sponge = Sponge::from_state([0b0000_0101, 0, 0, 0, 0]);
        sponge.xor_word0(0b0000_0110);
        // 0b101 ^ 0b110 = 0b011. An OR would give 0b111.
        assert_eq!(sponge.state_words()[0], 0b0000_0011);
    }
}
