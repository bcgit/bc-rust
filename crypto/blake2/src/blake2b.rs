//! BLAKE2b (RFC 7693) with a 64-byte digest: the unkeyed hash [`BLAKE2b_512`] and the keyed MAC
//! key [`BLAKE2b_512_MACKey`] with its worker [`BLAKE2b_512_MAC`].
//!
//! This file and `blake2s.rs` are deliberately structurally identical -- RFC 7693 s. 2.1 describes
//! one algorithm with two parameter columns -- so that a reviewer can diff them. Keep them in step.

use crate::MIN_MAC_OUTPUT_LEN;
use bouncycastle_core::errors::{HashError, KeyMaterialError, MACError, SuspendableError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{Hash, MAC, RNG, Suspendable, SuspendableKeyed};
use bouncycastle_utils::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_utils::{ct, min, secret::Secret};

/// RFC 7693 s. 2.1: "Block bytes | bb = 128".
const BB: usize = 128;

/// RFC 7693 s. 2.1: "Hash bytes | 1 <= nn <= 64". This crate implements only nn = 64.
const NN: usize = 64;

/// RFC 7693 s. 2.1: "Key bytes | 0 <= kk <= 64".
const MAX_KK: usize = 64;

/// RFC 7693 s. 2.1: "Rounds in F | r = 12".
const R: usize = 12;

/// RFC 7693 s. 2.1: "G Rotation constants = (32, 24, 16, 63)".
const R1: u32 = 32;
const R2: u32 = 24;
const R3: u32 = 16;
const R4: u32 = 63;

/// RFC 7693 s. 2.6: IV[i] = floor(2**w * frac(sqrt(prime(i+1)))), w = 64; values as in Appendix C.2
/// `blake2b_iv` ("BLAKE2b IV is the same as SHA-512 IV").
const IV: [u64; 8] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

/// RFC 7693 s. 2.7: message schedule SIGMA[0..9]. "For BLAKE2b, the two extra permutations for
/// rounds 10 and 11 are SIGMA[10..11] = SIGMA[0..1]", which F realises as `SIGMA[i mod 10]`.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// RFC 7693 s. 3.1: mixing function G.
#[inline]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    // v[a] := (v[a] + v[b] + x) mod 2**w
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    // v[d] := (v[d] ^ v[a]) >>> R1
    v[d] = (v[d] ^ v[a]).rotate_right(R1);
    // v[c] := (v[c] + v[d])     mod 2**w
    v[c] = v[c].wrapping_add(v[d]);
    // v[b] := (v[b] ^ v[c]) >>> R2
    v[b] = (v[b] ^ v[c]).rotate_right(R2);
    // v[a] := (v[a] + v[b] + y) mod 2**w
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    // v[d] := (v[d] ^ v[a]) >>> R3
    v[d] = (v[d] ^ v[a]).rotate_right(R3);
    // v[c] := (v[c] + v[d])     mod 2**w
    v[c] = v[c].wrapping_add(v[d]);
    // v[b] := (v[b] ^ v[c]) >>> R4
    v[b] = (v[b] ^ v[c]).rotate_right(R4);
}

/// RFC 7693 s. 3.2: compression function F( h[0..7], m[0..15], t, f ), updating `h` in place.
///
/// The message words `m` are read from `block` little-endian (s. 2.4). The transient work vector
/// `v` and words `m` are plain stack locals and are not zeroized; see the crate's Security
/// Considerations.
fn compress(h: &mut [u64; 8], block: &[u8; BB], t: u128, f: bool) {
    // s. 2.4: "Byte (octet) streams are interpreted as words in little-endian order".
    let mut m = [0u64; 16];
    let (words, _) = block.as_chunks::<8>();
    for (mi, bytes) in m.iter_mut().zip(words) {
        *mi = u64::from_le_bytes(*bytes);
    }

    // // Initialize local work vector v[0..15]
    let mut v = [0u64; 16];
    // v[0..7] := h[0..7]              // First half from state.
    v[..8].copy_from_slice(h);
    // v[8..15] := IV[0..7]            // Second half from IV.
    v[8..].copy_from_slice(&IV);

    // v[12] := v[12] ^ (t mod 2**w)   // Low word of the offset.
    v[12] ^= t as u64;
    // v[13] := v[13] ^ (t >> w)       // High word.
    // Mutants note: the high word of t is zero unless 2**64 or more bytes have been processed
    // (16 EiB), far beyond what a test can hash, so `^=` -> `|=` and `>>` -> `<<` here (both a
    // no-op on a zero high word) survive as equivalent on every testable input.
    v[13] ^= (t >> 64) as u64;

    // IF f = TRUE THEN                // last block flag?
    if f {
        // v[14] := v[14] ^ 0xFF..FF   // Invert all bits.
        v[14] ^= u64::MAX;
    }

    // // Cryptographic mixing
    // FOR i = 0 TO r - 1 DO           // Ten or twelve rounds.
    for i in 0..R {
        // s[0..15] := SIGMA[i mod 10][0..15]
        let s = &SIGMA[i % 10];

        // v := G( v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]] )
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        // v := G( v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]] )
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        // v := G( v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]] )
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        // v := G( v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]] )
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

        // v := G( v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]] )
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        // v := G( v, 1, 6, 11, 12, m[s[10]], m[s[11]] )
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        // v := G( v, 2, 7,  8, 13, m[s[12]], m[s[13]] )
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        // v := G( v, 3, 4,  9, 14, m[s[14]], m[s[15]] )
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    // FOR i = 0 TO 7 DO               // XOR the two halves.
    for i in 0..8 {
        // h[i] := h[i] ^ v[i] ^ v[i + 8]
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// RFC 7693 s. 3.3: the initial state for key length `kk`.
///
/// h[0..7] := IV[0..7]; h[0] := h[0] ^ 0x01010000 ^ (kk << 8) ^ nn (the parameter block p[0] of
/// s. 2.5, "p[0] = 0x0101kknn").
fn initial_h(kk: usize) -> Secret<[u64; 8]> {
    let mut h = Secret::<[u64; 8]>::new();
    // h[0..7] := IV[0..7]          // Initialization Vector.
    h.copy_from_slice(&IV);
    // // Parameter block p[0]
    // h[0] := h[0] ^ 0x01010000 ^ (kk << 8) ^ nn
    // Mutants note: 0x01010000, kk << 8 and nn occupy disjoint bytes of p[0] (s. 2.5
    // "0x0101kknn", with kk and nn below 256), so `^` -> `|` between them is an equivalent mutant.
    h[0] ^= 0x01010000 ^ ((kk as u64) << 8) ^ (NN as u64);
    h
}

/// The BLAKE2b engine shared by the hash and the MAC: RFC 7693 s. 3.3 processed incrementally, in
/// the shape of the Appendix C reference code.
///
/// Invariant: the buffer is compressed only when it is full *and* more input arrives, so the final
/// block d[dd-1] is always still in `buf` when [`Self::finalize`] runs and can be flagged
/// `f = TRUE`.
#[derive(Clone)]
struct Blake2bCore {
    /// The chaining state h[0..7].
    h: Secret<[u64; 8]>,
    /// s. 2.2: "Message byte offset at the end of the current block" -- the total of the bytes in
    /// every block compressed so far (key block included). s. 3.2 calls it a "2w-bit offset
    /// counter", which for w = 64 is a u128.
    t: u128,
    /// The current, not yet compressed, block. In keyed mode this is the padded key block `d[0]`
    /// exactly when `t == 0`.
    buf: Secret<[u8; BB]>,
    /// Number of valid bytes in `buf`, in `0..=BB`.
    buf_len: usize,
}

impl Blake2bCore {
    /// The unkeyed state (kk = 0).
    fn new_unkeyed() -> Self {
        Self { h: initial_h(0), t: 0, buf: Secret::new(), buf_len: 0 }
    }

    /// The keyed state. `key` must be 1..=64 bytes; the callers validate it.
    fn new_keyed(key: &[u8]) -> Self {
        debug_assert!(!key.is_empty() && key.len() <= MAX_KK);
        let mut core = Self { h: initial_h(key.len()), t: 0, buf: Secret::new(), buf_len: 0 };
        core.load_key_block(key);
        core
    }

    /// s. 3.3: "If a secret key is used (kk > 0), it is padded with zero bytes and set as `d[0]`."
    /// `d[0]` is left in the buffer as a full block, which is compressed as soon as any message
    /// byte arrives, or as the final block if none does
    /// (Appendix C.2 `blake2b_init`: `ctx->c = 128`).
    fn load_key_block(&mut self, key: &[u8]) {
        self.buf.fill(0);
        self.buf[..key.len()].copy_from_slice(key);
        self.buf_len = BB;
    }

    /// Absorbs `data`, compressing every block that is known not to be the last one.
    fn update(&mut self, data: &[u8]) {
        let mut data = data;
        let fill = BB - self.buf_len;

        // Only if `data` overflows the buffer is the buffered block known not to be final.
        if data.len() > fill {
            self.buf[self.buf_len..].copy_from_slice(&data[..fill]);
            data = &data[fill..];
            // s. 3.3: h := F( h, d[i], (i + 1) * bb, FALSE ) -- t is the byte offset at the end
            // of this block.
            self.add_to_t(BB);
            compress(&mut self.h, &self.buf, self.t, false);
            self.buf_len = 0;

            // Whole blocks straight from the input, keeping at least one byte back so that the
            // final block always ends up in the buffer: (len - 1) / bb blocks are each followed by
            // more input (e.g. 128 bytes -> 0 blocks, 129 -> 1, 256 -> 1).
            let num_blocks = data.len().saturating_sub(1) / BB;
            let (blocks, _) = data.as_chunks::<BB>();
            for block in &blocks[..num_blocks] {
                self.add_to_t(BB);
                compress(&mut self.h, block, self.t, false);
            }
            data = &data[num_blocks * BB..];
        }

        // What is left fits: data.len() <= BB - buf_len.
        self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
        self.buf_len += data.len();
    }

    /// `t += n`. s. 2.1 bounds the input at "0 <= ll < 2**128" bytes, which `t` (ll, plus bb in
    /// keyed mode) cannot exceed in practice; overflow is asserted in debug builds rather than
    /// silently wrapping into a different hash.
    fn add_to_t(&mut self, n: usize) {
        debug_assert!(self.t.checked_add(n as u128).is_some(), "BLAKE2b message too long");
        self.t = self.t.wrapping_add(n as u128);
    }

    /// RFC 7693 s. 3.3 final block, then "RETURN first "nn" bytes from little-endian word array
    /// h[]". Zeroizes all of `output`, writes `min(output.len(), nn)` bytes and returns that count.
    fn finalize(mut self, output: &mut [u8]) -> usize {
        // Final block: IF kk = 0 THEN h := F( h, d[dd - 1], ll, TRUE )
        //              ELSE       h := F( h, d[dd - 1], ll + bb, TRUE )
        // `t` already counts every compressed block (the key block included), so adding the bytes
        // of the last block gives ll, or ll + bb when keyed. The unkeyed empty message is the
        // s. 3.3 special case "d[0] consists of all zeros" with t = 0.
        self.add_to_t(self.buf_len);
        // "The final data block d[dd-1] is also padded with zero to "bb" bytes".
        self.buf[self.buf_len..].fill(0);
        compress(&mut self.h, &self.buf, self.t, true);

        output.fill(0);
        let n = *min(&output.len(), &NN);
        // Little-endian words, truncated to n bytes.
        for (chunk, word) in output[..n].chunks_mut(8).zip(self.h.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
        n
    }

    /// Serializes `h || t || buf || buf_len` (all little-endian) into `out`, which must be
    /// zeroed. `buf` is written as its first `buf_len` bytes followed by zeros, or as all zeros
    /// when `zero_buf` is set.
    fn write_state(&self, out: &mut [u8; CORE_STATE_LEN], zero_buf: bool) {
        let (words, _) = out[..64].as_chunks_mut::<8>();
        for (bytes, word) in words.iter_mut().zip(self.h.iter()) {
            *bytes = word.to_le_bytes();
        }
        out[64..80].copy_from_slice(&self.t.to_le_bytes());
        // Only the valid bytes: past buf_len the buffer still holds stale bytes of earlier
        // blocks -- in keyed mode, of the key block d[0] -- which must not leak into the state.
        if !zero_buf {
            out[80..80 + self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        }
        debug_assert!(self.buf_len <= BB);
        out[208] = self.buf_len as u8;
    }

    /// Inverse of [`Self::write_state`]. Rejects a `buf_len` larger than a block (a full block,
    /// `buf_len == bb`, is valid: it is compressed only when more input arrives) and a `t` that is
    /// not a whole number of blocks.
    fn read_state(input: &[u8; CORE_STATE_LEN]) -> Result<Self, SuspendableError> {
        let buf_len = input[208] as usize;
        if buf_len > BB {
            return Err(SuspendableError::InvalidData);
        }

        let mut h = Secret::<[u64; 8]>::new();
        let (words, _) = input[..64].as_chunks::<8>();
        for (hi, bytes) in h.iter_mut().zip(words) {
            *hi = u64::from_le_bytes(*bytes);
        }
        let mut t_bytes = [0u8; 16];
        t_bytes.copy_from_slice(&input[64..80]);
        let t = u128::from_le_bytes(t_bytes);
        // A compression only ever happens on a full block (s. 3.3 "(i + 1) * bb"), so at rest t is
        // a multiple of bb. For the keyed type this also rules out 0 < t < bb: the key block is
        // compressed first, with t = bb.
        if t % (BB as u128) != 0 {
            return Err(SuspendableError::InvalidData);
        }
        let mut buf = Secret::<[u8; BB]>::new();
        buf.copy_from_slice(&input[80..208]);

        Ok(Self { h, t, buf, buf_len })
    }
}

/// Length of the serialized engine state, without the version header.
const CORE_STATE_LEN: usize = 64 + 16 + BB + 1;

/// Length in bytes of the serialized state of [`BLAKE2b_512`].
///
/// Layout (after the 3-byte library version header; all integers little-endian):
///   [0   .. 64)   h        [u64; 8]
///   [64  .. 80)   t        u128 (RFC 7693 s. 2.2 byte offset)
///   [80  .. 208)  buf      [u8; 128]
///   [208 .. 209)  buf_len  u8 (always <= 128)
pub const SUSPENDED_BLAKE2B_512_STATE_LEN: usize = 3 + CORE_STATE_LEN;

/// Length in bytes of the serialized state of [`BLAKE2b_512_MAC`].
///
/// Same layout as [`SUSPENDED_BLAKE2B_512_STATE_LEN`], except that `buf` is written as zeros while
/// it holds the padded key block (`t == 0`), so the key never appears in the state. The two lengths
/// are equal today; depend on the one for the type you are suspending.
pub const SUSPENDED_BLAKE2B_512_MAC_STATE_LEN: usize = 3 + CORE_STATE_LEN;

/// The BLAKE2b hash with a 64-byte digest, unkeyed (RFC 7693, kk = 0, nn = 64).
///
/// See the [crate-level documentation](crate) for usage.
#[allow(non_camel_case_types)]
#[derive(Clone)]
pub struct BLAKE2b_512 {
    core: Blake2bCore,
}

impl BLAKE2b_512 {
    /// Creates a new BLAKE2b-512 instance, ready for use.
    pub fn new() -> Self {
        Self { core: Blake2bCore::new_unkeyed() }
    }
}

impl Default for BLAKE2b_512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash for BLAKE2b_512 {
    /// RFC 7693 s. 2.1: "Block bytes | bb = 128", so 1024 bits.
    fn block_bitlen(&self) -> usize {
        BB * 8
    }

    fn output_len(&self) -> usize {
        NN
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; NN];
        self.hash_out(data, &mut output);
        output
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    fn do_final(self) -> Vec<u8> {
        let mut output = vec![0u8; NN];
        self.do_final_out(&mut output);
        output
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        self.core.finalize(output)
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let mut output = vec![0u8; NN];
        self.do_final_partial_bits_out(partial_byte, num_bits, &mut output)?;
        Ok(output)
    }

    /// BLAKE2 is byte-oriented (RFC 7693 s. 2.1 counts "Input bytes"), so it has no encoding for a
    /// message that ends part-way through a byte.
    ///
    /// # Errors
    /// * [`HashError::InvalidLength`] if `num_bits > 7`, as for every [`Hash`].
    /// * [`HashError::InvalidInput`] if `num_bits` is in `1..=7`.
    ///
    /// `num_bits == 0` means the message ended on a byte boundary and is exactly
    /// [`Hash::do_final_out`]; `partial_byte` is ignored.
    ///
    /// This is the convention of Ascon-XOF128 / CXOF128 in this library. KMACXOF differs: it
    /// returns [`HashError::InvalidLength`] for every non-zero `num_bits`.
    fn do_final_partial_bits_out(
        self,
        _partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        output.fill(0);
        if num_bits > 7 {
            return Err(HashError::InvalidLength("num_partial_bits must be in the range [0,7]"));
        }
        if num_bits != 0 {
            return Err(HashError::InvalidInput(
                "BLAKE2 is byte-oriented (RFC 7693 s. 2.1) and cannot hash a partial final byte",
            ));
        }
        Ok(self.do_final_out(output))
    }

    /// RFC 7693 s. 4: BLAKE2b-512 has "Collision Security 2**256".
    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

impl Suspendable<SUSPENDED_BLAKE2B_512_STATE_LEN> for BLAKE2b_512 {
    fn suspend(self) -> [u8; SUSPENDED_BLAKE2B_512_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_BLAKE2B_512_STATE_LEN];
        let mut out = [0u8; CORE_STATE_LEN];
        self.core.write_state(&mut out, false);
        // add_lib_ver returns the CORE_STATE_LEN bytes after the 3-byte version header.
        add_lib_ver(&mut out_to_return).copy_from_slice(&out);
        out_to_return
    }

    /// # Errors
    /// * [`SuspendableError::IncompatibleVersion`] for a state from an incompatible library
    ///   version.
    /// * [`SuspendableError::InvalidData`] if the buffered length exceeds one block, if `t` is not
    ///   a whole number of blocks, or if a state taken before any compression (`t == 0`) does not
    ///   have the unkeyed initial `h` (for example a keyed state, or a tampered one).
    fn from_suspended(
        state: [u8; SUSPENDED_BLAKE2B_512_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        // At the moment, we have no not_before version to specify.
        // check_lib_ver returns the CORE_STATE_LEN bytes after the 3-byte version header.
        let mut input = [0u8; CORE_STATE_LEN];
        input.copy_from_slice(check_lib_ver(&state, None)?);
        let core = Blake2bCore::read_state(&input)?;
        // Before any compression h is exactly the unkeyed initial state (kk = 0), so anything else
        // is a state of a different parameter block -- such as a keyed one -- or a corrupt one.
        if core.t == 0 && *core.h != *initial_h(0) {
            return Err(SuspendableError::InvalidData);
        }
        Ok(Self { core })
    }
}

/// A BLAKE2b MAC key: RFC 7693 keyed BLAKE2b (kk = 1..=64, nn = 64), the key object for
/// [`BLAKE2b_512_MAC`].
///
/// This is the keyed BLAKE2b of the RFC ("BLAKE2BMAC" in OpenSSL), not HMAC-BLAKE2b. The key holds
/// the state after keyed initialisation (RFC 7693 s. 3.3), so every worker starts from it.
///
/// # Keys
/// Material must be tagged [`KeyType::MACKey`] (or be all-zero, [`KeyType::Zeroized`]) and be 1 to
/// 64 bytes (RFC 7693 s. 2.1 "0 <= kk <= 64"). Unlike HMAC, a zero-length key is refused:
/// kk = 0 is the unkeyed hash, [`BLAKE2b_512`].
#[allow(non_camel_case_types)]
#[derive(Clone)]
pub struct BLAKE2b_512_MACKey {
    /// The engine after keyed initialisation: h with kk bound into p[0], t = 0, and the padded
    /// key block `d[0]` in the buffer.
    core: Blake2bCore,
}

impl BLAKE2b_512_MACKey {
    /// Validates material in the order: type, security strength (unless `allow_weak_key`),
    /// length, and builds the key.
    ///
    /// The strength is checked before the length so that an over-long key with no security
    /// strength gets the strength error the shared test framework expects of every MAC key.
    fn from_checked(key: &dyn KeyMaterialTrait, allow_weak_key: bool) -> Result<Self, MACError> {
        // Same stance as HMAC and KMAC: an all-zero key is tagged Zeroized rather than MACKey,
        // and is let through so callers are not forced to re-tag it.
        if !(key.key_type() == KeyType::MACKey || key.key_type() == KeyType::Zeroized) {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "Key type must be a MAC key.",
            )));
        }
        if !allow_weak_key && key.security_strength() < SecurityStrength::_256bit {
            return Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(
                "BLAKE2b_512_MACKey: key has a lower security strength than BLAKE2b-512",
            )));
        }
        // RFC 7693 s. 2.1: "Key bytes | 0 <= kk <= 64". kk = 0 is the unkeyed hash, and there is
        // no pre-hashing of long keys as in HMAC.
        if key.key_len() == 0 || key.key_len() > MAX_KK {
            return Err(MACError::InvalidLength("BLAKE2b key must be 1 to 64 bytes"));
        }
        Ok(Self { core: Blake2bCore::new_keyed(key.ref_to_bytes()) })
    }
}

impl FromAnyKeyMaterial for BLAKE2b_512_MACKey {
    /// # Errors
    /// * [`MACError::KeyMaterialError`] with [`KeyMaterialError::InvalidKeyType`] unless the
    ///   material is [`KeyType::MACKey`] or [`KeyType::Zeroized`].
    /// * [`MACError::KeyMaterialError`] with [`KeyMaterialError::SecurityStrength`] if it is
    ///   tagged below 256 bits; [`Self::from_key_material_allow_weak`] skips this check.
    /// * [`MACError::InvalidLength`] unless it is 1 to 64 bytes.
    fn from_key_material(key: &dyn KeyMaterialTrait) -> Result<Self, MACError> {
        Self::from_checked(key, false)
    }

    /// As [`from_key_material`](Self::from_key_material) without the strength check.
    fn from_key_material_allow_weak(key: &dyn KeyMaterialTrait) -> Result<Self, MACError> {
        Self::from_checked(key, true)
    }

    /// Draws a 64-byte key from `rng`, tagged [`KeyType::MACKey`] at the RNG's strength capped
    /// at what the length carries.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the RNG fails, or with
    /// [`KeyMaterialError::SecurityStrength`] if its strength is below 256 bits.
    fn generate(rng: &mut dyn RNG) -> Result<Self, MACError> {
        let mut key = KeyMaterial::<MAX_KK>::new();
        do_hazardous_operations(&mut key, |key| {
            rng.next_bytes_out(key.ref_to_bytes_mut()?)
                .map_err(|_| KeyMaterialError::GenericError("RNG failed."))?;
            key.set_key_len(MAX_KK)?;
            key.set_key_type(KeyType::MACKey)?;
            // The RNG's strength, capped at what the length carries, as KMACKey::generate does.
            // Mutants note: at by_rng == by_len both arms give the same strength, so `<` -> `<=`
            // is an equivalent mutant.
            let by_len = SecurityStrength::from_bits(MAX_KK * 8);
            let by_rng = rng.security_strength();
            key.set_security_strength(if by_rng < by_len { by_rng } else { by_len })
        })?;
        Self::from_key_material(&key)
    }
}

impl MacGenerationKey for BLAKE2b_512_MACKey {
    type Generator<'k>
        = BLAKE2b_512_MAC
    where
        Self: 'k;

    fn create_generator<'k>(&'k self) -> Self::Generator<'k> {
        BLAKE2b_512_MAC { core: self.core.clone() }
    }
}

impl MacVerificationKey for BLAKE2b_512_MACKey {
    type Verifier<'k>
        = BLAKE2b_512_MAC
    where
        Self: 'k;

    fn create_verifier<'k>(&'k self) -> Self::Verifier<'k> {
        self.create_generator()
    }
}

/// The keyed BLAKE2b worker handed out by a [`BLAKE2b_512_MACKey`].
///
/// See the [crate-level documentation](crate) for usage.
#[allow(non_camel_case_types)]
#[derive(Clone)]
pub struct BLAKE2b_512_MAC {
    core: Blake2bCore,
}

impl MAC for BLAKE2b_512_MAC {
    fn output_len(&self) -> usize {
        NN
    }

    fn mac(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn mac_out(mut self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        self.do_update(data);
        self.do_final_out(out)
    }

    fn verify(mut self, data: &[u8], mac: &[u8]) -> bool {
        self.do_update(data);
        self.do_verify_final(mac)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    fn do_final(self) -> Vec<u8> {
        let mut out = vec![0u8; NN];
        self.core.finalize(&mut out);
        out
    }

    /// Zeroizes all of `out`, then writes the first `min(out.len(), 64)` bytes of the tag and
    /// returns that count. A truncated tag is the 64-byte tag cut short, not the RFC's BLAKE2b with
    /// a smaller nn (which binds nn into the parameter block, s. 2.5, and is a different function).
    ///
    /// # Errors
    /// [`MACError::InvalidLength`] if `out` is shorter than [`MIN_MAC_OUTPUT_LEN`].
    fn do_final_out(self, out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        if out.len() < MIN_MAC_OUTPUT_LEN {
            return Err(MACError::InvalidLength(
                "output buffer is shorter than MIN_MAC_OUTPUT_LEN (4 bytes)",
            ));
        }
        Ok(self.core.finalize(out))
    }

    /// Compares in constant time against the full 64-byte tag: a truncated or extended `mac` is
    /// not a match.
    fn do_verify_final(self, mac: &[u8]) -> bool {
        let computed = self.do_final();
        ct::ct_eq_bytes(&computed, mac)
    }

    /// RFC 7693 s. 4: BLAKE2b-512 has "Collision Security 2**256".
    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

/// The key is never written into the serialized state; resume takes the [`BLAKE2b_512_MACKey`]
/// again.
///
/// Before any message byte (`t == 0`) the buffer holds the padded key block, so `suspend` writes
/// zeros there and `from_suspended` rebuilds it from the key. Once a message byte arrives the key
/// is folded into `h`, and from then on the key passed to `from_suspended` is not used: resuming
/// with a different key gives the original MAC.
///
/// # 🚨 Security Considerations 🚨
/// Although it holds no key bytes, a suspended state with `t > 0` is a MAC oracle for every
/// extension of the absorbed prefix: its chaining value `h` alone finishes the MAC, so anyone
/// holding it can compute valid tags for any message that starts with that prefix. Protect it like
/// the key.
impl<'k> SuspendableKeyed<'k, SUSPENDED_BLAKE2B_512_MAC_STATE_LEN> for BLAKE2b_512_MAC {
    type Key = BLAKE2b_512_MACKey;

    fn suspend(self) -> [u8; SUSPENDED_BLAKE2B_512_MAC_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_BLAKE2B_512_MAC_STATE_LEN];
        let mut out = [0u8; CORE_STATE_LEN];
        // t == 0 exactly when buf still holds the key block d[0].
        self.core.write_state(&mut out, self.core.t == 0);
        // add_lib_ver returns the CORE_STATE_LEN bytes after the 3-byte version header.
        add_lib_ver(&mut out_to_return).copy_from_slice(&out);
        out_to_return
    }

    /// # Errors
    /// * [`SuspendableError::IncompatibleVersion`] for a state from an incompatible library
    ///   version.
    /// * [`SuspendableError::InvalidData`] if the buffered length exceeds one block or `t` is not
    ///   a whole number of blocks, or if a state taken before any input (`t == 0`) does not match
    ///   a fresh worker of `key` -- for example one from a key of a different length.
    fn from_suspended(
        state: [u8; SUSPENDED_BLAKE2B_512_MAC_STATE_LEN],
        key: &'k Self::Key,
    ) -> Result<Self, SuspendableError> {
        // At the moment, we have no not_before version to specify.
        // check_lib_ver returns the CORE_STATE_LEN bytes after the 3-byte version header.
        let mut input = [0u8; CORE_STATE_LEN];
        input.copy_from_slice(check_lib_ver(&state, None)?);
        let core = Blake2bCore::read_state(&input)?;

        if core.t == 0 {
            // Before any input the state is exactly the key's: h is the initial state for this
            // kk (bound into p[0], so a key of another length is caught) and buf is the full key
            // block. The serialized buffer is zeros, so the key's own state is taken as a whole.
            if core.buf_len != BB || *core.h != *key.core.h {
                return Err(SuspendableError::InvalidData);
            }
            return Ok(Self { core: key.core.clone() });
        }

        Ok(Self { core })
    }
}
