//! The block, round-key and field-element types every back end's kernels take. They are plain
//! arrays, the same on every architecture, so the x86_64 back end will add nothing here; it takes
//! and returns these as `arm64_le` does.

/// The AES block length in bytes (FIPS 197 Sec 3.4: `Nb = 4` words).
pub const BLOCK_LEN: usize = 16;

/// One AES block.
pub type Block = [u8; BLOCK_LEN];

/// Round keys for AES-128: `4 * (Nr + 1)` words with `Nr = 10`, as 11 blocks.
pub type RoundKeys128 = [Block; 11];
/// Round keys for AES-192: `Nr = 12`, 13 blocks.
pub type RoundKeys192 = [Block; 13];
/// Round keys for AES-256: `Nr = 14`, 15 blocks.
pub type RoundKeys256 = [Block; 15];

/// A block of `GF(2^128)` as two big-endian `u64`s, the form `bouncycastle-cipher`'s GHASH uses.
pub type Element = [u64; 2];
