//! The projection that lets a padded mode alias take its direction *and* its padding scheme.
//!
//! `bouncycastle-padding` splits its adapters by direction: [`PaddedEncryptor`] wraps a
//! [`BlockCipherEncryptor`] and [`PaddedDecryptor`] a [`BlockCipherDecryptor`]. They are two
//! distinct types, and a plain type alias cannot choose between two types based on one of its own
//! parameters, so `AES_CBC_128<Dir, Pad>` cannot be written directly.
//!
//! [`PaddedMode`] does it instead. It is implemented for each direction marker, and its associated
//! type is the adapter for that direction, so an alias can be written as a projection through it:
//!
//! ```text
//! pub type AES_CBC_128<Dir, Pad> = <Dir as PaddedMode<
//!     Cbc<AES_128, Encrypting, 16, 16>,   // what Encrypting resolves to
//!     Cbc<AES_128, Decrypting, 16, 16>,   // what Decrypting resolves to
//!     Pad, 16, 16,
//! >>::Mode;
//! ```
//!
//! One trait serves every block mode, since it is parameterised by the encryptor and decryptor
//! types rather than by the mode: CBC passes its two directions and `INIT_DATA_LEN = BLOCK_LEN`,
//! ECB passes its two and `INIT_DATA_LEN = 0`.

use crate::BLOCK_LEN;
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, Padding};
use bouncycastle_modes::{Decrypting, Encrypting};
use bouncycastle_padding::{PaddedDecryptor, PaddedEncryptor};

/// Projects a direction marker onto the padded adapter for that direction.
///
/// Implemented for [`Encrypting`] and [`Decrypting`] and for nothing else, so those remain the only
/// usable values of a `Dir` parameter. See the module docs for why it exists.
///
/// `Enc` and `Dec` are the two directions of the underlying block mode, `Pad` is the padding
/// scheme, and `INIT_DATA_LEN` is the mode's: the block length for a mode with an IV, 0 for ECB.
pub trait PaddedMode<Enc, Dec, Pad, const KEY_LEN: usize, const INIT_DATA_LEN: usize>
where
    Enc: BlockCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    Dec: BlockCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    Pad: Padding<BLOCK_LEN>,
{
    /// The padded type for this direction: a [`PaddedEncryptor`] over `Enc`, or a
    /// [`PaddedDecryptor`] over `Dec`.
    type Mode;
}

impl<Enc, Dec, Pad, const KEY_LEN: usize, const INIT_DATA_LEN: usize>
    PaddedMode<Enc, Dec, Pad, KEY_LEN, INIT_DATA_LEN> for Encrypting
where
    Enc: BlockCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    Dec: BlockCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    Pad: Padding<BLOCK_LEN>,
{
    type Mode = PaddedEncryptor<Enc, Pad, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>;
}

impl<Enc, Dec, Pad, const KEY_LEN: usize, const INIT_DATA_LEN: usize>
    PaddedMode<Enc, Dec, Pad, KEY_LEN, INIT_DATA_LEN> for Decrypting
where
    Enc: BlockCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    Dec: BlockCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    Pad: Padding<BLOCK_LEN>,
{
    type Mode = PaddedDecryptor<Dec, Pad, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>;
}
