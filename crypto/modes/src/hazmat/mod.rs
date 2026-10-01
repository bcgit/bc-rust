//! Raw primitives whose safe use is the caller's responsibility; see [`bouncycastle_core::hazmat`]
//! for what the path means and the supported uses.
//!
//! [`CtrKeyStream`] is the keystream under [`Ctr`](crate::Ctr). Constructed directly it takes the
//! nonce from the caller; [`Ctr`](crate::Ctr) generates the nonce and refuses to run past the
//! counter, and is the cipher to use.
//!
//! [`Ecb`] is the permutation applied block by block. It implements the block-cipher traits like
//! [`Cbc`](crate::Cbc) does, so it looks like a cipher, and it is not one: equal plaintext blocks
//! give equal ciphertext blocks. It is here for interoperability and test vectors.

mod ctr_key_stream;
mod ecb;

pub use ctr_key_stream::CtrKeyStream;
pub use ecb::Ecb;
