//! The shared test suites for a block cipher crate: everything that holds of `BlockCipherKey<P, M>`
//! for any 128-bit-block permutation `P`, so that AES, ARIA, Camellia, SM4 and the next cipher run
//! one copy of it rather than each carrying its own. A cipher crate's own tests keep what is the
//! cipher's: its known answers, its aliases and its sizes.
//!
//! * [`mode_keys`] -- the keys under every mode through the `core-test-framework` conformance
//!   suites, and what tells the modes apart on the key path.
//! * [`padded`] -- padded CBC through the key: the padding parameter selects the scheme.
//! * [`stream`] -- CFB, CFB8 and CTR through the key: any length, any chunking, a fresh IV, and
//!   the three modes distinct.
//! * [`wycheproof`] -- the Project Wycheproof CBC-PKCS5, CCM, GCM, CMAC and key-wrap sets, run
//!   through the key at one key length per call.
//!
//! Sits beside `bouncycastle-core-test-framework` rather than inside it because it names the
//! cipher crate's types, and that crate's own tests depend on the core framework. Only ever a
//! dev-dependency.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod material;
pub mod mode_keys;
pub mod padded;
pub mod stream;
pub mod wycheproof;

use bouncycastle_cipher::modes::ModeNames;
use bouncycastle_core::hazmat::ElectronicCodeBook;

/// What every suite here asks of the permutation: a 128-bit block, the key length the suite is
/// instantiated at, and the mode names.
pub trait Permutation<const KEY_LEN: usize>:
    ElectronicCodeBook<KEY_LEN, 16> + ModeNames + Clone
{
}

impl<P, const KEY_LEN: usize> Permutation<KEY_LEN> for P where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames + Clone
{
}
