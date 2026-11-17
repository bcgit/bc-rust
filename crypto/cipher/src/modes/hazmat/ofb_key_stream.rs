//! The OFB keystream (NIST SP 800-38A Sec 6.4), [`OfbKeyStream`]: a raw [`KeyStream`], used
//! through [`Ofb`].

use crate::modes::ModeNames;
use bouncycastle_core::hazmat::{BlockPermutation, KeyStream};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;
use bouncycastle_utils::secret::Secret;

// Imports needed for docs
#[allow(unused_imports)]
use crate::modes::Ofb;
#[allow(unused_imports)]
use crate::stream::{KeyStreamPolicy, StreamCipher};
// end of imports needed for docs

/// The OFB keystream `Oj = CIPH_K(Ij)`, `I1 = IV`, `Ij = Oj-1` (SP 800-38A Sec 6.4) over any
/// [`BlockPermutation`]. Use it through [`Ofb`].
///
/// # 🚨 Security Considerations 🚨
/// A raw [`KeyStream`]: constructed directly, it takes the IV from the caller. See
/// [`KeyStream`]'s security notes and [`bouncycastle_core::hazmat`] for the supported uses.
///
/// # State
///
/// A reference to the permutation, which the key owns, and one block: `Oj-1`, which is both the
/// last keystream block produced and the input to the next cipher call.
pub struct OfbKeyStream<'k, P, const BLOCK_LEN: usize>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    perm: &'k P,
    /// `Ij`, the input block of the next forward cipher call: `I1 = IV` before the first call,
    /// then `Oj-1` (Sec 6.4, `Ij = Oj-1`). After the first call it is keystream, so a `Secret`.
    next_input: Secret<[u8; BLOCK_LEN]>,
}

impl<'k, P, const BLOCK_LEN: usize> OfbKeyStream<'k, P, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    /// `I1 = IV`, over a key's stored permutation, which the keystream borrows. What the
    /// [`OFB`](crate::modes::OFB) mode impls build.
    #[inline]
    pub fn from_perm(perm: &'k P, iv: [u8; BLOCK_LEN]) -> Self {
        let mut next_input: Secret<[u8; BLOCK_LEN]> = Secret::new();
        *next_input = iv;
        Self { perm, next_input }
    }
}

impl<'k, P, const BLOCK_LEN: usize> Algorithm for OfbKeyStream<'k, P, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    /// The permutation's name for this mode, [`ModeNames::OFB_ALG_NAME`].
    const ALG_NAME: &'static str = P::OFB_ALG_NAME;
    /// A mode does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<'k, P, const BLOCK_LEN: usize> crate::sealed::Sealed for OfbKeyStream<'k, P, BLOCK_LEN> where
    P: BlockPermutation<BLOCK_LEN> + ModeNames
{
}

impl<'k, P, const BLOCK_LEN: usize> KeyStreamPolicy for OfbKeyStream<'k, P, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    const DECRYPT_ONLY: bool = P::DECRYPT_ONLY;
}

impl<'k, P, const BLOCK_LEN: usize> KeyStream<BLOCK_LEN, BLOCK_LEN>
    for OfbKeyStream<'k, P, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    /// SP 800-38A sets no per-message limit for OFB.
    fn remaining_blocks(&self) -> u64 {
        u64::MAX
    }

    /// `Cj = Pj XOR Oj` (or `Pj = Cj XOR Oj`, the same operation) for the next `blocks.len()`
    /// blocks.
    fn apply_blocks(&mut self, blocks: &mut [[u8; BLOCK_LEN]]) {
        // One block at a time, never through `encrypt_2blocks` / `encrypt_4blocks`: Sec 6.4, "each
        // forward cipher function (except the first) depends on the results of the previous
        // forward cipher function; therefore, multiple forward cipher functions cannot be
        // performed in parallel."
        for block in blocks.iter_mut() {
            // `Oj = CIPH_K(Ij)`, in place, so `next_input` now holds `Oj`, which is `Ij+1`.
            self.perm.encrypt_block(&mut self.next_input);
            // `Cj = Pj XOR Oj`.
            for (b, o) in block.iter_mut().zip(self.next_input.iter()) {
                *b ^= *o;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for [`OfbKeyStream`], which is `pub(crate)` and so cannot be reached from
    //! `tests/modes/ofb_tests.rs`; the same carve-out as `ctr_key_stream.rs`'s.

    use super::*;
    use crate::modes::modes_common::{ForwardOnlyToy, TOY_LEN, Toy};
    use bouncycastle_core::hazmat::KeyExpansion;
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core_test_framework::key_stream::TestFrameworkKeyStream;

    fn key() -> KeyMaterial<16> {
        KeyMaterial::<16>::from_bytes_as_type(&[0x5Au8; 16], KeyType::SymmetricCipherKey)
            .expect("a valid 16-byte key")
    }

    /// The keystream under the mode, on its own, over the toy and over [`ForwardOnlyToy`], so
    /// that the keystream is shown to need no inverse cipher.
    #[test]
    fn ofb_keystream_conforms_to_the_key_stream_framework() {
        let framework = TestFrameworkKeyStream::new();
        let toy = Toy::new(&key()).unwrap();
        framework
            .test::<TOY_LEN, TOY_LEN, _>(|iv| OfbKeyStream::<Toy, TOY_LEN>::from_perm(&toy, *iv));
        let forward_only = ForwardOnlyToy::new(&key()).unwrap();
        framework.test::<TOY_LEN, TOY_LEN, _>(|iv| {
            OfbKeyStream::<ForwardOnlyToy, TOY_LEN>::from_perm(&forward_only, *iv)
        });
    }

    /// The keystream reports the permutation's OFB name, not its bare `ALG_NAME`; `Ofb` forwards
    /// it, which `tests/modes/alg_name_tests.rs` checks.
    #[test]
    fn ofb_keystream_reports_the_ofb_name() {
        assert_eq!(OfbKeyStream::<Toy, 16>::ALG_NAME, Toy::OFB_ALG_NAME);
        assert_eq!(OfbKeyStream::<Toy, 16>::MAX_SECURITY_STRENGTH, Toy::MAX_SECURITY_STRENGTH);
    }

    /// `remaining_blocks` is `u64::MAX` before and after use: OFB has no per-message limit.
    #[test]
    fn ofb_keystream_reports_no_limit() {
        let toy = Toy::new(&key()).unwrap();
        let mut ks = OfbKeyStream::<Toy, TOY_LEN>::from_perm(&toy, [0u8; TOY_LEN]);
        assert_eq!(ks.remaining_blocks(), u64::MAX);
        ks.apply_blocks(&mut [[0u8; TOY_LEN]; 3]);
        assert_eq!(ks.remaining_blocks(), u64::MAX);
    }
}
