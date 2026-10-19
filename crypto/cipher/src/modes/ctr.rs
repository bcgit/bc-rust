//! The Counter mode of operation (NIST SP 800-38A §6.5).
//!
//! CTR mode (SP 800-38A Sec 6.5) applies the forward cipher to a sequence of counter blocks T1, T2, …, Tn
//! and XORs the resulting output blocks with the plaintext, so encryption and decryption are the same
//! operation, every block can be computed in parallel or ahead of time, and the last block may be
//! partial with no padding. This makes it a stream cipher.
//!
//! # The counter is finite, and running out is an error
//!
//! A `CTR_LEN`-byte counter has `2^(8 * CTR_LEN)` distinct values, so a message can be at most
//! that many blocks: 2^32 blocks (64 GiB) for a 4-byte counter, down to 256 blocks (4 KiB) for a
//! 1-byte one. SP 800-38A Appendix B.1 is explicit that this is the bound -- counter blocks "satisfy the
//! uniqueness requirement within the given message provided that `n <= 2^m`" -- and past it the
//! counter would repeat, which for a keystream mode means reusing keystream: the two-time-pad
//! failure, within a single message.
//!
//! So [`Ctr`] **refuses** rather than wraps. [`CtrKeyStream`] reports how many counter values are
//! left, and a call that would need more keystream than that returns
//! [`SymmetricCipherError::DataLimitExceeded`] and consumes nothing -- [`StreamCipher`] makes the check up
//! front, against the whole call, so a message is never half-encrypted before the mode notices.
//!
//! # Everything is parallel
//!
//! Sec 6.5: "In both CTR encryption and CTR decryption, the forward cipher functions can be
//! performed in parallel". Counter blocks depend on nothing but the nonce and the index, so unlike
//! CBC and CFB there is no feed-forward between blocks at all.
//! As such, both directions walk the block-aligned part of the data in fours through
//! [`ElectronicCodeBook::encrypt_4blocks`], then in pairs through [`ElectronicCodeBook::encrypt_2blocks`].
//! Only a leftover single block, and the keystream block for a short tail at the end, go one block at a time.
//!
//! Like the rest of CFB and CTR, only the **forward** cipher function is ever used, in both
//! directions, so a permutation that implements only `encrypt_block` works here.
//!
//! # Suspending and resuming execution
//!
//! [`Ctr`] implements [`SuspendableKeyed`](bouncycastle_core::traits::SuspendableKeyed), so a
//! message in progress can be suspended to a byte array and resumed later with the re-supplied key.
//! The state is the nonce, the next counter value and the partly used keystream block; the
//! permutation is rebuilt from the key. The array length is `Ctr::SUSPENDED_STATE_LEN`; see [the
//! crate docs](crate#suspending-and-resuming-execution) for an example.
//!
//! # 🚨 Security Considerations 🚨
//!
//! The one security requirement of CTR mode is that every counter block be distinct across all
//! messages ever encrypted under a key, since:
//!
//! > "if any plaintext block that is encrypted using a given counter block is known, then the output
//! > of the forward cipher function can be determined easily from the associated ciphertext block"
//!
//! and used to recover any other plaintext encrypted under that same counter. That is why [`Ctr`]
//! refuses to overflow the counter and returns a [`SymmetricCipherError::DataLimitExceeded`]
//! instead, and why the nonce is generated rather than accepted from the caller: within one
//! message the counter cannot repeat, and across messages a fresh random nonce is what keeps the
//! counter blocks distinct.

use crate::modes::ModeNames;
use crate::modes::hazmat::CtrKeyStream;
use crate::modes::iv::random_iv;
use crate::stream::StreamCipher;
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{
    ElectronicCodeBook, Mode, SymmetricDecryptMode, SymmetricEncryptMode,
};
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::secret::Secret;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
// end of imports needed for docs

/// The CTR mode type: the `M` of a mode-bound key such as `AES128Key<CTR>`, on the symmetric key
/// path with [`Ctr`] as its worker. `NONCE_LEN` is the init data length, `BLOCK_LEN - NONCE_LEN`
/// the counter width; the defaults are a 12-byte nonce on a 16-byte block, the `AES_CTR_*`
/// aliases' shape. The block length is a parameter because the nonce does not fix it, and
/// stable Rust cannot tie it to the permutation's from inside the mode impl. Its key state is the
/// keyed permutation alone.
pub struct CTR<const NONCE_LEN: usize = 12, const BLOCK_LEN: usize = 16>;

impl<P: Clone + ModeNames, const NONCE_LEN: usize, const BLOCK_LEN: usize> Mode<P>
    for CTR<NONCE_LEN, BLOCK_LEN>
{
    type KeyState = P;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;
    const ALG_NAME: &'static str = P::CTR_ALG_NAME;

    fn key_state(perm: P) -> Self::KeyState {
        perm
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const NONCE_LEN: usize>
    SymmetricEncryptMode<P, KEY_LEN, NONCE_LEN, 0> for CTR<NONCE_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
{
    type Encryptor = Ctr<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN>;

    fn encrypt_init(
        state: &Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor, [u8; NONCE_LEN]), SymmetricCipherError> {
        let nonce = random_iv::<NONCE_LEN>(rng)?;
        Ok((StreamCipher::from_keystream(CtrKeyStream::start(state.clone(), nonce)), nonce))
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const NONCE_LEN: usize>
    SymmetricDecryptMode<P, KEY_LEN, NONCE_LEN, 0> for CTR<NONCE_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
{
    type Decryptor = Ctr<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN>;

    fn decrypt_init(state: &Self::KeyState, init_data: &[u8; NONCE_LEN]) -> Self::Decryptor {
        StreamCipher::from_keystream(CtrKeyStream::start(state.clone(), *init_data))
    }
}

/// CTR mode over any [`ElectronicCodeBook`] permutation function, with the direction encoded in the type: the
/// [`CtrKeyStream`] wrapped in a [`StreamCipher`].
///
/// The counter block is the init data (the nonce) followed by a counter filling the rest of the
/// block, so `INIT_DATA_LEN` chooses the counter length; see the module docs. `Dir` is
/// [`Encrypting`] or [`Decrypting`].
///
/// # The counter width is checked at compile time
///
/// The counter must be at least one byte and at most four, so on a 16-byte block the nonce is 12,
/// 13, 14 or 15 bytes. Both bounds are inline `const` assertions in the constructors, so a nonce
/// length outside that range is a **compile** error at the call site rather than a runtime `Err`.
///
/// The permitted lengths all work, here through the mode type [`CTR`] a key is bound to:
///
/// ```
/// # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
/// # use toy::ToyBlockCipher;
/// use bouncycastle_core::hazmat::{ElectronicCodeBook, Mode, SymmetricEncryptMode};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_cipher::modes::CTR;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// let perm = ToyBlockCipher::new(&key).unwrap();
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// // 4-byte counter
/// let _ = CTR::<12>::encrypt_init(&<CTR<12> as Mode<ToyBlockCipher>>::key_state(perm.clone()), &mut rng).unwrap();
/// // 1-byte counter
/// let _ = CTR::<15>::encrypt_init(&<CTR<15> as Mode<ToyBlockCipher>>::key_state(perm), &mut rng).unwrap();
/// ```
pub type Ctr<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize> =
    StreamCipher<
        CtrKeyStream<P, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>,
        Dir,
        KEY_LEN,
        INIT_DATA_LEN,
        BLOCK_LEN,
    >;

/// XORs `Oj = CIPH_K(Tj)` into `blocks` for the next `blocks.len()` counter values, starting at
/// `*next` and advancing it past them, where `Tj = counter_block(j)`.
///
/// Shared by [`CtrKeyStream`] and CCM's keystream (SP 800-38C Sec 6.1 steps 5-7), which differ
/// only in how a counter block is formatted. Walks the blocks in fours through
/// [`ElectronicCodeBook::encrypt_4blocks`], then pairs, then a single block: the counter blocks
/// depend only on `j`, not on the data or on each other's cipher output, so the forward ciphers in
/// a batch are independent. This is the parallelism SP 800-38A Sec 6.5 describes, and it applies
/// to both directions.
///
/// The keystream scratch is one [`Secret`] per width and per call rather than per batch, so every
/// block of `Oj` is zeroized when this returns.
pub(crate) fn apply_counter_blocks<P, const KEY_LEN: usize, const BLOCK_LEN: usize>(
    perm: &P,
    next: &mut u64,
    counter_block: impl Fn(u64) -> [u8; BLOCK_LEN],
    blocks: &mut [[u8; BLOCK_LEN]],
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    let (fours, rest) = blocks.as_chunks_mut::<4>();
    let mut ks4: Secret<[[u8; BLOCK_LEN]; 4]> = Secret::new();
    for four in fours.iter_mut() {
        apply_batch(perm, next, &counter_block, four, &mut ks4, P::encrypt_4blocks);
    }
    let (pairs, single) = rest.as_chunks_mut::<2>();
    let mut ks2: Secret<[[u8; BLOCK_LEN]; 2]> = Secret::new();
    for pair in pairs.iter_mut() {
        apply_batch(perm, next, &counter_block, pair, &mut ks2, P::encrypt_2blocks);
    }
    let mut ks1: Secret<[[u8; BLOCK_LEN]; 1]> = Secret::new();
    for block in single.iter_mut() {
        apply_batch(perm, next, &counter_block, core::array::from_mut(block), &mut ks1, |p, b| {
            p.encrypt_block(&mut b[0])
        });
    }
}

/// One batch of [`apply_counter_blocks`]: builds `N` counter blocks into `keystream`, encrypts
/// them with one `batch` call, and XORs the result into `blocks`.
#[inline]
fn apply_batch<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const N: usize>(
    perm: &P,
    next: &mut u64,
    counter_block: &impl Fn(u64) -> [u8; BLOCK_LEN],
    blocks: &mut [[u8; BLOCK_LEN]; N],
    keystream: &mut [[u8; BLOCK_LEN]; N],
    batch: impl Fn(&P, &mut [[u8; BLOCK_LEN]; N]),
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    for slot in keystream.iter_mut() {
        *slot = counter_block(*next);
        *next += 1;
    }
    batch(perm, keystream);
    for (block, o) in blocks.iter_mut().zip(keystream.iter()) {
        for (b, o) in block.iter_mut().zip(o.iter()) {
            *b ^= *o;
        }
    }
}
