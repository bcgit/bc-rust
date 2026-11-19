//! CMAC, the block-cipher-based message authentication code of NIST SP 800-38B.
//!
//! [`Cmac`] implements [`MACGenerator`] (`Dir = Encrypting`) and [`MACVerifier`]
//! (`Dir = Decrypting`) over any [`BlockPermutation`] permutation with a 64- or 128-bit block (the
//! two block sizes SP 800-38B Sec 5.3 defines `R_b` for). The tag is one full block.
//!
//! The way onto it is a mode-bound key, built with `from_key_material`, which holds a
//! [`CmacKeyState`] -- the keyed permutation and the two subkeys, derived once -- and hands out
//! workers that borrow it through [`CMAC`], the marker a key type such as
//! `bouncycastle_aes::AES128Key<CMAC>` is bound to.
//!
//! # Usage Examples
//!
//! One-shot, and verifying, from a mode-bound key over `ToyBlockCipher` (see the
//! [module docs](super) for why); over the toy permutation the key is [`BlockCipherKey`](crate::BlockCipherKey),
//! the shape of the AES one:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_cipher::BlockCipherKey;
//! use bouncycastle_cipher::modes::CMAC;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
//!
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::MACKey).unwrap();
//! let key = BlockCipherKey::<ToyBlockCipher, CMAC>::from_key_material(&material).unwrap();
//! let tag: [u8; 16] = key.mac(b"a message");
//! assert!(key.verify(b"a message", &tag).is_ok());
//! ```
//!
//! Streaming:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_cipher::BlockCipherKey;
//! use bouncycastle_cipher::modes::CMAC;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey};
//! use bouncycastle_core::traits::MACGenerator;
//!
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::MACKey).unwrap();
//! let key = BlockCipherKey::<ToyBlockCipher, CMAC>::from_key_material(&material).unwrap();
//!
//! let mut cmac = key.create_generator();
//! cmac.do_update(b"a message that arrives ");
//! cmac.do_update(b"in pieces");
//! let mut tag = [0u8; 16];
//! assert_eq!(cmac.do_final_out(&mut tag), 16);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! * **Tag length** (Appendix A): a forger guesses a `Tlen`-bit tag with probability `2^-Tlen`, so
//!   shorter tags need a limit on failed verifications. The worker produces the full block; a
//!   protocol that truncates does so on the array it gets back, and takes on Appendix A.2's rule
//!   that "A value of Tlen that is less than 64 shall only be used in conjunction with a careful
//!   analysis of the risks". SP 800-38B Sec 5.5 also requires `Tlen` to be fixed for every use of
//!   a key; that is the caller's to keep.
//! * **Message span** (Appendix B): limit a key to 2^48 messages with a 128-bit block cipher, and
//!   2^21 with a 64-bit one.
//! * **Key separation** (Sec 5.2): the key "shall be used exclusively for the CMAC mode of the
//!   chosen block cipher", so the key's `from_key_material` accepts only a [`KeyType::MACKey`]
//!   key, never a [`KeyType::SymmetricCipherKey`] and not an all-zero (`Zeroized`) one.
//! * **Replay** (Appendix C): a valid tag says nothing about freshness; that is the protocol's job.
//!
//! [`KeyType::MACKey`]: bouncycastle_core::key_material::KeyType::MACKey
//! [`KeyType::SymmetricCipherKey`]: bouncycastle_core::key_material::KeyType::SymmetricCipherKey

use super::ModeNames;
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::MACError;
use bouncycastle_core::hazmat::{BlockPermutation, MacMode, Mode};
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, MACGenerator, MACVerifier};
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

/// The CMAC mode, as a key type names it: `AES128Key<CMAC>`. `BLOCK_LEN` is the permutation's
/// block length, 16 by default and 8 for a 64-bit block cipher; it is a parameter because stable
/// Rust cannot read it off the permutation from inside the mode impl, as for `CTR`. It is also
/// the tag length. The impls below are generic over any [`BlockPermutation`] of that block
/// length. A permutation that decrypts only (`BlockPermutation::DECRYPT_ONLY`) gets a verifier
/// and no generator: `generate_init` refuses it at compile time, as the encrypting constructors
/// of the cipher modes do, so a key over it can check tags and not produce them (SP 800-131A
/// Rev 2 Table 9: two-key TDEA CMAC generation "Disallowed", verification "Legacy use").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CMAC<const BLOCK_LEN: usize = 16>;

impl<P, const BLOCK_LEN: usize> Mode<P> for CMAC<BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames + Clone,
{
    type KeyState = CmacKeyState<P, BLOCK_LEN>;
    const KEY_TYPE: KeyType = KeyType::MACKey;

    fn key_state(perm: P) -> Self::KeyState {
        CmacKeyState::new(perm)
    }
}

impl<P, const BLOCK_LEN: usize> MacMode<P, BLOCK_LEN> for CMAC<BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames + Clone,
{
    type Generator<'k>
        = Cmac<'k, P, Encrypting, BLOCK_LEN>
    where
        P: 'k;
    type Verifier<'k>
        = Cmac<'k, P, Decrypting, BLOCK_LEN>
    where
        P: 'k;

    fn generate_init<'k>(state: &'k Self::KeyState) -> Self::Generator<'k> {
        const {
            assert!(
                !P::DECRYPT_ONLY,
                "this permutation decrypts only (BlockPermutation::DECRYPT_ONLY): no MAC generator may be made over it"
            )
        };
        Cmac::from_key_state(state)
    }

    fn verify_init<'k>(state: &'k Self::KeyState) -> Self::Verifier<'k> {
        Cmac::from_key_state(state)
    }
}

/// What a CMAC key keeps per key: the keyed permutation and the subkeys `K1` and `K2`
/// (Sec 6.1), derived once from `L = CIPH_K(0^b)` rather than per message.
#[derive(Clone)]
pub struct CmacKeyState<P, const BLOCK_LEN: usize> {
    perm: P,
    /// Subkey `K1` (Sec 6.1 step 2), applied to a complete final block.
    k1: Secret<[u8; BLOCK_LEN]>,
    /// Subkey `K2` (Sec 6.1 step 3), applied to a padded final block.
    k2: Secret<[u8; BLOCK_LEN]>,
}

// All three fields are compared, joined with `&` rather than `&&` so that the time taken does not
// say which of them differed; see `GcmKeyState` for the expectation on `P`.
impl<P: PartialEq, const BLOCK_LEN: usize> PartialEq for CmacKeyState<P, BLOCK_LEN> {
    fn eq(&self, other: &Self) -> bool {
        (self.perm == other.perm) & (self.k1 == other.k1) & (self.k2 == other.k2)
    }
}

impl<P: Eq, const BLOCK_LEN: usize> Eq for CmacKeyState<P, BLOCK_LEN> {}

impl<P, const BLOCK_LEN: usize> CmacKeyState<P, BLOCK_LEN> {
    /// The last byte of `R_b` (Sec 5.3): `R_128 = 0^120 || 10000111` and `R_64 = 0^59 || 11011`,
    /// every other byte zero. Any other block length fails to compile.
    const RB: u8 = match BLOCK_LEN {
        16 => 0x87,
        8 => 0x1B,
        _ => panic!("CMAC is defined for 64- and 128-bit block ciphers only (SP 800-38B Sec 5.3)"),
    };

    /// Derives the subkeys from an already-keyed permutation (Sec 6.1): [`CMAC`]'s `Mode` impl.
    pub(crate) fn new(perm: P) -> Self
    where
        P: BlockPermutation<BLOCK_LEN>,
    {
        // Step 1: L = CIPH_K(0^b). Sec 5.3: L "shall also be secret", so it is computed in place
        // in a `Secret`.
        let mut l: Secret<[u8; BLOCK_LEN]> = Secret::new();
        perm.encrypt_block(&mut l);
        // Steps 2 and 3.
        let mut k1: Secret<[u8; BLOCK_LEN]> = Secret::new();
        Self::dbl(&l, &mut k1);
        let mut k2: Secret<[u8; BLOCK_LEN]> = Secret::new();
        Self::dbl(&k1, &mut k2);
        Self { perm, k1, k2 }
    }

    /// Sec 6.1 steps 2 and 3: `out = x << 1` if `MSB_1(x) = 0`, else `(x << 1) (+) R_b`. The
    /// conditional XOR is done with a mask rather than a branch, since `x` is secret.
    fn dbl(x: &[u8; BLOCK_LEN], out: &mut [u8; BLOCK_LEN]) {
        let msb = x[0] >> 7;
        for i in 0..BLOCK_LEN - 1 {
            // The two operands share no bits, so `|` and `^` are interchangeable here.
            out[i] = (x[i] << 1) | (x[i + 1] >> 7);
        }
        out[BLOCK_LEN - 1] = (x[BLOCK_LEN - 1] << 1) ^ (Self::RB & 0u8.wrapping_sub(msb));
    }
}

/// CMAC (SP 800-38B) over the permutation `P`, with a `BLOCK_LEN` of 8 or 16 bytes, generating
/// (`Dir = Encrypting`) or verifying (`Dir = Decrypting`) a `BLOCK_LEN`-byte tag. See the module
/// docs.
pub struct Cmac<'k, P, Dir, const BLOCK_LEN: usize>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    key: &'k CmacKeyState<P, BLOCK_LEN>,
    /// `C_i` of Sec 6.2 step 6 for the blocks absorbed so far; `C_0 = 0^b` (step 5).
    c: Secret<[u8; BLOCK_LEN]>,
    /// The last `pending_len` bytes of message seen. Held back even when full, because only
    /// the final knows whether it is `M_n*` (step 4) and so which subkey it takes.
    pending: Secret<[u8; BLOCK_LEN]>,
    /// `0` only before any message byte has arrived; `1..=BLOCK_LEN` after.
    pending_len: usize,
    dir: PhantomData<Dir>,
}

impl<'k, P, Dir, const BLOCK_LEN: usize> Cmac<'k, P, Dir, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    /// Begins a MAC over a new message over a key state, which the worker borrows: the
    /// permutation and the subkeys stay in the key. [`CMAC`]'s `MacMode` impl.
    pub(crate) fn from_key_state(key: &'k CmacKeyState<P, BLOCK_LEN>) -> Self {
        Self { key, c: Secret::new(), pending: Secret::new(), pending_len: 0, dir: PhantomData }
    }

    /// Sec 6.2 step 6 for one block: `C_i = CIPH_K(C_{i-1} (+) M_i)`, in place in `c`.
    ///
    /// An associated function over the fields rather than a `&mut self` method, so that `pending`
    /// can be passed as `block` without first being copied out of its `Secret`.
    fn absorb(perm: &P, c: &mut Secret<[u8; BLOCK_LEN]>, block: &[u8; BLOCK_LEN]) {
        for (ci, mi) in c.iter_mut().zip(block.iter()) {
            *ci ^= mi;
        }
        perm.encrypt_block(c);
    }

    /// Absorbs every complete block except the last one seen, which stays pending until more data
    /// arrives or the final decides which subkey it takes: both directions' `do_update`.
    fn absorb_bytes(&mut self, mut data: &[u8]) {
        let take = (BLOCK_LEN - self.pending_len).min(data.len());
        self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&data[..take]);
        self.pending_len += take;
        data = &data[take..];
        if data.is_empty() {
            return;
        }

        // More data follows, so the (full) pending block is not the last one.
        Self::absorb(&self.key.perm, &mut self.c, &self.pending);
        while data.len() > BLOCK_LEN {
            let (block, rest) =
                data.split_first_chunk::<BLOCK_LEN>().expect("data.len() > BLOCK_LEN");
            Self::absorb(&self.key.perm, &mut self.c, block);
            data = rest;
        }
        self.pending[..data.len()].copy_from_slice(data);
        self.pending_len = data.len();
    }

    /// Sec 6.2 steps 4-6 for the final block, leaving `C_n` in `self.c`: `M_n = K1 (+) M_n*` if
    /// `M_n*` is complete, else `M_n = K2 (+) (M_n* || 10^j)`. An empty message (step 2's `n = 1`)
    /// is the incomplete case with an empty `M_n*`. Step 7 with `Tlen = b` is then `T = C_n`.
    fn finish(&mut self) {
        let subkey = if self.pending_len == BLOCK_LEN {
            &self.key.k1
        } else {
            self.pending[self.pending_len] = 0x80;
            self.pending[self.pending_len + 1..].fill(0);
            &self.key.k2
        };
        for (m, k) in self.pending.iter_mut().zip(subkey.iter()) {
            *m ^= k;
        }
        Self::absorb(&self.key.perm, &mut self.c, &self.pending);
    }
}

impl<'k, P, Dir, const BLOCK_LEN: usize> Algorithm for Cmac<'k, P, Dir, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    const ALG_NAME: &'static str = P::CMAC_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<'k, P, const BLOCK_LEN: usize> MACGenerator<BLOCK_LEN> for Cmac<'k, P, Encrypting, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    fn do_update(&mut self, data: &[u8]) {
        self.absorb_bytes(data)
    }

    /// The full `BLOCK_LEN`-byte tag, `T = C_n` (Sec 6.2 step 7 with `Tlen = b`).
    fn do_final_out(mut self, out: &mut [u8; BLOCK_LEN]) -> usize {
        self.finish();
        out.copy_from_slice(&self.c[..]);
        BLOCK_LEN
    }
}

impl<'k, P, const BLOCK_LEN: usize> MACVerifier<BLOCK_LEN> for Cmac<'k, P, Decrypting, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    fn do_update(&mut self, data: &[u8]) {
        self.absorb_bytes(data)
    }

    /// Sec 6.3: recomputes the tag and compares it in constant time.
    fn do_verify_final(mut self, mac: &[u8; BLOCK_LEN]) -> Result<(), MACError> {
        self.finish();
        if ct_eq_bytes(mac, &self.c[..]) { Ok(()) } else { Err(MACError::VerificationFailed) }
    }
}
