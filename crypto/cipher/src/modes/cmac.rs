//! CMAC, the block-cipher-based message authentication code of NIST SP 800-38B.
//!
//! [`Cmac`] implements [`MAC`] over any [`ElectronicCodeBook`] permutation with a 64- or 128-bit
//! block (the two block sizes SP 800-38B Sec 5.3 defines `R_b` for). The output is one full block,
//! which [`MAC::mac_out`] / [`MAC::do_final_out`] truncate to the caller's buffer, down to
//! [`CMAC_MIN_TAG_LEN`] bytes.
//!
//! The way onto it is a mode-bound key, built with `from_key_material`, which holds a
//! [`CmacKeyState`] -- the keyed permutation and the two subkeys, derived once -- and hands out
//! workers through [`CMAC`], the marker a key type such as `bouncycastle_aes::AES128Key<CMAC>` is
//! bound to.
//!
//! # Usage Examples
//!
//! One-shot, and verifying, from a key state -- what a mode-bound key holds -- over
//! `ToyBlockCipher` (see the [module docs](super) for why):
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_cipher::modes::{Cmac, CmacKeyState};
//! use bouncycastle_core::hazmat::ElectronicCodeBook;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::MAC;
//!
//! type ToyCmac = Cmac<ToyBlockCipher, 16, 16>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let state = CmacKeyState::new::<16>(ToyBlockCipher::new(&key).unwrap());
//! let tag = ToyCmac::from_key_state(&state).mac(b"a message");
//! assert_eq!(tag.len(), 16);
//! assert!(ToyCmac::from_key_state(&state).verify(b"a message", &tag));
//! ```
//!
//! Streaming, with a tag truncated to 8 bytes:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_cipher::modes::{Cmac, CmacKeyState};
//! use bouncycastle_core::hazmat::ElectronicCodeBook;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::MAC;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let state = CmacKeyState::new::<16>(ToyBlockCipher::new(&key).unwrap());
//!
//! let mut cmac = Cmac::<ToyBlockCipher, 16, 16>::from_key_state(&state);
//! cmac.do_update(b"a message that arrives ");
//! cmac.do_update(b"in pieces");
//! let mut tag = [0u8; 8];
//! assert_eq!(cmac.do_final_out(&mut tag).unwrap(), 8);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! * **Tag length** (Appendix A): a forger guesses a `Tlen`-bit tag with probability `2^-Tlen`, so
//!   shorter tags need a limit on failed verifications. Truncation below 64 bits is refused
//!   ([`CMAC_MIN_TAG_LEN`]). SP 800-38B Sec 5.5 also requires `Tlen` to be fixed for every use of
//!   a key; that is the caller's to keep.
//! * **Message span** (Appendix B): limit a key to 2^48 messages with a 128-bit block cipher, and
//!   2^21 with a 64-bit one.
//! * **Key separation** (Sec 5.2): the key "shall be used exclusively for the CMAC mode of the
//!   chosen block cipher", so the key's `from_key_material` accepts only a [`KeyType::MACKey`]
//!   key (or an all-zero key, as HMAC does), never a [`KeyType::SymmetricCipherKey`].
//! * **Replay** (Appendix C): a valid tag says nothing about freshness; that is the protocol's job.

use super::ModeNames;
use alloc::vec::Vec;
use bouncycastle_core::errors::{KeyMaterialError, MACError, SuspendableError};
use bouncycastle_core::hazmat::{ElectronicCodeBook, do_hazardous_operations};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, MAC, SuspendableKeyed};
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::suspendable_state::{add_lib_ver, check_lib_ver};

/// The shortest tag [`MAC::mac_out`] / [`MAC::do_final_out`] will truncate to: 64 bits, the length
/// SP 800-38B Appendix A.2 says "should provide sufficient protection against guessing attacks" for
/// most applications ("A value of Tlen that is less than 64 shall only be used in conjunction with
/// a careful analysis of the risks").
pub const CMAC_MIN_TAG_LEN: usize = 8;

/// The CMAC mode, as a key type names it: `AES128Key<CMAC>`. The mode-trait impls over each
/// permutation live with that permutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CMAC;

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

impl<P, const BLOCK_LEN: usize> CmacKeyState<P, BLOCK_LEN> {
    /// The last byte of `R_b` (Sec 5.3): `R_128 = 0^120 || 10000111` and `R_64 = 0^59 || 11011`,
    /// every other byte zero. Any other block length fails to compile.
    const RB: u8 = match BLOCK_LEN {
        16 => 0x87,
        8 => 0x1B,
        _ => panic!("CMAC is defined for 64- and 128-bit block ciphers only (SP 800-38B Sec 5.3)"),
    };

    /// Derives the subkeys from an already-keyed permutation (Sec 6.1).
    pub fn new<const KEY_LEN: usize>(perm: P) -> Self
    where
        P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
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

/// CMAC (SP 800-38B) over the permutation `P`, keyed by a `KEY_LEN`-byte key, with a `BLOCK_LEN`
/// of 8 or 16 bytes. See the module docs.
pub struct Cmac<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    key: CmacKeyState<P, BLOCK_LEN>,
    /// `C_i` of Sec 6.2 step 6 for the blocks absorbed so far; `C_0 = 0^b` (step 5).
    c: Secret<[u8; BLOCK_LEN]>,
    /// The last `pending_len` bytes of message seen. Held back even when full, because only
    /// `do_final` knows whether it is `M_n*` (step 4) and so which subkey it takes.
    pending: Secret<[u8; BLOCK_LEN]>,
    /// `0` only before any message byte has arrived; `1..=BLOCK_LEN` after.
    pending_len: usize,
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> Cmac<P, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    /// Length of the [`SuspendableKeyed`] state: the three-byte library version, `C_i`, the
    /// pending block, and its length.
    pub const SUSPENDED_STATE_LEN: usize = 3 + 2 * BLOCK_LEN + 1;

    /// Begins a MAC over a new message from a key state, which is cloned into the worker.
    pub fn from_key_state(state: &CmacKeyState<P, BLOCK_LEN>) -> Self
    where
        P: Clone,
    {
        Self::from_owned_state(state.clone())
    }

    fn from_owned_state(key: CmacKeyState<P, BLOCK_LEN>) -> Self {
        Self { key, c: Secret::new(), pending: Secret::new(), pending_len: 0 }
    }

    /// Validates `key` and derives the subkeys. The checks run type, then strength, then length,
    /// so a short-strength key is reported as such whatever its length.
    fn init(
        key: &(impl KeyMaterialTrait + ?Sized),
        allow_weak_key: bool,
    ) -> Result<Self, MACError> {
        if !(key.key_type() == KeyType::MACKey || key.key_type() == KeyType::Zeroized) {
            return Err(KeyMaterialError::InvalidKeyType("CMAC: key type must be a MAC key").into());
        }
        if !allow_weak_key && key.security_strength() < P::MAX_SECURITY_STRENGTH {
            return Err(KeyMaterialError::SecurityStrength(
                "CMAC: provided key has a lower security strength than the block cipher",
            )
            .into());
        }
        if key.key_len() != KEY_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }

        // `P::new` accepts only a full-strength `SymmetricCipherKey`. The MAC key's type, strength
        // and length were checked above, so this copy is retagged to pass that gate and is used for
        // nothing else; `P::new` then has nothing left to reject.
        let mut cipher_key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            key.ref_to_bytes(),
            KeyType::SymmetricCipherKey,
        )?;
        do_hazardous_operations(&mut cipher_key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(P::MAX_SECURITY_STRENGTH)
        })?;
        let perm = P::new(&cipher_key)
            .map_err(|_| MACError::GenericError("CMAC: the block cipher rejected the key"))?;

        Ok(Self::from_owned_state(CmacKeyState::new(perm)))
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

    /// Sec 6.2 steps 4-6 for the final block, leaving `C_n` in `self.c`: `M_n = K1 (+) M_n*` if
    /// `M_n*` is complete, else `M_n = K2 (+) (M_n* || 10^j)`. An empty message (step 2's `n = 1`)
    /// is the incomplete case with an empty `M_n*`.
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

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> Algorithm for Cmac<P, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    const ALG_NAME: &'static str = P::CMAC_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> MAC for Cmac<P, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    fn output_len(&self) -> usize {
        BLOCK_LEN
    }

    fn mac(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn mac_out(mut self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError> {
        self.do_update(data);
        self.do_final_out(out)
    }

    fn verify(mut self, data: &[u8], mac: &[u8]) -> bool {
        self.do_update(data);
        self.do_verify_final(mac)
    }

    /// Absorbs every complete block except the last one seen, which stays pending until more data
    /// arrives or [`MAC::do_final`] decides which subkey it takes.
    fn do_update(&mut self, mut data: &[u8]) {
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

    /// The full `BLOCK_LEN`-byte tag.
    fn do_final(mut self) -> Vec<u8> {
        self.finish();
        self.c.to_vec()
    }

    /// Sec 6.2 step 7, `T = MSB_Tlen(C_n)`, with `Tlen` the length of `out` up to `BLOCK_LEN`.
    ///
    /// # Errors
    /// [`MACError::InvalidLength`] if `out` is shorter than [`CMAC_MIN_TAG_LEN`].
    fn do_final_out(mut self, out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        if out.len() < CMAC_MIN_TAG_LEN {
            return Err(MACError::InvalidLength(
                "CMAC: tags shorter than 64 bits are not supported (SP 800-38B Appendix A.2)",
            ));
        }
        self.finish();
        let n = out.len().min(BLOCK_LEN);
        out[..n].copy_from_slice(&self.c[..n]);
        Ok(n)
    }

    /// Sec 6.3: recomputes the full tag and compares it in constant time. A truncated `mac` never
    /// matches, as the trait requires.
    fn do_verify_final(mut self, mac: &[u8]) -> bool {
        self.finish();
        mac.len() == BLOCK_LEN && ct_eq_bytes(mac, &self.c[..])
    }

    fn max_security_strength(&self) -> SecurityStrength {
        P::MAX_SECURITY_STRENGTH
    }
}

/// The state is `C_i` and the pending block; the subkeys are recomputed from the re-supplied key,
/// which must be the one the suspended `Cmac` was created with -- a different key cannot be
/// detected and silently produces a wrong tag. As for HMAC, the key's security strength is not
/// re-checked on resume.
///
/// `STATE_LEN` must be [`Cmac::SUSPENDED_STATE_LEN`]; any other value fails to compile.
impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const STATE_LEN: usize>
    SuspendableKeyed<STATE_LEN> for Cmac<P, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    type Key = dyn KeyMaterialTrait;

    fn suspend(self) -> [u8; STATE_LEN] {
        const {
            assert!(
                STATE_LEN == 3 + 2 * BLOCK_LEN + 1,
                "STATE_LEN must be Cmac::SUSPENDED_STATE_LEN"
            )
        };
        let mut state = [0u8; STATE_LEN];
        let body = add_lib_ver(&mut state);
        body[..BLOCK_LEN].copy_from_slice(&self.c[..]);
        body[BLOCK_LEN..2 * BLOCK_LEN].copy_from_slice(&self.pending[..]);
        // `pending_len <= BLOCK_LEN <= 16`, so it fits in a byte.
        body[2 * BLOCK_LEN] = self.pending_len as u8;
        state
    }

    /// # Errors
    /// [`SuspendableError::IncompatibleVersion`] for a state from an incompatible library version,
    /// and [`SuspendableError::InvalidData`] for a malformed state or a key the CMAC key's
    /// `from_key_material_allow_weak` would reject.
    fn from_suspended(state: [u8; STATE_LEN], key: &Self::Key) -> Result<Self, SuspendableError> {
        const {
            assert!(
                STATE_LEN == 3 + 2 * BLOCK_LEN + 1,
                "STATE_LEN must be Cmac::SUSPENDED_STATE_LEN"
            )
        };
        let body = check_lib_ver(&state, None)?;
        let pending_len = body[2 * BLOCK_LEN] as usize;
        if pending_len > BLOCK_LEN {
            return Err(SuspendableError::InvalidData);
        }
        let mut cmac = Self::init(key, true).map_err(|_| SuspendableError::InvalidData)?;
        cmac.c.copy_from_slice(&body[..BLOCK_LEN]);
        cmac.pending.copy_from_slice(&body[BLOCK_LEN..2 * BLOCK_LEN]);
        cmac.pending_len = pending_len;
        Ok(cmac)
    }
}
