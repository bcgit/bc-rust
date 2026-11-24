//! SM2 public key encryption (GB/T 32918.4-2016) with SM3: the key pair and its methods. See
//! [`crate::sm2`] for usage, memory figures and the security considerations.
//!
//! A ciphertext has three parts: `C1`, the point `[k]G` in the uncompressed form
//! `04 || x1 || y1`; `C3`, an SM3 hash value over the message and the shared point; and `C2`,
//! the message under a key stream, as long as the message. The detached pair,
//! [`SM2EncryptionPublicKey::encrypt_detached_inplace`] and
//! [`SM2EncryptionPrivateKey::decrypt_detached_inplace`], works on the message where it lies
//! and hands `C1` and `C3` over as arrays. The `_out` forms lay the parts out in one buffer:
//! `C1 || C3 || C2`, the order of GB/T 32918.4-2016 and GM/T 0003.4-2012, or with `c1c2c3` in
//! the name `C1 || C2 || C3`, the order of `draft-shen-sm2-ecdsa-02` and the default of Bouncy
//! Castle Java's `SM2Engine`. Nothing in a ciphertext says which order it is in.
//!
//! The hash is SM3. Encryption writes `C1` uncompressed. Decryption also accepts the hybrid form
//! `06 || x1 || y1` or `07 || x1 || y1`, the tag giving the parity of `y1`, which must match;
//! both forms are in GB/T 32918.1-2016 Section 4.2.10 (4.2.9 in the English translation of
//! GM/T 0003.1-2012, which numbers the conversions one lower). The compressed form, 33 bytes,
//! is refused: `C1` here is 65 bytes in every API. There is no ASN.1 form here.
//!
//! Decryption makes the standard's test for an all-zero key stream (step B4), so a ciphertext
//! from a sender that does not make the matching retry of step A5 is refused when its key
//! stream is all zero, about one one-byte message in 256; Bouncy Castle Java's `SM2Engine`
//! makes no such test when it decrypts.

use crate::hazmat::sm2::Sm2FieldElement;
use crate::hazmat::sm2_comb::comb_multiply_base_point;
use crate::hazmat::sm2_scalar::Sm2Scalar;
use crate::hazmat::sm2_sec1;
use crate::sm2::encryption_core::{self, KEY_WIPED_STACK_WORDS, WipeStackBelowOnDrop};
use crate::sm2::extra_bits::{N_MINUS_1_LIMBS, reduce_wide_bits_mod_n_minus_2};
use crate::sm2::keys::{EXTRA_BITS_DRBG_OUTPUT_LEN, PK_LEN, SK_LEN};
use crate::stack_wipe::wipe_stack_below;
use bouncycastle_core::errors::{KeyDecodingError, PublicKeyEncryptionError, RNGError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{PrivateKey, PublicKey, RNG};
use bouncycastle_utils::nat;
use bouncycastle_utils::secret::{Secret, zeroize_in_place};
use core::fmt;
use core::fmt::{Display, Formatter};

/// Length of `C1`: a point in the uncompressed form, `04 || x1 || y1`, or on decryption the
/// hybrid form, `06` or `07` for `04`.
pub const C1_LEN: usize = encryption_core::C1_LEN;

/// Length of `C3`: an SM3 hash value.
pub const C3_LEN: usize = encryption_core::C3_LEN;

/// How much longer a ciphertext is than its message: `C1` and `C3`.
pub const OVERHEAD_LEN: usize = C1_LEN + C3_LEN;

/// The two orders a ciphertext's parts are laid out in.
#[derive(Clone, Copy)]
enum Order {
    /// `C1 || C3 || C2`.
    C1C3C2,
    /// `C1 || C2 || C3`.
    C1C2C3,
}

impl Order {
    /// Where `C3` and `C2` lie in a ciphertext of `C2` length `c2_len`, after `C1`.
    fn ranges(self, c2_len: usize) -> (core::ops::Range<usize>, core::ops::Range<usize>) {
        match self {
            Order::C1C3C2 => (C1_LEN..OVERHEAD_LEN, OVERHEAD_LEN..OVERHEAD_LEN + c2_len),
            Order::C1C2C3 => (C1_LEN + c2_len..OVERHEAD_LEN + c2_len, C1_LEN..C1_LEN + c2_len),
        }
    }
}

/// An SM2 public key for encryption: `PB = [dB]G`, a point on the curve other than the point at
/// infinity, which decoding checks. The encoding is that of [`crate::sm2::keys::SM2PublicKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SM2EncryptionPublicKey {
    x: Sm2FieldElement,
    y: Sm2FieldElement,
}

impl SM2EncryptionPublicKey {
    /// Encrypts the message in `buf` where it lies: `buf` holds the message on entry and `C2`
    /// on return, and `C1` and `C3` are returned. Each call draws a fresh `k` from `rng`, so two
    /// encryptions of one message differ.
    ///
    /// # Errors
    /// [`PublicKeyEncryptionError::InvalidInputLength`] for an empty message, or one of
    /// `(2^32 - 1) * 32` bytes or more; [`PublicKeyEncryptionError::RNGError`] if `rng` offers
    /// less than 128 bits of security strength or fails to deliver; and
    /// [`PublicKeyEncryptionError::EncryptionFailed`] if sixteen draws from `rng` in a row
    /// each gave a key stream of all zeros, which for a one-byte message has probability about
    /// `2^-128`, estimated with SM3 as an ideal hash and the draws as independent. After any
    /// error `buf` holds the message as it was given.
    pub fn encrypt_detached_inplace(
        &self,
        rng: &mut dyn RNG,
        buf: &mut [u8],
    ) -> Result<([u8; C1_LEN], [u8; C3_LEN]), PublicKeyEncryptionError> {
        encryption_core::encrypt_detached_inplace(&self.x, &self.y, rng, buf)
    }

    /// The length of the ciphertext of a message of `plaintext_len` bytes, which is what
    /// [`encrypt_out`](Self::encrypt_out) needs of its output buffer.
    pub fn encrypt_out_len(&self, plaintext_len: usize) -> usize {
        plaintext_len.saturating_add(OVERHEAD_LEN)
    }

    /// Encrypts `plaintext` into `out` as `C1 || C3 || C2`, the order of GB/T 32918.4-2016, and
    /// returns the number of bytes written, `plaintext.len() + OVERHEAD_LEN`. `out` is
    /// zeroized first, and is all zero after an error.
    ///
    /// # Errors
    /// [`PublicKeyEncryptionError::OutputBufferTooSmall`] if `out` is shorter than
    /// [`encrypt_out_len`](Self::encrypt_out_len), and those of
    /// [`encrypt_detached_inplace`](Self::encrypt_detached_inplace).
    pub fn encrypt_out(
        &self,
        rng: &mut dyn RNG,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PublicKeyEncryptionError> {
        self.encrypt_ordered_out(Order::C1C3C2, rng, plaintext, out)
    }

    /// As [`encrypt_out_len`](Self::encrypt_out_len), for
    /// [`encrypt_c1c2c3_out`](Self::encrypt_c1c2c3_out); the two orders are the same length.
    pub fn encrypt_c1c2c3_out_len(&self, plaintext_len: usize) -> usize {
        self.encrypt_out_len(plaintext_len)
    }

    /// As [`encrypt_out`](Self::encrypt_out), with the parts in the order `C1 || C2 || C3`.
    pub fn encrypt_c1c2c3_out(
        &self,
        rng: &mut dyn RNG,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PublicKeyEncryptionError> {
        self.encrypt_ordered_out(Order::C1C2C3, rng, plaintext, out)
    }

    fn encrypt_ordered_out(
        &self,
        order: Order,
        rng: &mut dyn RNG,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PublicKeyEncryptionError> {
        out.fill(0);
        encryption_core::check_length(plaintext.len())?;
        // Saturated only where no buffer is that long, and then refused as too small.
        let len = self.encrypt_out_len(plaintext.len());
        if out.len() < len {
            return Err(PublicKeyEncryptionError::OutputBufferTooSmall(len));
        }
        let (c3_range, c2_range) = order.ranges(plaintext.len());
        out[c2_range.clone()].copy_from_slice(plaintext);
        match self.encrypt_detached_inplace(rng, &mut out[c2_range.clone()]) {
            Ok((c1, c3)) => {
                out[..C1_LEN].copy_from_slice(&c1);
                out[c3_range].copy_from_slice(&c3);
                Ok(len)
            }
            Err(e) => {
                // The copy of the message.
                encryption_core::wipe(&mut out[c2_range]);
                Err(e)
            }
        }
    }
}

impl PublicKey<PK_LEN> for SM2EncryptionPublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        sm2_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.encode();
        PK_LEN
    }

    /// Accepts the 65-byte uncompressed and the 33-byte compressed form, checking that the
    /// coordinates are below `p` and satisfy the curve equation. The cofactor is 1, so such a
    /// point has order `n`.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let (x, y) = sm2_sec1::decode(bytes)
            .ok_or(KeyDecodingError("invalid or out-of-range SM2 point encoding"))?;
        Ok(Self { x, y })
    }
}

impl Display for SM2EncryptionPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "SM2EncryptionPublicKey {{ {:x?} }}", self.encode())
    }
}

/// An SM2 private key for decryption: `dB` in `[1, n-2]` (GB/T 32918.1-2016 Section 6.1 a)),
/// held in a [`Secret`] and zeroized when the key is dropped. The encoding is that of
/// [`crate::sm2::keys::SM2PrivateKey`], 32 bytes big-endian.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SM2EncryptionPrivateKey {
    d: Sm2Scalar,
}

impl SM2EncryptionPrivateKey {
    /// The public key `PB = [dB]G`, computed on each call.
    pub fn derive_pk(&self) -> SM2EncryptionPublicKey {
        let pk = public_key_in_own_frame(&self.d);
        wipe_stack_below::<KEY_WIPED_STACK_WORDS>();
        pk
    }

    /// Decrypts `C2` in `buf` where it lies, given `C1` and `C3`: `buf` holds `C2` on entry and
    /// the message on return.
    ///
    /// The message is computed before it is checked against `C3`, so `buf` passes through a
    /// state in which it holds bytes nobody has authenticated; on any error `buf` is zeroized
    /// before this returns.
    ///
    /// # Errors
    /// [`PublicKeyEncryptionError::DecryptionFailed`] if `C1` is not the uncompressed or hybrid
    /// encoding of a point on the curve or the ciphertext does not verify, without saying which;
    /// and
    /// [`PublicKeyEncryptionError::InvalidInputLength`] for an empty `buf`, or one of
    /// `(2^32 - 1) * 32` bytes or more.
    pub fn decrypt_detached_inplace(
        &self,
        c1: &[u8; C1_LEN],
        c3: &[u8; C3_LEN],
        buf: &mut [u8],
    ) -> Result<(), PublicKeyEncryptionError> {
        encryption_core::decrypt_detached_inplace(&self.d, c1, c3, buf)
    }

    /// The length of the message in a ciphertext of `ciphertext_len` bytes, which is what
    /// [`decrypt_out`](Self::decrypt_out) needs of its output buffer; zero for a length no
    /// ciphertext has.
    pub fn decrypt_out_len(&self, ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(OVERHEAD_LEN)
    }

    /// Decrypts `ciphertext`, which is `C1 || C3 || C2`, into `out`, and returns the length of
    /// the message. `out` is zeroized first, and is all zero after an error.
    ///
    /// # Errors
    /// [`PublicKeyEncryptionError::InvalidInputLength`] if `ciphertext` is not longer than
    /// [`OVERHEAD_LEN`]; [`PublicKeyEncryptionError::OutputBufferTooSmall`] if `out` is shorter
    /// than [`decrypt_out_len`](Self::decrypt_out_len); and those of
    /// [`decrypt_detached_inplace`](Self::decrypt_detached_inplace).
    pub fn decrypt_out(
        &self,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PublicKeyEncryptionError> {
        self.decrypt_ordered_out(Order::C1C3C2, ciphertext, out)
    }

    /// As [`decrypt_out_len`](Self::decrypt_out_len), for
    /// [`decrypt_c1c2c3_out`](Self::decrypt_c1c2c3_out); the two orders are the same length.
    pub fn decrypt_c1c2c3_out_len(&self, ciphertext_len: usize) -> usize {
        self.decrypt_out_len(ciphertext_len)
    }

    /// As [`decrypt_out`](Self::decrypt_out), for a ciphertext in the order `C1 || C2 || C3`.
    pub fn decrypt_c1c2c3_out(
        &self,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PublicKeyEncryptionError> {
        self.decrypt_ordered_out(Order::C1C2C3, ciphertext, out)
    }

    fn decrypt_ordered_out(
        &self,
        order: Order,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PublicKeyEncryptionError> {
        out.fill(0);
        if ciphertext.len() <= OVERHEAD_LEN {
            return Err(PublicKeyEncryptionError::InvalidInputLength(
                "an SM2 ciphertext is C1, C3 and at least one byte of C2",
            ));
        }
        let len = ciphertext.len() - OVERHEAD_LEN;
        if out.len() < len {
            return Err(PublicKeyEncryptionError::OutputBufferTooSmall(len));
        }
        let (c3_range, c2_range) = order.ranges(len);
        // The lengths are those of the arrays by the ranges' construction.
        let c1: &[u8; C1_LEN] = ciphertext[..C1_LEN].try_into().unwrap();
        let c3: &[u8; C3_LEN] = ciphertext[c3_range].try_into().unwrap();
        out[..len].copy_from_slice(&ciphertext[c2_range]);
        self.decrypt_detached_inplace(c1, c3, &mut out[..len])?;
        Ok(len)
    }
}

impl PrivateKey<SK_LEN> for SM2EncryptionPrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.d.to_be_bytes()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        *out = self.d.to_be_bytes();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let array: &[u8; SK_LEN] =
            bytes.try_into().map_err(|_| KeyDecodingError("SM2 private key must be 32 bytes"))?;
        // GB/T 32918.1-2016 Section 6.1 a): d is in [1, n-2], checked on the value as encoded
        // and not after a reduction, so that a key has one encoding. Whether it is in range is
        // all that the branch below shows of it.
        let mut limbs = Secret::<[u64; 4]>::new();
        *limbs = sm2_sec1::limbs_from_be_bytes(array);
        // borrow == 1 iff limbs < n - 1.
        let (mut difference, borrow) = nat::sub(&limbs, &N_MINUS_1_LIMBS);
        zeroize_in_place(&mut difference);
        let any_bit = limbs.iter().fold(0, |bits, limb| bits | limb);
        if any_bit == 0 || borrow != 1 {
            return Err(KeyDecodingError("SM2 private key must be in [1, n-2]"));
        }
        Ok(Self { d: Sm2Scalar::from_limbs(*limbs) })
    }
}

/// `PB = [dB]G`. `dB` is in `[1, n-2]` and `G` has order `n`, so `[dB]G` is not the point at
/// infinity, and the conversion that does not branch on it applies.
#[inline]
fn public_key(d: &Sm2Scalar) -> SM2EncryptionPublicKey {
    let mut point = comb_multiply_base_point(d);
    let (x, y) = point.affine_of_nonidentity();
    point.zeroize();
    SM2EncryptionPublicKey { x, y }
}

/// [`public_key`], never inlined, so that what it and its callees leave lies below its
/// caller's frame, where `wipe_stack_below` reaches it.
#[inline(never)]
fn public_key_in_own_frame(d: &Sm2Scalar) -> SM2EncryptionPublicKey {
    public_key(d)
}

/// The key pair that 320 bits of an RNG's output give, never inlined, for the same reason. It
/// returns what [`keygen`] does, for `keygen` to end in the call: the private key is then
/// written to where `keygen`'s caller wants it, and to no frame above the wiped ones.
#[inline(never)]
fn key_pair_in_own_frame(
    extra_bits: &[u8; EXTRA_BITS_DRBG_OUTPUT_LEN],
) -> Result<(SM2EncryptionPublicKey, SM2EncryptionPrivateKey), PublicKeyEncryptionError> {
    let sk = SM2EncryptionPrivateKey { d: reduce_wide_bits_mod_n_minus_2(extra_bits) };
    Ok((public_key(&sk.d), sk))
}

/// Generates an SM2 key pair for encryption, by the method of [`crate::sm2::keys::keygen`]:
/// `dB` in `[1, n-2]` from 320 bits of `rng`'s output (see [`crate::sm2::extra_bits`]), and
/// `PB = [dB]G`.
///
/// # Errors
/// [`PublicKeyEncryptionError::RNGError`] if `rng` offers less than 128 bits of security
/// strength or fails to deliver.
pub fn keygen(
    rng: &mut dyn RNG,
) -> Result<(SM2EncryptionPublicKey, SM2EncryptionPrivateKey), PublicKeyEncryptionError> {
    if rng.security_strength() < SecurityStrength::_128bit {
        return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
    }
    // Dropped last, after the result is where the caller wants it.
    let _wipe = WipeStackBelowOnDrop::<KEY_WIPED_STACK_WORDS>;
    let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    encryption_core::fill_bytes(rng, &mut *extra_bits)?;
    key_pair_in_own_frame(&extra_bits)
}
