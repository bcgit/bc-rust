//! The computation of SM2 public key encryption: GB/T 32918.4-2016 Section 6.1 (encryption, steps
//! A1 to A8), Section 7.1 (decryption, B1 to B7) and the key derivation function of Section
//! 5.4.3, over SM3. `draft-shen-sm2-ecdsa-02` Sections 7.2.1 and 7.3.1 give the same steps in
//! English, except that its A8 orders the ciphertext `C1 || C2 || C3`. The keys and the public
//! API are in [`crate::sm2::encryption`].
//!
//! The message is processed where it lies. `C2 = M xor t` (A6) and `C3 = Hash(x2 || M || y2)`
//! (A7) are computed in one pass over the caller's buffer, a keystream block at a time, so `t`
//! is never held whole; the all-zero test of `t` (A5, B4) is accumulated over the same pass.
//!
//! Everything derived from `k`, `dB` or `[k]PB = [dB]C1` is computed in a frame of its own, and
//! the stack that frame and its callees used is overwritten afterwards: the field arithmetic,
//! the conversions to bytes and SM3's compression function pass such values through locals and
//! spilled registers that zeroizing the named values does not reach.

use crate::hazmat::sm2::Sm2FieldElement;
use crate::hazmat::sm2_comb::comb_multiply_base_point;
use crate::hazmat::sm2_mul::multiply_point;
use crate::hazmat::sm2_point::Sm2JacobianPoint;
use crate::hazmat::sm2_scalar::Sm2Scalar;
use crate::hazmat::sm2_sec1;
use crate::rng_draw::fill_bytes;
use crate::sm2::extra_bits::reduce_wide_bits_mod_n_minus_1;
use crate::sm2::keys::EXTRA_BITS_DRBG_OUTPUT_LEN;
use bouncycastle_core::errors::{PublicKeyEncryptionError, RNGError};
use bouncycastle_core::hazmat::finish_token;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Hash, RNG};
use bouncycastle_digest::sm3::SM3;
use bouncycastle_utils::ct::{Condition, ct_eq_bytes_condition, value_barrier};
use bouncycastle_utils::secret::{Secret, zeroize_in_place};
use bouncycastle_utils::stack_wipe::wipe_stack_below;

/// Length of `C1`, the point `[k]G` in the uncompressed form `04 || x1 || y1`.
pub(in crate::sm2) const C1_LEN: usize = 65;

/// Length of `C3`, an SM3 hash value.
pub(in crate::sm2) const C3_LEN: usize = 32;

/// `v / 8`: the bytes of key data one call of the hash yields (Section 5.4.3).
const KDF_BLOCK_LEN: usize = 32;

/// The longest message, in bytes. Section 5.4.3 requires `klen < (2^32 - 1) v` bits, which for
/// `v = 256` and a whole number of bytes is at most `(2^32 - 1) * 32 - 1` bytes.
const MAX_MESSAGE_LEN: u64 = (u32::MAX as u64) * (KDF_BLOCK_LEN as u64) - 1;

/// How many values of `k` encryption tries before it gives up. Step A5 returns to A1 when `t`
/// is all zero, which for a message of `len` bytes happens with probability about `2^-(8 len)`,
/// taking SM3 as an ideal hash and the draws of `k` as independent: one draw in 256 for a
/// one-byte message. Under the same model sixteen draws all doing so has probability at most
/// `2^-128`, the strength of the algorithm.
pub(in crate::sm2) const MAX_ENCRYPT_ATTEMPTS: usize = 16;

/// Whether a message or `C2` of `len` bytes can be processed: it is not empty, and it is within
/// what the key derivation function may produce.
fn length_in_range(len: u64) -> bool {
    len != 0 && len <= MAX_MESSAGE_LEN
}

pub(in crate::sm2) fn check_length(len: usize) -> Result<(), PublicKeyEncryptionError> {
    if length_in_range(len as u64) {
        Ok(())
    } else {
        Err(PublicKeyEncryptionError::InvalidInputLength(
            "an SM2 message is from 1 to (2^32 - 1) * 32 - 1 bytes",
        ))
    }
}

/// Zeroizes a caller's buffer through a volatile write per byte.
pub(in crate::sm2) fn wipe(buf: &mut [u8]) {
    for byte in buf {
        zeroize_in_place(byte);
    }
}

/// The key derivation function of Section 5.4.3 for `Z = x2 || y2`, handing out `K` a hash
/// value at a time: `Ha_i = SM3(Z || ct)` for the 32-bit counter `ct = 1, 2, ..`, big-endian.
///
/// `Z` is 64 bytes, one block of SM3, so it is absorbed once, and each `Ha_i` is finished from
/// a copy of that state: SM3 iterates its compression function over the blocks in order, so the
/// state after `Z` is the same whatever follows it.
struct KeyDerivation {
    /// SM3 with `Z` absorbed.
    after_z: SM3,
    /// The counter of the block last produced; 0 before the first.
    ct: u32,
    /// `Ha_ct`.
    block: Secret<[u8; KDF_BLOCK_LEN]>,
}

impl KeyDerivation {
    fn new(z: &[u8; 64]) -> Self {
        let mut after_z = SM3::new();
        after_z.do_update(z);
        Self { after_z, ct: 0, block: Secret::new() }
    }

    /// `Ha_i` for the next `i`. The message length was checked against [`MAX_MESSAGE_LEN`], so
    /// this is called at most `2^32 - 1` times and the counter does not wrap.
    fn next_block(&mut self) -> &[u8; KDF_BLOCK_LEN] {
        self.ct += 1; // a) ct = 0x00000001 for the first block; b.2) ct++
        let mut hash = self.after_z.clone();
        hash.do_update(&self.ct.to_be_bytes());
        hash.finish_into(&finish_token(), &mut *self.block); // b.1) Ha_i = Hv(Z || ct)
        &self.block
    }
}

/// One pass over `buf`: XORs `t = KDF(x2 || y2, klen)` into it and absorbs the plaintext into
/// `c3_hash`, which is `buf` as it is before the XOR when encrypting (`message_is_input`) and
/// as it is after when decrypting. Returns the OR of every byte of `t`, which is zero exactly
/// when `t` is the all-zero string; a last block shorter than a hash value uses, and tests,
/// only its leftmost bytes (Section 5.4.3 c)).
fn xor_t_and_absorb_message(
    kdf: &mut KeyDerivation,
    c3_hash: &mut SM3,
    buf: &mut [u8],
    message_is_input: bool,
) -> u32 {
    let mut t_bits = 0u32;
    for chunk in buf.chunks_mut(KDF_BLOCK_LEN) {
        let t_block = kdf.next_block();
        if message_is_input {
            c3_hash.do_update(chunk);
        }
        for (byte, t_byte) in chunk.iter_mut().zip(t_block) {
            t_bits = value_barrier(t_bits | u32::from(*t_byte));
            *byte ^= *t_byte;
        }
        if !message_is_input {
            c3_hash.do_update(chunk);
        }
    }
    t_bits
}

/// `x2 || y2` as the 64 bytes the key derivation function and `C3` take, each coordinate
/// converted as GB/T 32918.1-2016 Section 4.2.6 does a field element (32 bytes, big-endian),
/// which step A4 names; the English translation of GM/T 0003.1-2012 numbers it 4.2.5.
fn z_bytes(x2: &Sm2FieldElement, y2: &Sm2FieldElement) -> Secret<[u8; 64]> {
    let mut z = Secret::<[u8; 64]>::new();
    z[..32].copy_from_slice(&sm2_sec1::be_bytes_from_limbs(&x2.to_limbs()));
    z[32..].copy_from_slice(&sm2_sec1::be_bytes_from_limbs(&y2.to_limbs()));
    z
}

/// Steps A2 to A8 for a given `k`, over the message in `buf`. TRUE when `C1` and `C3` are
/// written and `buf` holds `C2`; FALSE when this `k` gives no ciphertext, with the message in
/// `buf` unchanged and nothing written, and the caller is to draw another: `t` was all zero
/// (step A5), or one of the two points was the point at infinity.
///
/// `pb` is the recipient's public key, a point of order `n`, and `k` is in `[1, n-1]`, so
/// neither `[k]G` nor `[k]PB` is the point at infinity; the second case is there so that
/// nothing is derived from the identity's coordinates should that ever not hold.
fn encrypt_with_k(
    k: &Sm2Scalar,
    pb: &Sm2JacobianPoint,
    buf: &mut [u8],
    c1: &mut [u8; C1_LEN],
    c3: &mut [u8; C3_LEN],
) -> bool {
    // A2: C1 = [k]G = (x1, y1).
    let mut c1_point = comb_multiply_base_point(k);
    // A4: [k]PB = (x2, y2).
    let mut shared_point = multiply_point(k, pb);
    // Both are computed before either is looked at, and the conversions are the branch-free
    // ones: the identity comes out of them as (0, 0).
    let infinity = c1_point.is_infinity() | shared_point.is_infinity();
    let (mut x1, mut y1) = c1_point.affine_of_nonidentity();
    let (mut x2, mut y2) = shared_point.affine_of_nonidentity();
    let z = z_bytes(&x2, &y2);
    c1_point.zeroize();
    shared_point.zeroize();
    x2.zeroize();
    y2.zeroize();

    // Not reached for a `k` in [1, n-1] and a `pb` of order n. The branch is on a value derived
    // from `k`, and a `k` that takes it is used for nothing.
    if infinity.to_bool() {
        x1.zeroize();
        y1.zeroize();
        return false;
    }

    // A5: t = KDF(x2 || y2, klen); A6: C2 = M xor t; A7: C3 = Hash(x2 || M || y2).
    let mut kdf = KeyDerivation::new(&z);
    let mut c3_hash = SM3::new();
    c3_hash.do_update(&z[..32]);
    let t_bits = xor_t_and_absorb_message(&mut kdf, &mut c3_hash, buf, true);

    // A5: "if t is the all-zero bit string, return to A1". XORing an all-zero `t` has left the
    // message in `buf` as it was, so there is nothing to undo. The branch is on a value derived
    // from `k`, and a `k` that takes it is discarded.
    if Condition::<u32>::is_zero(t_bits).to_bool() {
        x1.zeroize();
        y1.zeroize();
        return false;
    }

    c3_hash.do_update(&z[32..]);
    c3_hash.finish_into(&finish_token(), c3);
    // A2's conversion of C1 to a byte string, in the uncompressed form.
    *c1 = sm2_sec1::encode_uncompressed(&x1, &y1);
    x1.zeroize();
    y1.zeroize();
    true
}

/// Steps B3 to B6 over `C2` in `buf`, which holds `M'` on return whether or not it is
/// authentic: TRUE if `t` was not all zero (B4) and `u = C3` (B6), as one condition. The caller
/// wipes `buf` on FALSE.
///
/// The standard leaves at B4 before computing `M'`; here both checks are evaluated on every
/// call and combined, so that which of them failed shows in neither the result nor the time
/// taken.
///
/// `c1_point` has passed step B1, so it has order `n`, and `dB` is in `[1, n-2]`, so `[dB]C1`
/// is not the point at infinity; if it is all the same, the result is FALSE.
fn decrypt_with_d(
    d: &Sm2Scalar,
    c1_point: &Sm2JacobianPoint,
    c3: &[u8; C3_LEN],
    buf: &mut [u8],
) -> Condition<u32> {
    // B3: [dB]C1 = (x2, y2).
    let mut shared_point = multiply_point(d, c1_point);
    let (mut x2, mut y2) = shared_point.affine_of_nonidentity();
    let z = z_bytes(&x2, &y2);
    shared_point.zeroize();
    x2.zeroize();
    y2.zeroize();
    // The branch-free conversion gives the point at infinity as (0, 0), which is on no curve
    // with b != 0, so this is the test for it.
    let infinity = ct_eq_bytes_condition(&*z, &[0u8; 64]);

    // B4: t = KDF(x2 || y2, klen); B5: M' = C2 xor t; B6: u = Hash(x2 || M' || y2).
    let mut kdf = KeyDerivation::new(&z);
    let mut u_hash = SM3::new();
    u_hash.do_update(&z[..32]);
    let t_bits = xor_t_and_absorb_message(&mut kdf, &mut u_hash, buf, false);
    u_hash.do_update(&z[32..]);
    let mut u = Secret::<[u8; C3_LEN]>::new();
    u_hash.finish_into(&finish_token(), &mut *u);

    let t_is_not_zero = Condition::<u32>::is_not_zero(t_bits); // B4
    let u_is_c3 = ct_eq_bytes_condition(&*u, c3); // B6
    t_is_not_zero & u_is_c3 & !infinity
}

/// What [`wipe_stack_below`] overwrites after encryption and decryption, in 64-bit words: 8192
/// bytes. In x86-64 builds under the workspace's release profile with the body of the wipe
/// taken out, `dev_scripts/sm2_stack_harness` reports the stack written to 5016 bytes below a
/// call of `encrypt_out` and 4488 below one of `decrypt_out` with rustc 1.97 (nightly), and
/// 4896 and 4448 with rustc 1.88, of which 500 to 800 bytes are the frames above the wiped
/// region; with 4096 bytes wiped that harness finds the computation's residue with either,
/// and `dev_scripts/check_sm2_stack.sh` fails. Measured in review on
/// arm64 Linux, encryption writes to between 5216 and 5440 bytes below the call, and the check
/// fails with 4608 bytes wiped and passes with 5120. The rest is room for a compiler that lays
/// the frames out less tightly.
const WIPED_STACK_WORDS: usize = 1024;

/// What [`wipe_stack_below`] overwrites after a key pair is generated or a public key derived,
/// in 64-bit words: 4096 bytes. Measured as [`WIPED_STACK_WORDS`] was, `keygen` writes to 2552
/// bytes below its call with rustc 1.97 (nightly) and 2272 with rustc 1.88, and `derive_pk` to
/// 2440 and 2208; with 2304 bytes the check fails. Measured in review on arm64 Linux, it fails
/// with 2048 bytes and passes with 2560.
pub(in crate::sm2) const KEY_WIPED_STACK_WORDS: usize = 512;

/// Step A1's reduction of the RNG's output to `k`, then [`encrypt_with_k`]. Never inlined, so
/// that what it and its callees leave lies below its caller's frame, where
/// [`wipe_stack_below`] reaches it.
#[inline(never)]
fn encrypt_attempt_in_own_frame(
    wide_bits: &[u8; EXTRA_BITS_DRBG_OUTPUT_LEN],
    pb: &Sm2JacobianPoint,
    buf: &mut [u8],
    c1: &mut [u8; C1_LEN],
    c3: &mut [u8; C3_LEN],
) -> bool {
    // A1: k in [1, n-1], by the extra-random-bits reduction this module's signing uses.
    let k = reduce_wide_bits_mod_n_minus_1(wide_bits);
    encrypt_with_k(&k, pb, buf, c1, c3)
}

/// [`decrypt_with_d`], never inlined, for the same reason.
#[inline(never)]
fn decrypt_in_own_frame(
    d: &Sm2Scalar,
    c1_point: &Sm2JacobianPoint,
    c3: &[u8; C3_LEN],
    buf: &mut [u8],
) -> Condition<u32> {
    decrypt_with_d(d, c1_point, c3, buf)
}

/// GB/T 32918.4-2016 Section 6.1 for the public key `PB = (pb_x, pb_y)`: `buf` holds `M` on
/// entry and `C2` on return, and `C1` (uncompressed) and `C3` are returned.
///
/// On an error `buf` holds the message as it was given.
pub(in crate::sm2) fn encrypt_detached_inplace(
    pb_x: &Sm2FieldElement,
    pb_y: &Sm2FieldElement,
    rng: &mut dyn RNG,
    buf: &mut [u8],
) -> Result<([u8; C1_LEN], [u8; C3_LEN]), PublicKeyEncryptionError> {
    check_length(buf.len())?;
    if rng.security_strength() < SecurityStrength::_128bit {
        return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
    }

    // A3: S = [h]PB, and an error if S is the point at infinity. The cofactor h is 1
    // (GM/T 0003.5-2012 gives none among the curve's parameters and its Annex B states
    // "cofactor h: 1"; `crate::hazmat::sm2_sec1` derives it), so S is PB, and a public key that
    // exists is a point on the curve and so not the point at infinity.
    let pb = Sm2JacobianPoint::from_affine(*pb_x, *pb_y);

    let mut c1 = [0u8; C1_LEN];
    let mut c3 = [0u8; C3_LEN];
    for _ in 0..MAX_ENCRYPT_ATTEMPTS {
        let mut wide_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
        fill_bytes(rng, &mut *wide_bits)?;
        let done = encrypt_attempt_in_own_frame(&wide_bits, &pb, buf, &mut c1, &mut c3);
        wipe_stack_below::<WIPED_STACK_WORDS>();
        if done {
            return Ok((c1, c3)); // A8, as the parts for the caller to lay out
        }
        // A5: return to A1.
    }
    Err(PublicKeyEncryptionError::EncryptionFailed)
}

/// GB/T 32918.4-2016 Section 7.1 for the private key `dB`: `buf` holds `C2` on entry and `M'`
/// on return.
///
/// On an error `buf` is zeroized.
pub(in crate::sm2) fn decrypt_detached_inplace(
    d: &Sm2Scalar,
    c1: &[u8; C1_LEN],
    c3: &[u8; C3_LEN],
    buf: &mut [u8],
) -> Result<(), PublicKeyEncryptionError> {
    if let Err(e) = check_length(buf.len()) {
        wipe(buf);
        return Err(e);
    }

    // B1: convert C1 to a point and check that it satisfies the curve equation, before the
    // private key is used for anything. The uncompressed and hybrid forms are the two at this
    // length; both coordinates are to be below p, and a hybrid tag is to match y's parity.
    let Some(c1_point) = sm2_sec1::decode_point_uncompressed_or_hybrid(c1) else {
        wipe(buf);
        return Err(PublicKeyEncryptionError::DecryptionFailed);
    };
    // B2: S = [h]C1, and an error if S is the point at infinity. The cofactor h is 1 (see step
    // A3 in `encrypt_detached_inplace`), so S is C1, which B1 has shown to be a point on the
    // curve and so not the point at infinity.

    let ok = decrypt_in_own_frame(d, &c1_point, c3, buf);
    wipe_stack_below::<WIPED_STACK_WORDS>();
    if ok.to_bool() {
        Ok(()) // B7
    } else {
        wipe(buf);
        Err(PublicKeyEncryptionError::DecryptionFailed)
    }
}

// Unit tests, under the QUALITY_AND_STYLE.md exception for private code with known answers that
// the public API cannot reach: the public API draws `k` from an RNG through a reduction, so the
// intermediates of the standard's worked example, the all-zero `t` of step A5 and the retry
// bound are reachable only here.
//
// Where the constants come from. `DB`, `K`, `M` and the expected `PB`, `C1`, `x2 || y2`, `t`,
// `C2` and `C3` of the first group are GM/T 0003.5-2012 Annex C.2 (the English translation
// published at gmbz.org.cn), each recomputed from `dB`, `k` and `M` by a Python model written
// from GB/T 32918.4-2016 (affine integer arithmetic, OpenSSL's SM3) before being used here.
// The annex prints the ciphertext without `C1`'s leading `04`. `KDF_70` and the values for
// `K_ZERO_T` are not in any standard: the same Python model computed them, `K_ZERO_T` being the
// smallest `k` for which a one-byte message under the annex's `PB` gets `t = 00`.
#[cfg(test)]
mod tests {
    use super::*;
    use bouncycastle_core::hazmat::FixedSeedRNG;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), 2 * N);
        let mut out = [0u8; N];
        for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        out
    }

    const DB: &str = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    const PB: &str = "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020\
                      ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13";
    const K: &str = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21";
    const M: &[u8; 19] = b"encryption standard";
    const C1: &str = "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73\
                      e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0";
    const X2_Y2: &str = "335e18d751e51f040e27d468138b7ab1dc86ad7f981d7d416222fd6ab3ed230d\
                         ab743ebcfb22d64f7b6ab791f70658f25b48fa93e54064fdbfbed3f0bd847ac9";
    const T: &str = "44e60fdbf0bae81437665374bef26749046c9e";
    const C2: &str = "21886ca989ca9c7d58087307ca93092d651efa";
    const C3: &str = "59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766";

    /// `KDF(x2 || y2, 560)` for the annex's `x2 || y2`: counters 1 to 3, the last block cut.
    const KDF_70: &str = "44e60fdbf0bae81437665374bef26749046c9e038663294a24f3eccc533e579a\
                          75abe2630d06376d2a947c0755c7c053cbb7d66046bc7b1e057698692ebd905e\
                          8ff15cd2879a";

    /// `k = 470`: `KDF(x2 || y2, 8) = 00` for `(x2, y2) = [470]PB`.
    const K_ZERO_T: u64 = 470;
    /// The first hash value of that `k`'s key stream: only its first byte is zero.
    const ZERO_T_BLOCK: &str = "00cc76c9f723292f73e914e1c9a341a756b1c499c6cf3f650f39ff013ab3a3e6";
    const ZERO_T_C1: &str = "0417a8dbf0e9d5ce427a04c8800bef14de5e22e24c5cee027d8f71fe0bf8a909\
                             b10bc9ed977244bf069fa0e9163a353597134cf54a2747957945678515b49265e8";
    /// `SM3(x2 || 4d || y2)` for that `k`.
    const ZERO_T_C3: &str = "ae0472e858ff7f757df1d97567fd4889d0f340ed959cf70756029aaeff7d5f6e";

    fn pb() -> Sm2JacobianPoint {
        sm2_sec1::decode_point(&hex::<65>(PB)).unwrap()
    }

    fn scalar(s: &str) -> Sm2Scalar {
        Sm2Scalar::from_be_bytes(&hex::<32>(s))
    }

    /// The 40 bytes that step A1's reduction turns into `k`: `k - 1`, since the reduction is
    /// `(bytes mod (n - 1)) + 1`.
    fn wide_bits_for(k: &[u8; 32]) -> [u8; 40] {
        let mut k_minus_1 = *k;
        for byte in k_minus_1.iter_mut().rev() {
            let (difference, borrow) = byte.overflowing_sub(1);
            *byte = difference;
            if !borrow {
                break;
            }
        }
        let mut wide = [0u8; 40];
        wide[8..].copy_from_slice(&k_minus_1);
        wide
    }

    fn k_zero_t_bytes() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[24..].copy_from_slice(&K_ZERO_T.to_be_bytes());
        k
    }

    #[test]
    fn annex_c_shared_point_and_key_stream() {
        let (x2, y2) = multiply_point(&scalar(K), &pb()).affine_of_nonidentity();
        let z = z_bytes(&x2, &y2);
        assert_eq!(*z, hex::<64>(X2_Y2));

        let mut kdf = KeyDerivation::new(&z);
        assert_eq!(kdf.next_block()[..19], hex::<19>(T));
    }

    #[test]
    fn key_derivation_counts_from_one_and_cuts_the_last_block() {
        let expected = hex::<70>(KDF_70);
        let mut kdf = KeyDerivation::new(&hex::<64>(X2_Y2));
        assert_eq!(kdf.next_block()[..], expected[..32]);
        assert_eq!(kdf.next_block()[..], expected[32..64]);
        assert_eq!(kdf.next_block()[..6], expected[64..]);

        // The same through the pass that uses it: an all-zero buffer comes out as t.
        let mut buf = [0u8; 70];
        let mut kdf = KeyDerivation::new(&hex::<64>(X2_Y2));
        let t_bits = xor_t_and_absorb_message(&mut kdf, &mut SM3::new(), &mut buf, true);
        assert_eq!(buf, expected);
        assert_ne!(t_bits, 0);
    }

    #[test]
    fn annex_c_encryption_with_its_k() {
        let mut buf = *M;
        let (mut c1, mut c3) = ([0u8; C1_LEN], [0u8; C3_LEN]);
        assert!(encrypt_with_k(&scalar(K), &pb(), &mut buf, &mut c1, &mut c3));
        assert_eq!(c1, hex::<65>(C1));
        assert_eq!(buf, hex::<19>(C2));
        assert_eq!(c3, hex::<32>(C3));
    }

    #[test]
    fn annex_c_decryption() {
        let c1_point = sm2_sec1::decode_point(&hex::<65>(C1)).unwrap();
        let mut buf = hex::<19>(C2);
        assert!(decrypt_with_d(&scalar(DB), &c1_point, &hex(C3), &mut buf).to_bool());
        assert_eq!(&buf, M);
    }

    #[test]
    fn annex_c_through_the_rng_path() {
        let (x, y) = sm2_sec1::decode(&hex::<65>(PB)).unwrap();
        let mut rng = FixedSeedRNG::new(wide_bits_for(&hex(K)));
        let mut buf = *M;
        let (c1, c3) = encrypt_detached_inplace(&x, &y, &mut rng, &mut buf).unwrap();
        assert_eq!(c1, hex::<65>(C1));
        assert_eq!(buf, hex::<19>(C2));
        assert_eq!(c3, hex::<32>(C3));
    }

    #[test]
    fn encryption_reports_an_all_zero_t_and_leaves_the_message() {
        let k = Sm2Scalar::from_be_bytes(&k_zero_t_bytes());
        let (x2, y2) = multiply_point(&k, &pb()).affine_of_nonidentity();
        let mut kdf = KeyDerivation::new(&z_bytes(&x2, &y2));
        assert_eq!(*kdf.next_block(), hex::<32>(ZERO_T_BLOCK));

        let mut buf = [0x4d];
        let (mut c1, mut c3) = ([0u8; C1_LEN], [0u8; C3_LEN]);
        assert!(!encrypt_with_k(&k, &pb(), &mut buf, &mut c1, &mut c3));
        assert_eq!(buf, [0x4d]);
        assert_eq!((c1, c3), ([0u8; C1_LEN], [0u8; C3_LEN]));

        // A second byte of the message takes a byte of t that is not zero, and the same k is
        // then good: the test is over the bytes of t that are used and no others.
        let mut buf = [0x4d, 0x4d];
        assert!(encrypt_with_k(&k, &pb(), &mut buf, &mut c1, &mut c3));
        assert_eq!(buf, [0x4d, 0x4d ^ 0xcc]);
        assert_eq!(c1, hex::<65>(ZERO_T_C1));
    }

    /// Step B4: a ciphertext whose `t` is all zero is refused although its `C3` is the hash
    /// decryption computes.
    #[test]
    fn decryption_refuses_an_all_zero_t() {
        let c1_point = sm2_sec1::decode_point(&hex::<65>(ZERO_T_C1)).unwrap();
        let mut buf = [0x4d];
        assert!(!decrypt_with_d(&scalar(DB), &c1_point, &hex(ZERO_T_C3), &mut buf).to_bool());

        let mut buf = [0x4d];
        assert_eq!(
            decrypt_detached_inplace(&scalar(DB), &hex(ZERO_T_C1), &hex(ZERO_T_C3), &mut buf),
            Err(PublicKeyEncryptionError::DecryptionFailed)
        );
        assert_eq!(buf, [0]);

        // The control: the same C1 and the hash over two bytes, whose t is 00 cc, decrypts.
        let (x2, y2) = multiply_point(&Sm2Scalar::from_be_bytes(&k_zero_t_bytes()), &pb())
            .affine_of_nonidentity();
        let z = z_bytes(&x2, &y2);
        let mut hash = SM3::new();
        hash.do_update(&z[..32]);
        hash.do_update(&[0x4d, 0x4d]);
        hash.do_update(&z[32..]);
        let mut c3 = [0u8; C3_LEN];
        hash.do_final_out(&mut c3);
        let mut buf = [0x4d, 0x4d ^ 0xcc];
        decrypt_detached_inplace(&scalar(DB), &hex(ZERO_T_C1), &c3, &mut buf).unwrap();
        assert_eq!(buf, [0x4d, 0x4d]);
    }

    /// Step A5's return to A1: the first `k` gives an all-zero `t`, the second is the annex's
    /// and its ciphertext is the result.
    #[test]
    fn encryption_draws_again_after_an_all_zero_t() {
        let (x, y) = sm2_sec1::decode(&hex::<65>(PB)).unwrap();
        let mut seed = [0u8; 80];
        seed[..40].copy_from_slice(&wide_bits_for(&k_zero_t_bytes()));
        seed[40..].copy_from_slice(&wide_bits_for(&hex(K)));
        let mut rng = FixedSeedRNG::new(seed);

        let mut buf = [0x4d];
        let (c1, c3) = encrypt_detached_inplace(&x, &y, &mut rng, &mut buf).unwrap();

        let mut expected = [0x4d];
        let (mut expected_c1, mut expected_c3) = ([0u8; C1_LEN], [0u8; C3_LEN]);
        assert!(encrypt_with_k(
            &scalar(K),
            &pb(),
            &mut expected,
            &mut expected_c1,
            &mut expected_c3
        ));
        assert_eq!((c1, c3, buf), (expected_c1, expected_c3, expected));
        assert_eq!(c1, hex::<65>(C1));
    }

    /// The bound: [`MAX_ENCRYPT_ATTEMPTS`] values of `k` are tried and no more. The RNG hands
    /// out the all-zero-`t` value `bad` times and the annex's `k` after that.
    #[test]
    fn encryption_gives_up_at_the_bound_and_leaves_the_message() {
        let (x, y) = sm2_sec1::decode(&hex::<65>(PB)).unwrap();
        let seed_with = |bad: usize| {
            let mut seed = [0u8; 40 * (MAX_ENCRYPT_ATTEMPTS + 1)];
            for (i, draw) in seed.chunks_mut(40).enumerate() {
                let k = if i < bad { k_zero_t_bytes() } else { hex(K) };
                draw.copy_from_slice(&wide_bits_for(&k));
            }
            seed
        };

        let mut buf = [0x4d];
        let mut rng = FixedSeedRNG::new(seed_with(MAX_ENCRYPT_ATTEMPTS - 1));
        let (c1, _) = encrypt_detached_inplace(&x, &y, &mut rng, &mut buf).unwrap();
        assert_eq!(c1, hex::<65>(C1));

        let mut buf = [0x4d];
        let mut rng = FixedSeedRNG::new(seed_with(MAX_ENCRYPT_ATTEMPTS));
        assert_eq!(
            encrypt_detached_inplace(&x, &y, &mut rng, &mut buf),
            Err(PublicKeyEncryptionError::EncryptionFailed)
        );
        assert_eq!(buf, [0x4d]);
    }

    /// The point at infinity cannot come out of a multiplication the public API starts; a zero
    /// scalar, which the key and `k` types rule out, stands in for whatever would produce it.
    #[test]
    fn the_point_at_infinity_gives_no_ciphertext_and_no_plaintext() {
        let zero = Sm2Scalar::from_limbs([0; 4]);

        let mut buf = *M;
        let (mut c1, mut c3) = ([0u8; C1_LEN], [0u8; C3_LEN]);
        assert!(!encrypt_with_k(&zero, &pb(), &mut buf, &mut c1, &mut c3));
        assert_eq!(&buf, M);
        assert_eq!((c1, c3), ([0u8; C1_LEN], [0u8; C3_LEN]));

        // One of the two points is enough: `[k]G` is a point and `[k]PB` is not, for a public
        // key that is itself the point at infinity, which decoding one rules out.
        let identity = Sm2JacobianPoint::INFINITY;
        assert!(!encrypt_with_k(&scalar(K), &identity, &mut buf, &mut c1, &mut c3));
        assert_eq!(&buf, M);
        assert_eq!((c1, c3), ([0u8; C1_LEN], [0u8; C3_LEN]));

        // What decryption would accept if it took (0, 0) for x2 and y2: C2 under the key
        // stream of 64 zero bytes, and the hash over them.
        let z = [0u8; 64];
        let mut buf = *M;
        let mut hash = SM3::new();
        hash.do_update(&z[..32]);
        let t_bits =
            xor_t_and_absorb_message(&mut KeyDerivation::new(&z), &mut hash, &mut buf, true);
        assert_ne!(t_bits, 0);
        hash.do_update(&z[32..]);
        let mut c3 = [0u8; C3_LEN];
        hash.do_final_out(&mut c3);
        let c1_point = sm2_sec1::decode_point(&hex::<65>(C1)).unwrap();
        assert!(!decrypt_with_d(&zero, &c1_point, &c3, &mut buf).to_bool());
    }

    #[test]
    fn length_in_range_boundary_cases() {
        assert!(!length_in_range(0));
        assert!(length_in_range(1));
        // klen < (2^32 - 1) * 256 bits: 137438953440 bytes is that many bits exactly.
        assert!(length_in_range(137_438_953_439));
        assert!(!length_in_range(137_438_953_440));
        assert!(!length_in_range(u64::MAX));
    }
}
