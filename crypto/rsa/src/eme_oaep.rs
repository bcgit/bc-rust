//! EME-OAEP (RFC 8017 §7.1.1 step 2 and §7.1.2 step 3): the encoding RSAES-OAEP puts a message
//! into before the RSA primitive, and the decoding that takes it back out, over a label hash
//! `H` and an MGF1 hash `M` (§B.2.1; SP 800-56B Rev. 2 §7.2.2.1 item 2: the MGF's hash "need
//! not be the same as the hash function H").
//!
//! The decoding is the sensitive half. RFC 8017 §7.1.2's note: "Care must be taken to ensure
//! that an opponent cannot distinguish the different error conditions in Step 3.g, whether by
//! error message or timing, and, more generally, that an opponent cannot learn partial
//! information about the encoded message EM." [`decode_out`] folds every check into one mask,
//! reads the whole of `DB` whatever it holds, and copies the message out without branching or
//! indexing on where it starts.

use crate::mgf1::{MAX_HASH_LEN, mgf1_xor};
use bouncycastle_core::traits::{HashAlgParams, HashOneShot};
use bouncycastle_utils::ct::value_barrier;
use bouncycastle_utils::secret::Secret;

/// `0xFF` if `x` is not zero, else `0x00`, without a branch.
fn nonzero_mask(x: u8) -> u8 {
    let x = value_barrier(x as u32);
    // x | -x has its top bit set exactly when x is not zero.
    (((x | x.wrapping_neg()) >> 31) as u8).wrapping_neg()
}

/// `0xFF` if `a == b`, else `0x00`, without a branch.
fn eq_mask_u32(a: u32, b: u32) -> u8 {
    let x = value_barrier(a ^ b);
    !(((x | x.wrapping_neg()) >> 31) as u8).wrapping_neg()
}

/// `lHash = Hash(L)` (§7.1.1 step 2.a) into the front of `out`; returns `hLen`.
pub(crate) fn label_hash<H: HashOneShot + HashAlgParams>(
    label: &[u8],
    out: &mut [u8; MAX_HASH_LEN],
) -> usize {
    H::hash_out(label, &mut out[..H::OUTPUT_LEN])
}

/// EME-OAEP encoding (§7.1.1 step 2) of `msg` into `em`, the whole `k` bytes of it, with the
/// caller's `seed` (step 2.d's random octet string, `hLen` bytes). The caller has checked
/// `mLen <= k - 2hLen - 2` (step 1.b).
pub(crate) fn encode<H, M>(l_hash: &[u8], seed: &[u8], msg: &[u8], em: &mut [u8])
where
    H: HashOneShot + HashAlgParams,
    M: HashOneShot + HashAlgParams,
{
    let h_len = H::OUTPUT_LEN;
    let k = em.len();
    debug_assert!(l_hash.len() == h_len && seed.len() == h_len);
    debug_assert!(msg.len() + 2 * h_len + 2 <= k);

    // i. EM = 0x00 || maskedSeed || maskedDB, built in place.
    let (y, rest) = em.split_at_mut(1);
    let (seed_part, db) = rest.split_at_mut(h_len);
    y[0] = 0x00;
    // b., c. DB = lHash || PS || 0x01 || M, with PS of k - mLen - 2hLen - 2 zero octets.
    let ps_end = db.len() - msg.len() - 1;
    db[..h_len].copy_from_slice(l_hash);
    db[h_len..ps_end].fill(0x00);
    db[ps_end] = 0x01;
    db[ps_end + 1..].copy_from_slice(msg);
    // e., f. dbMask = MGF(seed, k - hLen - 1); maskedDB = DB xor dbMask.
    mgf1_xor::<M>(seed, db);
    // g., h. seedMask = MGF(maskedDB, hLen); maskedSeed = seed xor seedMask.
    seed_part.copy_from_slice(seed);
    mgf1_xor::<M>(db, seed_part);
}

/// EME-OAEP decoding (§7.1.2 step 3) of `em`, all `k` bytes of it, which is unmasked in place:
/// the message into the front of `out`, and its length returned, or `None` for a decryption
/// error of any kind, with `out` zeroized. The caller has checked `k >= 2hLen + 2` (step 1.c)
/// and wipes `em`.
///
/// With `exact_len` the message must be exactly that long, which is part of the same single
/// check; `out` must then be that long. Without it, a message longer than `out` is a decryption
/// error like any other.
///
/// Constant time in `em`: the length of the padding string is not visible in the control flow
/// or in which memory is touched, on success or failure. Only the final success or failure is.
pub(crate) fn decode_out<H, M>(
    l_hash: &[u8],
    em: &mut [u8],
    exact_len: Option<usize>,
    out: &mut [u8],
) -> Option<usize>
where
    H: HashOneShot + HashAlgParams,
    M: HashOneShot + HashAlgParams,
{
    let h_len = H::OUTPUT_LEN;
    debug_assert!(l_hash.len() == h_len && em.len() >= 2 * h_len + 2);
    out.fill(0);

    // b. EM = Y || maskedSeed || maskedDB.
    let (y, rest) = em.split_at_mut(1);
    let (seed, db) = rest.split_at_mut(h_len);
    // c., d. seedMask = MGF(maskedDB, hLen); seed = maskedSeed xor seedMask.
    mgf1_xor::<M>(db, seed);
    // e., f. dbMask = MGF(seed, k - hLen - 1); DB = maskedDB xor dbMask.
    mgf1_xor::<M>(seed, db);

    // g. DB = lHash' || PS || 0x01 || M. "If there is no octet with hexadecimal value 0x01 to
    // separate PS from M, if lHash does not equal lHash', or if Y is nonzero, output
    // 'decryption error'". `bad` gathers all three, and the length checks below.
    let mut bad = nonzero_mask(y[0]);
    let (l_hash_prime, ps_and_m) = db.split_at(h_len);
    let mut diff = 0u8;
    for (a, b) in l_hash.iter().zip(l_hash_prime) {
        diff |= a ^ b;
    }
    bad |= nonzero_mask(diff);

    // The separator is the first nonzero octet after lHash', and it must be 0x01. The scan
    // reads every octet; `found` is all ones from the first nonzero octet on, and `index` is
    // where it was.
    let mut found = 0u8;
    let mut index = 0u32;
    for (i, b) in ps_and_m.iter().enumerate() {
        let nonzero = nonzero_mask(*b);
        let first = nonzero & !found;
        bad |= first & nonzero_mask(*b ^ 0x01);
        // index = first ? i : index
        let first32 = (first as u32).wrapping_mul(0x0101_0101);
        index = (first32 & i as u32) | (!first32 & index);
        found |= nonzero;
    }
    bad |= !found;

    // M is what follows the separator: ps_and_m[index + 1..], mLen bytes.
    let m_start = index.wrapping_add(1);
    let m_len = (ps_and_m.len() as u32).wrapping_sub(m_start);
    match exact_len {
        Some(len) => bad |= !eq_mask_u32(m_len, len as u32),
        // m_len > out.len(): the subtraction borrows.
        None => {
            bad |= ((((out.len() as u32).wrapping_sub(value_barrier(m_len))) >> 31) as u8)
                .wrapping_neg()
        }
    }

    // out[j] = ps_and_m[m_start + j], taken by scanning every octet of DB for every octet of
    // the output, so that no address depends on m_start. Positions past the message stay zero.
    let good = !bad;
    for (j, o) in out.iter_mut().enumerate() {
        let want = m_start.wrapping_add(j as u32);
        let mut byte = 0u8;
        for (i, b) in ps_and_m.iter().enumerate() {
            byte |= b & eq_mask_u32(i as u32, want);
        }
        *o = byte & good;
    }

    // The one visible outcome: the error, or the length.
    if bad != 0 {
        return None;
    }
    Some(m_len as usize)
}

/// A buffer for `lHash` and the seed: `hLen` bytes of [`MAX_HASH_LEN`].
pub(crate) type HashBuf = Secret<[u8; MAX_HASH_LEN]>;
