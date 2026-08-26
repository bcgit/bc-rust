//! Hardware SHA-256 compression via the ARMv8 Cryptographic Extension
//! (`SHA256H`/`SHA256H2`/`SHA256SU0`/`SHA256SU1`) — the `intrinsics`-feature
//! counterpart of the scalar compression function.
//!
//! Instruction availability is checked at runtime.

use crate::sha256::SHA256_K;

#[repr(align(16))]
struct AlignedK([u32; 64]);

static SHA256_K_HW: AlignedK = AlignedK(SHA256_K);

/// Compresses `blocks` into the state `h` (FIPS 180-4 section 6.2.2,
/// four rounds per `SHA256H`/`SHA256H2` pair), returning whether the
/// hardware implementation was available.
pub(crate) fn try_compress(h: &mut [u32; 8], blocks: &[[u8; 64]]) -> bool {
    if !is_supported() {
        return false;
    }

    // SAFETY: `is_supported` established that this CPU implements the
    // SHA-2 instructions required by `compress_blocks`.
    unsafe { compress_blocks(h, blocks) }
    true
}

#[inline]
fn is_supported() -> bool {
    cfg!(target_feature = "sha2") || std::arch::is_aarch64_feature_detected!("sha2")
}

#[target_feature(enable = "sha2")]
unsafe fn compress_blocks(h: &mut [u32; 8], blocks: &[[u8; 64]]) {
    use core::arch::aarch64::{
        vaddq_u32, vld1q_u32, vld1q_u8, vreinterpretq_u32_u8, vrev32q_u8, vsha256h2q_u32,
        vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
    };
    use core::arch::asm;

    // SAFETY: all loads/stores are within `h` ([u32; 8], read/written as
    // two 4-lane halves), the current 64-byte `block` (read as four
    // 16-byte quarters), and `SHA256_K_HW` ([u32; 64], read as sixteen
    // 4-lane rows). The caller established SHA-2 instruction support.
    unsafe {
        let k = SHA256_K_HW.0.as_ptr();
        let mut abcd = vld1q_u32(h.as_ptr());
        let mut efgh = vld1q_u32(h.as_ptr().add(4));

        for block in blocks {
            let p = block.as_ptr();
            let abcd_save = abcd;
            let efgh_save = efgh;

            // Load + byte-swap the 16 message words for this block, same
            // as the scalar version's `x[0..16]` — just 4 at a time.
            let mut m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)));
            let mut m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(16))));
            let mut m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(32))));
            let mut m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(48))));

            // K row for the group in flight; each group fetches the next
            // row before its own hash pair issues, so the load is off the
            // critical path (same software pipeline as the hand-written
            // assembly this replaced).
            let mut k_cur = vld1q_u32(k);

            // SHA256H + SHA256H2 together do 4 rounds of mixing in one go
            // — the scalar version does the same 4 rounds one at a time
            // (via 4 calls to `sha256_round!`), reshuffling which
            // variable plays which role each round so it doesn't have to
            // physically move 8 values around. The hardware does that
            // mixing and shuffling internally, so there's no reshuffling
            // to write here — `abcd`/`efgh` just get overwritten in place.
            //
            // (The empty-asm block below is not part of the algorithm —
            // it's a compiler hint. Without it, LLVM's register allocator
            // makes a suboptimal choice that costs ~17% performance; the
            // hint just pins a temporary copy in its own register.)
            macro_rules! hash_pair {
                ($wk:expr) => {
                    let wk = $wk;
                    let mut prev = efgh;
                    // Empty register barrier: pins `prev` in a physical
                    // register of its own, so the allocator cannot
                    // coalesce the copy onto sha256h2's tied destination.
                    asm!(
                        "// {prev:q} register barrier",
                        prev = inout(vreg) prev,
                        options(pure, nomem, nostack, preserves_flags),
                    );
                    efgh = vsha256h2q_u32(efgh, abcd, wk);
                    abcd = vsha256hq_u32(abcd, prev, wk);
                };
            }

            // One "group" = 4 rounds, plus computing the next 4 message
            // words while we're at it (SU0 before the mixing step, SU1
            // after) — same overall work as 4 loop iterations of
            // compress_scalar, just batched by 4.
            //
            // `$mc/$mn/$ma/$mb` are just the 4 message-word vectors,
            // named by how far each one is from the one being extended
            // right now: mc = current, mn = next, ma/mb = the other two.
            // Each call below passes `m0..m3` shifted by one, so the same
            // 4 vectors rotate through all 4 roles as we go.
            macro_rules! group {
                ($mc:ident, $mn:ident, $ma:ident, $mb:ident, $next:expr) => {
                    let k_next = vld1q_u32(k.add($next * 4));
                    // Round constant + message word for these 4 rounds,
                    // added together in one step (scalar: K[t] + x[t],
                    // one `t` at a time).
                    let wk = vaddq_u32(k_cur, $mc);
                    // Start computing the next 4 message words.
                    $mc = vsha256su0q_u32($mc, $mn);
                    hash_pair!(wk);
                    // Finish computing them.
                    $mc = vsha256su1q_u32($mc, $ma, $mb);
                    k_cur = k_next;
                };
            }
            // The last few rounds don't need new message words anymore
            // (we've already computed all 64), so this skips the SU0/SU1
            // step and just does the mixing.
            macro_rules! tail_group {
                ($mc:ident, $next:expr) => {
                    let k_next = vld1q_u32(k.add($next * 4));
                    hash_pair!(vaddq_u32(k_cur, $mc));
                    k_cur = k_next;
                };
            }

            group!(m0, m1, m2, m3, 1);
            group!(m1, m2, m3, m0, 2);
            group!(m2, m3, m0, m1, 3);
            group!(m3, m0, m1, m2, 4);
            group!(m0, m1, m2, m3, 5);
            group!(m1, m2, m3, m0, 6);
            group!(m2, m3, m0, m1, 7);
            group!(m3, m0, m1, m2, 8);
            group!(m0, m1, m2, m3, 9);
            group!(m1, m2, m3, m0, 10);
            group!(m2, m3, m0, m1, 11);
            group!(m3, m0, m1, m2, 12);

            tail_group!(m0, 13);
            tail_group!(m1, 14);
            tail_group!(m2, 15);
            hash_pair!(vaddq_u32(k_cur, m3));

            // Add the state we started this block with back in — same
            // last step as compress_scalar's `s[i] += a` (etc.) loop.
            abcd = vaddq_u32(abcd, abcd_save);
            efgh = vaddq_u32(efgh, efgh_save);
        }

        vst1q_u32(h.as_mut_ptr(), abcd);
        vst1q_u32(h.as_mut_ptr().add(4), efgh);
    }
}

#[cfg(test)]
mod tests {
    use super::{is_supported, try_compress};
    use crate::sha256::Sha256State;
    use crate::SHA256Params;

    #[test]
    fn hardware_compression_matches_scalar() {
        if !is_supported() {
            return;
        }

        let mut seed = 0x6a09_e667u32;

        for block_count in [0, 1, 2, 3, 8] {
            let mut scalar = Sha256State::<SHA256Params>::new();
            for word in scalar.h.iter_mut() {
                seed = xorshift32(seed);
                *word = seed;
            }

            let mut accelerated = scalar.clone();
            let mut blocks = vec![[0u8; 64]; block_count];
            for byte in blocks.iter_mut().flatten() {
                seed = xorshift32(seed);
                *byte = seed as u8;
            }

            scalar.compress_scalar(&blocks);
            assert!(try_compress(&mut accelerated.h, &blocks));
            assert_eq!(&*accelerated.h, &*scalar.h);
        }
    }

    fn xorshift32(mut value: u32) -> u32 {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        value
    }
}
