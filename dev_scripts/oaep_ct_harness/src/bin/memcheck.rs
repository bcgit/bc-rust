//! Runs the EME-OAEP decode over an encoded message memcheck regards as undefined (fresh heap
//! memory, never written), so that memcheck reports any conditional jump or address computed
//! from it. `control` is a variable-time separator search over the same bytes, which memcheck
//! must report, or a clean run proves nothing.
//!
//!   valgrind -q --error-exitcode=9 target/release/memcheck any|exact|control
use std::alloc::{Layout, alloc, dealloc};
use std::hint::black_box;

#[inline(never)]
fn control(em: &[u8]) -> usize {
    let mut i = 65;
    while i < em.len() && em[i] == 0 {
        i += 1;
    }
    i
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    // k for a 2048-bit modulus; the key-transport output is k - 2hLen - 2 bytes.
    let k: usize = 256;
    let layout = Layout::from_size_align(k, 16).unwrap();
    let l_hash = [0x5au8; 32];
    // SAFETY: a fresh allocation of `k` bytes, deliberately left uninitialised. This program
    // exists only to be run under memcheck, which tracks those bytes as undefined.
    let p = unsafe { alloc(layout) };
    assert!(!p.is_null());
    let em = unsafe { core::slice::from_raw_parts_mut(p, k) };
    let mut out = [0u8; 190];
    match mode.as_str() {
        "any" => {
            black_box(oaep_ct_harness::decode_any(&l_hash, em, &mut out));
        }
        "exact" => {
            black_box(oaep_ct_harness::decode_exact(&l_hash, em, 32, &mut out[..32]));
        }
        "control" => {
            black_box(control(em));
        }
        _ => panic!("usage: memcheck any|exact|control"),
    }
    black_box(&out);
    // SAFETY: `p` came from `alloc` with this layout and is not used again.
    unsafe { dealloc(p, layout) };
}
