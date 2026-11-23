//! Runs the RSA private-key arithmetic over a key memcheck regards as undefined, so that
//! memcheck reports any conditional jump or address computed from it. That arithmetic is not
//! public: `bouncycastle-rsa` shows it to this program under `--cfg
//! bouncycastle_rsa_ct_harness`, which `check_rsa_ct.sh` sets. A secret is made
//! undefined without changing its value by XOR with fresh heap memory, which memcheck tracks
//! as undefined and `--malloc-fill=0x00` makes zero. The controls must be reported, or a
//! clean run proves nothing.
//!
//!   valgrind -q --malloc-fill=0x00 --error-exitcode=9 target/release/memcheck <mode>
//!
//!   context          `MontgomeryContext::for_secret_modulus` over an undefined modulus
//!   crt              `RSA2048::crt_exp` with p, q, dP, dQ and qInv undefined
//!   import           `RSA2048::crt_congruences` with p, q, dP, dQ and qInv undefined
//!   control-context  `for_public_modulus`, which is variable time, over the same modulus
//!   control-crt      `crt`, then a branch on its result, which is computed from the key
//!   control-import   `import`, then a branch on its verdicts
use bouncycastle_rsa::RSA2048;
use bouncycastle_rsa::ct_harness::PrivateKeyEngine;
use bouncycastle_rsa::keys::RsaPrivateComponents;
use bouncycastle_rsa::modexp::MontgomeryContext;
use bouncycastle_rsa::size::RsaSigningSize;
use std::alloc::{Layout, alloc};
use std::hint::black_box;

// The RSA-2048 key of `mem_usage_benches`' `bench_rsa_mem_usage`.
const P: [u64; 16] = [
    0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9,
    0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788,
    0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2,
    0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894,
];
const Q: [u64; 16] = [
    0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492,
    0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0,
    0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868,
    0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898,
];
const D_P: [u64; 16] = [
    0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414,
    0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d,
    0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5,
    0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159,
];
const D_Q: [u64; 16] = [
    0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf,
    0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555,
    0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348,
    0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09,
];
const Q_INV: [u64; 16] = [
    0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983,
    0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b,
    0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51,
    0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163,
];

/// XORs `len` bytes of fresh heap memory into the `len` bytes at `at`. The allocation is not
/// freed: the process is about to exit, and memcheck is not asked for leaks.
///
/// # Safety
/// `at` must be valid for reads and writes of `len` bytes, of a type every bit pattern is a
/// value of.
unsafe fn make_undefined(at: *mut u8, len: usize) {
    // SAFETY: a fresh allocation of `len` bytes, deliberately left uninitialised and read. This
    // program exists only to be run under memcheck, which tracks those bytes as undefined and
    // was told to fill them with zeros. The pointer goes through `black_box` so that the
    // compiler cannot see the memory is fresh and fold the XOR away.
    let zeros = black_box(unsafe { alloc(Layout::from_size_align(len, 8).unwrap()) });
    assert!(!zeros.is_null());
    for i in 0..len {
        // SAFETY: `i < len`, within the allocation and within what the caller vouched for.
        unsafe { *at.add(i) ^= *zeros.add(i) };
    }
}

/// `value`, undefined.
fn undefined(value: &[u64; 16]) -> [u64; 16] {
    let mut n = *value;
    // SAFETY: `n` is 128 bytes of `u64`.
    unsafe { make_undefined(n.as_mut_ptr().cast(), 128) };
    n
}

/// p, undefined.
fn undefined_modulus() -> [u64; 16] {
    undefined(&P)
}

/// p, q, dP, dQ and qInv, undefined, for the congruences a private key's constructor checks.
fn undefined_components() -> [[u64; 16]; 5] {
    [&P, &Q, &D_P, &D_Q, &Q_INV].map(undefined)
}

/// The key, with its five secret components undefined and `n` and `e` left defined: the
/// result check works over those two in variable time, as it may.
fn undefined_key() -> RsaPrivateComponents<RSA2048> {
    let mut sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 65537)
            .unwrap();
    // The key type gives no mutable access to its components, so they are found in its bytes.
    // Five components, n and e are all it holds; a field added to it holds key material this
    // function would leave defined, and has to be dealt with here first.
    let size = size_of::<RsaPrivateComponents<RSA2048>>();
    assert_eq!(
        size,
        5 * 128 + 256 + 8,
        "RsaPrivateComponents has a field this harness does not know"
    );
    let base = (&raw mut sk).cast::<u8>();
    // SAFETY: `base` points at `size` initialised bytes of `sk`, which has no padding (the
    // assertion above), read while nothing else borrows it.
    let image = unsafe { std::slice::from_raw_parts(base, size) }.to_vec();
    for component in [&P, &Q, &D_P, &D_Q, &Q_INV] {
        let needle: Vec<u8> = component.iter().flat_map(|limb| limb.to_ne_bytes()).collect();
        let at = image.windows(128).position(|w| w == needle).expect("component not found");
        // SAFETY: `at + 128 <= size`, inside `sk`, whose components are arrays of `u64`.
        unsafe { make_undefined(base.add(at), 128) };
    }
    sk
}

fn input() -> [u64; 32] {
    let mut x = [0u64; 32];
    x[0] = 0x0123_4567_89ab_cdef;
    x[17] = 0xfeed_face_cafe_f00d;
    x
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "context" => {
            let n = undefined_modulus();
            black_box(MontgomeryContext::<16>::for_secret_modulus(black_box(&n)));
        }
        "control-context" => {
            let n = undefined_modulus();
            black_box(MontgomeryContext::<16>::for_public_modulus(black_box(&n)));
        }
        "crt" => {
            let sk = undefined_key();
            let mut out = [0u64; 32];
            // The result is not turned into a `bool`: whether the check passed is computed
            // from the key, and a branch on it here would be this program's own.
            let _ = black_box(RSA2048::crt_exp(black_box(&sk), black_box(&input()), &mut out));
            black_box(&out);
        }
        "control-crt" => {
            let sk = undefined_key();
            let mut out = [0u64; 32];
            if RSA2048::crt_exp(black_box(&sk), black_box(&input()), &mut out).to_bool() {
                black_box(&out);
            }
        }
        "import" => {
            let [p, q, d_p, d_q, q_inv] = black_box(undefined_components());
            // The verdicts are not turned into `bool`s, as `crt`'s result is not.
            let _ = black_box(RSA2048::crt_congruences(&p, &q, &d_p, &d_q, &q_inv, 65537));
        }
        "control-import" => {
            let [p, q, d_p, d_q, q_inv] = black_box(undefined_components());
            let verdicts = RSA2048::crt_congruences(&p, &q, &d_p, &d_q, &q_inv, 65537);
            if verdicts.into_iter().all(|ok| ok.to_bool()) {
                black_box(());
            }
        }
        _ => {
            panic!("usage: memcheck context|crt|import|control-context|control-crt|control-import")
        }
    }
}
