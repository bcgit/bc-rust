//! The hardware back ends for AES (FIPS 197) and the GHASH multiplication of GCM (NIST SP 800-38D
//! Sec 6.3), one module per architecture. Today there is one, [`arm64_le`]: the AArch64 Crypto
//! Extensions, with the AES round functions on the `AESE`/`AESMC`/`AESD`/`AESIMC` instructions and
//! the `GF(2^128)` product on `PMULL`/`PMULL2`. The x86 back end is to follow beside it.
//!
//! This crate is a building block for `bouncycastle-aes` and `bouncycastle-cipher`, not a primitive
//! for applications. Nothing here is a cipher: [`arm64_le::aes`] transforms exactly one, two or
//! four blocks and [`arm64_le::ghash`] multiplies field elements. The modes of operation that make
//! those safe to use on data live in `bouncycastle-cipher`, and the AES types applications use live
//! in `bouncycastle-aes`.
//!
//! # Availability
//!
//! The crate has content only on little-endian AArch64 with NEON, and only when the code using
//! it can be sure the CPU has `FEAT_AES`, `FEAT_PMULL` and NEON:
//!
//! * **The build declares it** (`target_feature = "aes"`), as `aarch64-apple-darwin` does by
//!   default and `RUSTFLAGS="-C target-feature=+aes"` does elsewhere. Every CPU the binary may
//!   run on then has the instructions; see Security Considerations.
//! * **The target is Linux, Android, macOS, iOS or Windows**, and [`Aes::detect`] asks the
//!   operating system at run time. A binary built this way runs everywhere and uses the
//!   instructions where they are.
//!
//! Without either, the crate compiles to nothing, and `bouncycastle-aes` falls back to its
//! portable engine.
//!
//! Every kernel is `#[target_feature(enable = "aes,neon")]`, so calling one directly is `unsafe`.
//! The safe way in is an [`Aes`] value, which exists only once the instructions are known to be
//! present, and whose methods are the kernels.
//!
//! To exercise the run-time path on a host that declares `aes` by default, disable it for
//! rustdoc as well as rustc, since cargo hands `RUSTFLAGS` only to the latter:
//! `RUSTFLAGS="-C target-feature=-aes" RUSTDOCFLAGS="-C target-feature=-aes" cargo test`.
//!
//! # Usage Examples
//!
//! The AES kernels work on round keys expanded from a raw key and on arrays of whole blocks:
//!
//! ```
//! # #[cfg(all(target_arch = "aarch64", target_endian = "little", target_feature = "neon",
//! #     any(target_feature = "aes", target_os = "linux", target_os = "android",
//! #     target_os = "macos", target_os = "ios", target_os = "windows")))]
//! # if let Some(cx) = bouncycastle_asm::Aes::detect() {
//! // `cx` is an `Aes`, from `Aes::detect()`.
//! let w = cx.expand_128(&[0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//!                      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]);
//! let dw = cx.equivalent_inverse_round_keys(&w);
//!
//! // FIPS 197 Appendix B: input 3243f6a8885a308d313198a2e0370734 encrypts to
//! // 3925841d02dc09fbdc118597196a0b32 under the key above.
//! let mut blocks = [[0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
//!                    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]];
//! cx.encrypt_blocks(&w, &mut blocks);
//! assert_eq!(blocks[0], [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
//!                        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);
//! cx.decrypt_blocks(&dw, &mut blocks);
//! assert_eq!(blocks[0][0], 0x32);
//! # }
//! ```
//!
//! The GHASH kernel multiplies elements in the `[u64; 2]` form `bouncycastle-cipher`'s GHASH uses,
//! and [`arm64_le::ghash::mul4`] (here [`Aes::ghash_mul4`]) sums four products under one reduction
//! so a caller holding `H`, `H^2`, `H^3` and `H^4` can absorb four blocks per call:
//!
//! ```
//! # #[cfg(all(target_arch = "aarch64", target_endian = "little", target_feature = "neon",
//! #     any(target_feature = "aes", target_os = "linux", target_os = "android",
//! #     target_os = "macos", target_os = "ios", target_os = "windows")))]
//! # if let Some(cx) = bouncycastle_asm::Aes::detect() {
//! let h = [0x6699_aabb_ccdd_ee00, 0x1122_3344_5566_7788];
//! let h2 = cx.ghash_mul(&h, &h);
//! let h3 = cx.ghash_mul(&h2, &h);
//! let h4 = cx.ghash_mul(&h3, &h);
//! let x = [[1, 2], [3, 4], [5, 6], [7, 8]];
//!
//! // One reduction for four products...
//! let fast = cx.ghash_mul4(&x, &[h4, h3, h2, h]);
//! // ...equals the four products reduced one at a time.
//! let slow = [
//!     cx.ghash_mul(&x[0], &h4)[0] ^ cx.ghash_mul(&x[1], &h3)[0] ^ cx.ghash_mul(&x[2], &h2)[0] ^ cx.ghash_mul(&x[3], &h)[0],
//!     cx.ghash_mul(&x[0], &h4)[1] ^ cx.ghash_mul(&x[1], &h3)[1] ^ cx.ghash_mul(&x[2], &h2)[1] ^ cx.ghash_mul(&x[3], &h)[1],
//! ];
//! assert_eq!(fast, slow);
//! # }
//! ```
//!
//! # Memory Usage
//!
//! The kernels hold no state between calls. Everything they touch is the caller's round-key
//! array and the blocks being transformed, plus registers:
//!
//! | | AES-128 | AES-192 | AES-256 |
//! |---|---|---|---|
//! | Round keys, one direction (`4 * (Nr + 1)` words, FIPS 197 Sec 5.2) | 176 B | 208 B | 240 B |
//! | Both directions (`w` and `dw`) | 352 B | 416 B | 480 B |
//! | Working state per call | 16 B per block in flight, in registers | | |
//!
//! GHASH: `mul` and `mul4` use registers only; a caller choosing `mul4` keeps four 16-byte
//! powers of `H` instead of one.
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## This crate contains `unsafe` code
//!
//! bc-rust forbids `unsafe` everywhere except `bouncycastle-utils` and this crate. Here it is
//! confined to two modules, and the crate root is `#![deny(unsafe_code)]` so an `unsafe` block
//! anywhere else is a compile error. [`arm64_le::intrinsics`] holds the two load/store wrappers
//! whose intrinsics take raw pointers. The `arm64_le::cpu` module holds [`Aes`], whose methods call
//! the `#[target_feature]` kernels: the compiler requires `unsafe` there because it cannot see that
//! the CPU has the instructions, and the value's existence is the proof that it does.
//!
//! ## What makes the kernels safe to call
//!
//! An [`Aes`] value comes only from [`Aes::detect`] or `Aes::declared`, and its field is private.
//! `detect` asks for `FEAT_AES`, `FEAT_PMULL` and NEON (the table in the `arm64_le::cpu` module
//! docs), which covers every feature the kernels' `#[target_feature]` attributes name; a proof may
//! ask for more than its kernels need, never less. `declared` exists only under
//! `cfg(target_feature = "aes")`, the feature those attributes name. The proof's methods take and
//! return byte arrays and `[u64; 2]`, so no NEON vector type crosses it.
//!
//! Which kernels run depends on the CPU alone, never on the key or the data, and is decided once
//! when the caller's value is built: `bouncycastle-aes`'s `Detected` engine chooses when it
//! expands the key, and `bouncycastle-cipher`'s GHASH stores the proof when it is constructed.
//!
//! `dev_scripts/quality_stats.sh` counts the crate's `unsafe` blocks, functions, impls and traits
//! by the keyword before `{`, `fn`, `impl` or `trait`, so the three `unsafe extern` declarations
//! are not in it. The figure is 13: the eight proof methods, the two load/store wrappers and one
//! operating-system call per back end. Any other figure is a review finding. A pull request that
//! adds a kernel checks its attribute and proof parameters against the proof's row of the
//! `arm64_le::cpu` table, confirms the proof asks for every feature the attribute names, says how
//! the proof's `None` arm is exercised, and states the new figure.
//!
//! ## What the detector does not do
//!
//! The run-time detector reads what the operating system reports and nothing else. It has no
//! counterpart to the standard library's Android workaround for the Samsung Exynos 9810, whose
//! cores differ in features while kernels before Android 9 reported them for all cores: std
//! 1.94.1 recognises that chip from the `ro.arch` system property and reports less. Nor does it
//! fall back, as std does on Linux when `getauxval` is missing or returns zero for both words,
//! to reading `/proc/self/auxv`: here two zero words mean no features.
//!
//! The crate has no test hook, neither an environment variable nor a cargo feature, so the
//! `None` arms are exercised from outside the process, by intercepting the operating-system
//! call. Otherwise the back ends read what std reads: `AT_HWCAP` and `AT_HWCAP2` on Linux and
//! Android, and `PF_ARM_NEON_INSTRUCTIONS_AVAILABLE` and
//! `PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE` on Windows. On macOS and iOS they read
//! `hw.optional.arm.FEAT_AES` and `hw.optional.arm.FEAT_PMULL` as std does, but NEON as
//! `hw.optional.neon`, because the `hw.optional.AdvSIMD` that std reads is gone from macOS 26.
//!
//! ## A binary built with `aes` requires the hardware
//!
//! Declaring `target_feature = "aes"` is a promise to the compiler, not a request. Running the
//! result on a CPU without `FEAT_AES` and `FEAT_PMULL` is undefined behaviour and in practice an
//! illegal instruction fault. Whoever builds the final binary is the one who can make that
//! promise. A build that cannot, such as a distribution package, should leave `aes` undeclared
//! and let the crate check at run time.
//!
//! ## Timing
//!
//! The instructions operate on register contents: no memory is indexed by the key, the state
//! or the field elements, and no branch depends on them. Whether an instruction's latency is
//! data-independent is a property of the CPU rather than of this code; this crate neither
//! sets nor relies on Arm's data-independent-timing (`DIT`) control. The portable engines in
//! `bouncycastle-aes` and `bouncycastle-cipher` make the same no-secret-indexing claim with
//! the same caveat about the compiler.
//!
//! ## Nothing here is safe to use on data directly
//!
//! A block permutation applied block by block is ECB, and a field multiplication is not a MAC.
//! Use the modes in `bouncycastle-cipher` and the types in `bouncycastle-aes`.

#![no_std]
#![forbid(missing_docs)]
#![deny(unsafe_code)]

// The operating systems in this gate are the ones `arm64_le/cpu/probe.rs` has a back end for: the
// two lists change together.
#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    any(
        target_feature = "aes",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]
pub mod arm64_le;

/// The CPU proof for this target's back end, [`arm64_le::Aes`] on AArch64. Every back end exports
/// one under this name with the same methods (`expand_128`, `expand_192`, `expand_256`,
/// `equivalent_inverse_round_keys`, `encrypt_blocks`, `decrypt_blocks`, `ghash_mul`,
/// `ghash_mul4`), so callers never name an architecture. The x86_64 back end will re-export its
/// own, and later proofs (`Sha2`, `Sha3`, `Sm4`, one per feature) are re-exported the same way.
#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    any(
        target_feature = "aes",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]
pub use arm64_le::Aes;
