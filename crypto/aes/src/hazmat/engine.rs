//! The engines behind [`AESInternal`](crate::hazmat::AESInternal): the key schedule and the
//! round functions, behind one sealed trait so that the type, its trait impls and every mode
//! built on it are written once whichever implementation runs the rounds.
//!
//! [`Bitsliced`] is the portable, table-free engine the crate docs describe. `Arm` runs the
//! rounds on the AArch64 Crypto Extensions through `bouncycastle-asm`'s kernels, and `Detected`
//! picks one of those two when the key is set, by asking the CPU. [`DefaultEngine`] is, with the
//! `asm` feature (on by default):
//!
//! * `Arm` on a little-endian AArch64 build that declares `target_feature = "aes"`;
//! * `Detected` on any other little-endian AArch64 build for Linux, Android, macOS, iOS or
//!   Windows;
//! * [`Bitsliced`] everywhere else, and on every build without the feature.
//!
//! `AES128Internal` and friends use the default; naming an engine explicitly, as
//! `AESInternal<AES128Params, Bitsliced<AES128Params>>`, is for tests that compare engines and
//! for callers with a reason to pin one.
//!
//! An engine holds the expanded key and nothing else. It is constructed only through
//! `AESInternal::new`, which validates the key first, so `expand` takes the key as
//! [`AESParams::Key`], an array whose type carries its length.

use crate::AESParams;
use crate::bitslice::{Block, PlaneWord, Planes};
use crate::round::{add_round_key, inv_mix_columns, inv_shift_rows, mix_columns, shift_rows};
use crate::sbox::{inv_sbox, sbox};
use crate::schedule::{expand, round_key};
#[cfg(all(
    feature = "asm",
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
use bouncycastle_asm::Aes;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};

/// Prevents an engine from being added outside this crate: every engine is reviewed against the
/// FIPS 197 vectors and the constant-time claims in the crate docs before it can sit behind
/// `AESInternal`.
trait EngineInternalTrait {}

/// The key schedule and block functions behind [`AESInternal`](crate::hazmat::AESInternal).
///
/// Sealed: only the engines in this module implement it. The six block functions are the
/// [`ElectronicCodeBook`](bouncycastle_core::hazmat::ElectronicCodeBook) entry points, with the
/// same contract: the two- and four-block forms must be indistinguishable from two or four
/// single-block calls, and exist so that an engine can run independent blocks together for
/// little more than the cost of one.
///
/// Two engines are equal when their expanded keys are, and `AESInternal`'s equality is the
/// engine's; an implementation decides it in constant time, through [`Secret`]'s equality,
/// which inspects every byte.
pub trait Engine<P: AESParams>: EngineInternalTrait + Clone + PartialEq + Eq {
    /// KEYEXPANSION() (FIPS 197 Sec 5.2). `key`'s type is its length, `P::KEY_LEN` bytes.
    fn expand(key: &P::Key) -> Self;
    /// CIPHER() (FIPS 197 Sec 5.1) on one block, in place.
    fn encrypt_block(&self, block: &mut Block);
    /// The inverse of CIPHER() on one block, in place.
    fn decrypt_block(&self, block: &mut Block);
    /// CIPHER() on two independent blocks, in place.
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]);
    /// The inverse of CIPHER() on two independent blocks, in place.
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]);
    /// CIPHER() on four independent blocks, in place.
    fn encrypt_4blocks(&self, blocks: &mut [Block; 4]);
    /// The inverse of CIPHER() on four independent blocks, in place.
    fn decrypt_4blocks(&self, blocks: &mut [Block; 4]);
}

/// Prevents [`RoundKeys`] from being implemented outside this crate: the three AES sizes are the
/// only round-key arrays.
trait RoundKeysInternalTrait {}

impl RoundKeysInternalTrait for [Block; 11] {}
impl RoundKeysInternalTrait for [Block; 13] {}
impl RoundKeysInternalTrait for [Block; 15] {}

/// `[Block; Nr + 1]` for one key size: the bound on
/// [`AESParams::RoundKeys`], sealed and implemented for the three
/// AES sizes.
///
/// On a target without the `Arm` engine it is only the bound. There it carries that engine's
/// kernels, which take the round keys as `[Block; Nr + 1]`, and `Nr + 1` cannot be written as an
/// expression over `P` on stable const generics (the same reason `AESParams::Schedule` is an
/// associated type). An engine must implement [`Engine<P>`] for every `P`, since the key types
/// name `AESInternal<P>` for any `P`, so one that holds its schedule in that form reaches the
/// kernels for its size through this trait rather than naming `N`.
#[cfg(not(all(
    feature = "asm",
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
)))]
pub trait RoundKeys: ZeroizablePrimitive + RoundKeysInternalTrait {
    /// The key this size expands from, `[u8; KEY_LEN]`.
    type Key;
}

#[cfg(not(all(
    feature = "asm",
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
)))]
impl RoundKeys for [Block; 11] {
    type Key = [u8; 16];
}
#[cfg(not(all(
    feature = "asm",
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
)))]
impl RoundKeys for [Block; 13] {
    type Key = [u8; 24];
}
#[cfg(not(all(
    feature = "asm",
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
)))]
impl RoundKeys for [Block; 15] {
    type Key = [u8; 32];
}

/// `[Block; Nr + 1]` for one key size: the bound on
/// [`AESParams::RoundKeys`], sealed and implemented for the three
/// AES sizes, carrying the [`Arm`] engine's kernels for that size.
///
/// The kernels in `bouncycastle_asm::arm64_le::aes` take the round keys as `[Block; Nr + 1]`, and
/// `Nr + 1` cannot be written as an expression over `P` on stable const generics (the same reason
/// `AESParams::Schedule` is an associated type). An engine must implement [`Engine<P>`] for every
/// `P`, since the key types name `AESInternal<P>` for any `P`, so [`Arm`] reaches the kernels for
/// its size through this trait rather than naming `N`. Only `expand` differs between the sizes; the
/// block functions are the same kernels. Every method takes the [`Aes`] proof the kernels need.
#[cfg(all(
    feature = "asm",
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
pub trait RoundKeys: ZeroizablePrimitive + RoundKeysInternalTrait {
    /// The key this size expands from, `[u8; KEY_LEN]`.
    type Key;
    /// KEYEXPANSION()'s `w` for a key of this size; `key`'s type is that size's length.
    fn expand(cx: Aes, key: &Self::Key) -> Self;
    /// KEYEXPANSIONEIC()'s `dw`: `self` with INVMIXCOLUMNS() applied to round keys `1..=Nr-1`.
    fn equivalent_inverse(&self, cx: Aes) -> Self;
    /// CIPHER() on `B` independent blocks, in place, with `self` as `w`.
    fn encrypt_blocks<const B: usize>(&self, cx: Aes, blocks: &mut [Block; B]);
    /// The equivalent inverse cipher on `B` independent blocks, in place, with `self` as `dw`.
    fn decrypt_blocks<const B: usize>(&self, cx: Aes, blocks: &mut [Block; B]);
}

/// The engine `AESInternal` uses unless one is named: [`Bitsliced`], because this build can
/// neither assume nor detect the AArch64 Crypto Extensions.
#[cfg(not(all(
    feature = "asm",
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
)))]
pub type DefaultEngine<P> = Bitsliced<P>;

/// The engine `AESInternal` uses unless one is named: [`Arm`], because this build declares the
/// AArch64 Crypto Extensions.
#[cfg(all(
    feature = "asm",
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "aes",
    target_feature = "neon"
))]
pub type DefaultEngine<P> = Arm<P>;

/// The engine `AESInternal` uses unless one is named: [`Detected`], because this build can ask
/// the CPU whether it has the AArch64 Crypto Extensions.
#[cfg(all(
    feature = "asm",
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    not(target_feature = "aes"),
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]
pub type DefaultEngine<P> = Detected<P>;

/// The portable engine: the bit-sliced, table-free implementation described in the crate docs.
///
/// Its only state is the bit-sliced schedule in a [`Secret`]. Both directions work from that one
/// schedule (see `inv_cipher`), so there is no second copy and no transformation at construction
/// time, which is what keeps it at 176, 208 or 240 bytes.
pub struct Bitsliced<P: AESParams> {
    schedule: Secret<P::Schedule>,
}

// Written out rather than derived: a derive would demand `P: Clone`, and the parameter set is a
// marker that nothing clones.
impl<P: AESParams> Clone for Bitsliced<P> {
    fn clone(&self) -> Self {
        Self { schedule: self.schedule.clone() }
    }
}

// Round key 0 is the key itself (FIPS 197 Sec 5.2), so two schedules are equal exactly when the
// keys are; `Secret`'s equality inspects every byte.
impl<P: AESParams> PartialEq for Bitsliced<P> {
    fn eq(&self, other: &Self) -> bool {
        self.schedule == other.schedule
    }
}

impl<P: AESParams> Eq for Bitsliced<P> {}

impl<P: AESParams> EngineInternalTrait for Bitsliced<P> {}

impl<P: AESParams> Bitsliced<P> {
    /// CIPHER() on every block in the state at once (FIPS 197 Sec 5.1, Algorithm 1).
    ///
    /// `T` is the plane width, and so the number of blocks: one, two or four. The body is the
    /// same at every width; see [`crate::bitslice`].
    ///
    /// Algorithm 1 line by line: line 3 is the initial ADDROUNDKEY() with `w[0..3]`; lines 4-9 are
    /// the `Nr - 1` full rounds; lines 10-12 are the final round, which omits MIXCOLUMNS(); line
    /// 13 returns the state.
    fn cipher<T: PlaneWord>(&self, q: &mut Planes<T>) {
        // line 3: state = state XOR w[0..3]
        add_round_key(q, &round_key::<P, T>(&self.schedule, 0));

        // lines 4-9: for round from 1 to Nr - 1
        for round in 1..P::NR {
            sbox(q); // line 5, SUBBYTES()
            shift_rows(q); // line 6, SHIFTROWS()
            mix_columns(q); // line 7, MIXCOLUMNS()
            add_round_key(q, &round_key::<P, T>(&self.schedule, round)); // line 8
        }

        // lines 10-12: the final round has no MIXCOLUMNS()
        sbox(q);
        shift_rows(q);
        add_round_key(q, &round_key::<P, T>(&self.schedule, P::NR));
    }

    /// INVCIPHER() on every block in the state at once (FIPS 197 Sec 5.3, Algorithm 3).
    ///
    /// This is the **straight** inverse cipher of Algorithm 3, not the equivalent inverse cipher
    /// of Sec 5.3.5. That matters: Algorithm 3 applies INVMIXCOLUMNS() *after* ADDROUNDKEY(),
    /// which lets it use the ordinary key schedule, whereas Sec 5.3.5 reorders the round to put
    /// the two the other way round and needs a separate schedule with INVMIXCOLUMNS() applied to
    /// each round key (Algorithm 5, KEYEXPANSIONEIC()).
    ///
    /// Following Algorithm 3 is therefore what allows one [`Bitsliced`] value to encrypt *and* decrypt
    /// from a single stored schedule, with no second copy and no transformation at construction
    /// time -- which is the whole reason this crate can offer both directions at 176-240 bytes of
    /// state.
    ///
    /// Line by line: line 3 is ADDROUNDKEY() with the last round key; lines 4-9 are the
    /// `Nr - 1` full inverse rounds; lines 10-12 are the final one, which omits INVMIXCOLUMNS();
    /// line 13 returns the state.
    fn inv_cipher<T: PlaneWord>(&self, q: &mut Planes<T>) {
        // line 3: state = state XOR w[4*Nr .. 4*Nr+3]
        add_round_key(q, &round_key::<P, T>(&self.schedule, P::NR));

        // lines 4-9: for round from Nr - 1 down to 1
        for round in (1..P::NR).rev() {
            inv_shift_rows(q); // line 5, INVSHIFTROWS()
            inv_sbox(q); // line 6, INVSUBBYTES()
            add_round_key(q, &round_key::<P, T>(&self.schedule, round)); // line 7
            inv_mix_columns(q); // line 8, INVMIXCOLUMNS()
        }

        // lines 10-12: the final inverse round has no INVMIXCOLUMNS()
        inv_shift_rows(q);
        inv_sbox(q);
        add_round_key(q, &round_key::<P, T>(&self.schedule, 0));
    }

    /// Encrypts the blocks a `T`-wide state holds, in place: transpose in, [`Self::cipher`],
    /// transpose out.
    #[inline(always)]
    fn encrypt<T: PlaneWord>(&self, blocks: &mut T::Blocks) {
        let mut q = T::pack(blocks);
        self.cipher(&mut q);
        T::unpack(&mut q, blocks);
    }

    /// Decrypts the blocks a `T`-wide state holds, in place: transpose in, [`Self::inv_cipher`],
    /// transpose out.
    #[inline(always)]
    fn decrypt<T: PlaneWord>(&self, blocks: &mut T::Blocks) {
        let mut q = T::pack(blocks);
        self.inv_cipher(&mut q);
        T::unpack(&mut q, blocks);
    }
}

impl<P: AESParams> Engine<P> for Bitsliced<P> {
    fn expand(key: &P::Key) -> Self {
        Self { schedule: expand::<P>(key) }
    }

    /// On `u16` planes: the state holds exactly one block, so nothing is wasted.
    fn encrypt_block(&self, block: &mut Block) {
        self.encrypt::<u16>(core::array::from_mut(block));
    }

    /// On `u16` planes.
    fn decrypt_block(&self, block: &mut Block) {
        self.decrypt::<u16>(core::array::from_mut(block));
    }

    /// On `u32` planes, for about the cost of one block.
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        self.encrypt::<u32>(blocks);
    }

    /// On `u32` planes.
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        self.decrypt::<u32>(blocks);
    }

    /// On `u64` planes, for about the cost of one block.
    fn encrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        self.encrypt::<u64>(blocks);
    }

    /// On `u64` planes.
    fn decrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        self.decrypt::<u64>(blocks);
    }
}

/// The AArch64 Crypto Extensions engine, over the kernels in `bouncycastle_asm::arm64_le::aes`.
///
/// CIPHER() runs on `AESE`/`AESMC` and decryption is the equivalent inverse cipher of FIPS 197 Sec
/// 5.3.5 on `AESD`/`AESIMC`, which is what those instructions compute, so this engine holds both
/// schedules: `w` from KEYEXPANSION() and `dw` from KEYEXPANSIONEIC(). That is twice the state of
/// [`Bitsliced`], 352, 416 or 480 bytes; a build that only encrypts, as CTR, GCM and CCM do, still
/// pays for `dw`, which is the price of one type serving both directions. The expansion itself is
/// table-free: SUBWORD() goes through `AESE`, see `bouncycastle_asm::arm64_le::aes`.
///
/// The expanded arrays are moved into their [`Secret`]s; the compiler may leave a copy of each
/// in the dead frame of the kernel that produced it, which is the same caveat the crate's
/// Security Considerations make about working state.
///
/// It is built from the [`Aes`] proof it is given. A build that declares
/// `target_feature = "aes"` implements [`Engine`] for it with `Aes::declared()`; on any other
/// build only `Detected` builds one, with the proof `Aes::detect()` returned.
#[cfg(all(
    feature = "asm",
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
pub struct Arm<P: AESParams> {
    /// Proof that the CPU has the instructions, which the kernels need. Zero-sized.
    cx: Aes,
    /// KEYEXPANSION()'s `w`, as `Nr + 1` round keys.
    w: Secret<P::RoundKeys>,
    /// KEYEXPANSIONEIC()'s `dw`: `w` with INVMIXCOLUMNS() applied to round keys `1..=Nr-1`.
    dw: Secret<P::RoundKeys>,
}

#[cfg(all(
    feature = "asm",
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
mod arm {
    #[cfg(target_feature = "aes")]
    use super::Engine;
    use super::{Arm, EngineInternalTrait, RoundKeys};
    use crate::AESParams;
    use crate::bitslice::Block;
    use bouncycastle_asm::Aes;
    use bouncycastle_utils::secret::Secret;

    impl<P: AESParams> Clone for Arm<P> {
        fn clone(&self) -> Self {
            Self { cx: self.cx, w: self.w.clone(), dw: self.dw.clone() }
        }
    }

    // Both schedules are compared, joined with `&` rather than `&&` so that the time taken does
    // not say which of them differed; `Secret`'s equality inspects every byte. Round key 0 of `w`
    // is the key itself (FIPS 197 Sec 5.2), so two engines are equal exactly when the keys are.
    impl<P: AESParams> PartialEq for Arm<P> {
        fn eq(&self, other: &Self) -> bool {
            (self.w == other.w) & (self.dw == other.dw)
        }
    }

    impl<P: AESParams> Eq for Arm<P> {}

    impl<P: AESParams> EngineInternalTrait for Arm<P> {}

    impl<P: AESParams> Arm<P> {
        /// KEYEXPANSION()'s `w` and KEYEXPANSIONEIC()'s `dw` for `key`, on the kernels `cx`
        /// proves the CPU has. The only constructor.
        pub(crate) fn new(cx: Aes, key: &P::Key) -> Self {
            let mut w = Secret::<P::RoundKeys>::new();
            *w = P::RoundKeys::expand(cx, key);
            let mut dw = Secret::<P::RoundKeys>::new();
            *dw = w.equivalent_inverse(cx);
            Self { cx, w, dw }
        }

        /// CIPHER() on `B` independent blocks, in place, through the stored proof. The arm crate
        /// asserts which `B` are admissible.
        pub(crate) fn encrypt_blocks<const B: usize>(&self, blocks: &mut [Block; B]) {
            self.w.encrypt_blocks(self.cx, blocks);
        }

        /// The equivalent inverse cipher on `B` independent blocks, in place, through the stored
        /// proof.
        pub(crate) fn decrypt_blocks<const B: usize>(&self, blocks: &mut [Block; B]) {
            self.dw.decrypt_blocks(self.cx, blocks);
        }
    }

    /// Only where the build declares the instructions, so that `Aes::declared()` is the proof.
    #[cfg(target_feature = "aes")]
    impl<P: AESParams> Engine<P> for Arm<P> {
        fn expand(key: &P::Key) -> Self {
            Self::new(Aes::declared(), key)
        }
        fn encrypt_block(&self, block: &mut Block) {
            self.encrypt_blocks(core::array::from_mut(block));
        }
        fn decrypt_block(&self, block: &mut Block) {
            self.decrypt_blocks(core::array::from_mut(block));
        }
        fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
            self.encrypt_blocks(blocks);
        }
        fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
            self.decrypt_blocks(blocks);
        }
        fn encrypt_4blocks(&self, blocks: &mut [Block; 4]) {
            self.encrypt_blocks(blocks);
        }
        fn decrypt_4blocks(&self, blocks: &mut [Block; 4]) {
            self.decrypt_blocks(blocks);
        }
    }

    impl RoundKeys for [Block; 11] {
        type Key = [u8; 16];
        fn expand(cx: Aes, key: &[u8; 16]) -> Self {
            cx.expand_128(key)
        }
        fn equivalent_inverse(&self, cx: Aes) -> Self {
            cx.equivalent_inverse_round_keys(self)
        }
        fn encrypt_blocks<const B: usize>(&self, cx: Aes, blocks: &mut [Block; B]) {
            cx.encrypt_blocks(self, blocks);
        }
        fn decrypt_blocks<const B: usize>(&self, cx: Aes, blocks: &mut [Block; B]) {
            cx.decrypt_blocks(self, blocks);
        }
    }

    impl RoundKeys for [Block; 13] {
        type Key = [u8; 24];
        fn expand(cx: Aes, key: &[u8; 24]) -> Self {
            cx.expand_192(key)
        }
        fn equivalent_inverse(&self, cx: Aes) -> Self {
            cx.equivalent_inverse_round_keys(self)
        }
        fn encrypt_blocks<const B: usize>(&self, cx: Aes, blocks: &mut [Block; B]) {
            cx.encrypt_blocks(self, blocks);
        }
        fn decrypt_blocks<const B: usize>(&self, cx: Aes, blocks: &mut [Block; B]) {
            cx.decrypt_blocks(self, blocks);
        }
    }

    impl RoundKeys for [Block; 15] {
        type Key = [u8; 32];
        fn expand(cx: Aes, key: &[u8; 32]) -> Self {
            cx.expand_256(key)
        }
        fn equivalent_inverse(&self, cx: Aes) -> Self {
            cx.equivalent_inverse_round_keys(self)
        }
        fn encrypt_blocks<const B: usize>(&self, cx: Aes, blocks: &mut [Block; B]) {
            cx.encrypt_blocks(self, blocks);
        }
        fn decrypt_blocks<const B: usize>(&self, cx: Aes, blocks: &mut [Block; B]) {
            cx.decrypt_blocks(self, blocks);
        }
    }
}

/// The engine chosen when the key is set: [`Arm`] if the CPU has the AArch64 Crypto Extensions,
/// [`Bitsliced`] if not. [`DefaultEngine`] on an AArch64 build for Linux, Android, macOS, iOS or
/// Windows that has the `asm` feature (on by default) and does not declare the instructions, so
/// that one binary uses them wherever it runs on them.
///
/// The CPU is asked once per key, in key expansion, and the operating-system query behind that
/// caches its answer. Each block call is then a match on the variant, which depends on the CPU
/// and never on the key or data. The size is [`Arm`]'s plus the discriminant.
#[cfg(all(
    feature = "asm",
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    not(target_feature = "aes"),
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]
pub enum Detected<P: AESParams> {
    /// The CPU has the instructions.
    Arm(Arm<P>),
    /// The CPU lacks them.
    Bitsliced(Bitsliced<P>),
}

#[cfg(all(
    feature = "asm",
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    not(target_feature = "aes"),
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]
mod detected {
    use super::{Arm, Bitsliced, Detected, Engine, EngineInternalTrait};
    use crate::AESParams;
    use crate::bitslice::Block;
    use bouncycastle_asm::Aes;

    // Written out rather than derived, for the reason `Bitsliced`'s is.
    impl<P: AESParams> Clone for Detected<P> {
        fn clone(&self) -> Self {
            match self {
                Self::Arm(e) => Self::Arm(e.clone()),
                Self::Bitsliced(e) => Self::Bitsliced(e.clone()),
            }
        }
    }

    // Which variant a key expanded into depends on the CPU, never on the key, so the match says
    // nothing about the key; the engines' own equality is constant-time.
    impl<P: AESParams> PartialEq for Detected<P> {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Arm(a), Self::Arm(b)) => a == b,
                (Self::Bitsliced(a), Self::Bitsliced(b)) => a == b,
                _ => false,
            }
        }
    }

    impl<P: AESParams> Eq for Detected<P> {}

    impl<P: AESParams> EngineInternalTrait for Detected<P> {}

    impl<P: AESParams> Engine<P> for Detected<P> {
        fn expand(key: &P::Key) -> Self {
            match Aes::detect() {
                Some(cx) => Self::Arm(Arm::new(cx, key)),
                None => Self::Bitsliced(<Bitsliced<P> as Engine<P>>::expand(key)),
            }
        }
        fn encrypt_block(&self, block: &mut Block) {
            match self {
                Self::Arm(e) => e.encrypt_blocks(core::array::from_mut(block)),
                Self::Bitsliced(e) => e.encrypt_block(block),
            }
        }
        fn decrypt_block(&self, block: &mut Block) {
            match self {
                Self::Arm(e) => e.decrypt_blocks(core::array::from_mut(block)),
                Self::Bitsliced(e) => e.decrypt_block(block),
            }
        }
        fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
            match self {
                Self::Arm(e) => e.encrypt_blocks(blocks),
                Self::Bitsliced(e) => e.encrypt_2blocks(blocks),
            }
        }
        fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
            match self {
                Self::Arm(e) => e.decrypt_blocks(blocks),
                Self::Bitsliced(e) => e.decrypt_2blocks(blocks),
            }
        }
        fn encrypt_4blocks(&self, blocks: &mut [Block; 4]) {
            match self {
                Self::Arm(e) => e.encrypt_blocks(blocks),
                Self::Bitsliced(e) => e.encrypt_4blocks(blocks),
            }
        }
        fn decrypt_4blocks(&self, blocks: &mut [Block; 4]) {
            match self {
                Self::Arm(e) => e.decrypt_blocks(blocks),
                Self::Bitsliced(e) => e.decrypt_4blocks(blocks),
            }
        }
    }
}
