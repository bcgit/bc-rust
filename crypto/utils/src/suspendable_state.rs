//! Suspending a stateful object to a byte array and resuming it later: the version header every
//! suspended state starts with, the error type, and the component trait that composite states
//! are built from.
//!
//! The traits themselves -- `Suspendable` and `SuspendableKeyed` -- live in `bouncycastle-core`,
//! since they are part of the trait vocabulary every primitive implements. What is here is the
//! machinery their implementations share.
//!
//! # The version header
//!
//! Every suspended state begins with the three-byte library version that wrote it
//! ([`add_lib_ver`]), and every deserializer checks it ([`check_lib_ver`]): a state from a
//! future major or minor version, or from the sentinel `0.0.0`, is refused, and anything else on
//! the same major.minor stream is accepted. See [`LIB_VERSION`] for the maintenance rule that
//! makes this gate sound.
//!
//! # Composing suspended states
//!
//! The traits carry the state length as a const generic parameter, `SuspendableKeyed<N>`, so a
//! generic adapter over an inner type -- a block cipher mode over a permutation, a stream cipher
//! over a keystream -- cannot write its own `N` as "the inner length plus my own" on stable Rust
//! (`generic_const_exprs`). [`SuspendableComponent`] is the workaround: it names the length as
//! an associated const and reads and writes state through slices, so composition is ordinary
//! code. Each public type's `SuspendableKeyed<N>` impl is then a shell over
//! [`suspend_component`] and [`resume_component`], which add the version header and check at
//! compile time that `N` is the component's length plus [`LIB_VERSION_LEN`]. A wrong `N` is a
//! compile error at the call site.
//!
//! ```
//! use bouncycastle_utils::suspendable_state::{
//!     Cursor, CursorMut, LIB_VERSION_LEN, SuspendableComponent, SuspendableError,
//!     bounded_usize, resume_component, suspend_component,
//! };
//!
//! /// A toy: a counter that must never exceed 100, and a key it is checked against on resume.
//! struct Counter { count: usize }
//!
//! impl SuspendableComponent for Counter {
//!     const STATE_LEN: usize = 8;
//!     type Key = u8;
//!     fn write_state(&self, out: &mut [u8]) {
//!         CursorMut::new(out).u64(self.count as u64);
//!     }
//!     fn read_state(state: &[u8], key: &u8) -> Result<Self, SuspendableError> {
//!         if *key != 7 { return Err(SuspendableError::InvalidData); }
//!         Ok(Counter { count: bounded_usize(Cursor::new(state).u64(), 100)? })
//!     }
//! }
//!
//! const STATE_LEN: usize = LIB_VERSION_LEN + Counter::STATE_LEN;
//! let state: [u8; STATE_LEN] = suspend_component(&Counter { count: 42 });
//! let resumed: Counter = resume_component(&state, &7).unwrap();
//! assert_eq!(resumed.count, 42);
//! assert!(resume_component::<Counter, STATE_LEN>(&state, &8).is_err(), "wrong key");
//! ```
//!
//! [`Cursor`] and [`CursorMut`] are for writing the layouts as a sequence of fields rather than
//! offset arithmetic; [`bounded_usize`] reads a count back and refuses one past its bound.

/// Errors from suspending and resuming an object's state.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SuspendableError {
    /// The serialized state was produced by a library version incompatible with this one.
    IncompatibleVersion,
    /// The serialized state is malformed or corrupt.
    InvalidData,
}

/// A semantic library version, ordered by `major`, then `minor`, then `patch`.
///
/// The field declaration order matters: the derived [`Ord`]/[`PartialOrd`] compare fields
/// lexicographically in declaration order, which is exactly semantic-version precedence.
/// A semantic version can often also take a suffix, e.g. "alpha", "beta", "rc1", etc.
/// We're not going to model that here because it's not useful for versioning serialized states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    /// Incremented for incompatible changes.
    pub major: u8,
    /// Incremented for compatible additions, and for any change to a suspended-state layout.
    pub minor: u8,
    /// Incremented for fixes that change no layout.
    pub patch: u8,
}

impl From<[u8; 3]> for SemVer {
    fn from(v: [u8; 3]) -> Self {
        SemVer { major: v[0], minor: v[1], patch: v[2] }
    }
}

impl From<SemVer> for [u8; 3] {
    fn from(v: SemVer) -> Self {
        [v.major, v.minor, v.patch]
    }
}

/// Parse a decimal ASCII string (a Cargo version component) into a u8 at compile time.
const fn parse_version_component(s: &str) -> u8 {
    let bytes = s.as_bytes();
    let mut result: u8 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let d = bytes[i];
        assert!(d >= b'0' && d <= b'9', "version component must be numeric");
        // A component > 255 overflows u8 and fails the build (SemVer fields are u8 by design).
        result = result * 10 + (d - b'0');
        i += 1;
    }
    result
}

/// The current library version at compile time, via Cargo's `CARGO_PKG_VERSION_*` env vars. Every
/// crate in the workspace takes `version.workspace = true`, so this is the workspace version
/// whichever crate is building.
///
/// MAINTAINER NOTE: this single value is the *only* compatibility gate for every serialized state in
/// the workspace (see [`check_lib_ver`]), and the policy accepts any future *patch* on the same
/// major.minor stream. Therefore any change to the on-the-wire layout of *any* suspendable state --
/// in any primitive crate -- MUST bump the workspace's **minor** version (never just the patch),
/// otherwise an older build will silently accept and misread a newer, incompatible state.
pub const LIB_VERSION: SemVer = SemVer {
    major: parse_version_component(env!("CARGO_PKG_VERSION_MAJOR")),
    minor: parse_version_component(env!("CARGO_PKG_VERSION_MINOR")),
    patch: parse_version_component(env!("CARGO_PKG_VERSION_PATCH")),
};

/// Bytes of library-version header [`add_lib_ver`] puts in front of every suspended state.
pub const LIB_VERSION_LEN: usize = 3;

/// Puts the library version into the first three bytes of the state array.
///
/// Hands back a slice to the same array, starting after the version tag.
pub fn add_lib_ver<const SERIALIZED_LEN: usize>(state: &mut [u8; SERIALIZED_LEN]) -> &mut [u8] {
    state[..LIB_VERSION_LEN].copy_from_slice(&<[u8; 3]>::from(LIB_VERSION));
    &mut state[LIB_VERSION_LEN..]
}

/// A helper for deserializing an object's state
///
/// The state_out array must have length at least SERIALIZED_LEN - 3.
///
/// Returns the number of bytes written to state_out, or a [`SuspendableError::IncompatibleVersion`] if
/// the version of the serialized state is earlier than the specified `not_before` version, or
/// is a future MAJOR or MINOR version (but future PATCH versions are ok).
///
/// Note that for testability, this will always reject if the serialized state contains a version tag
/// of `[0,0,0]`.
///
/// Hands back a slice to the same array, starting after the version tag.
pub fn check_lib_ver<const SERIALIZED_LEN: usize>(
    state: &[u8; SERIALIZED_LEN],
    not_before: Option<[u8; 3]>,
) -> Result<&[u8], SuspendableError> {
    // the .unwrap is infallible after the guard check
    if state.len() < LIB_VERSION_LEN {
        return Err(SuspendableError::InvalidData);
    }
    let ver_bytes: [u8; 3] = state[..LIB_VERSION_LEN].try_into().unwrap();
    let ver = SemVer::from(ver_bytes);

    let not_before = SemVer::from(not_before.unwrap_or([0, 0, 0]));

    if ver < not_before {
        return Err(SuspendableError::IncompatibleVersion);
    };
    // Nothing is ever compatible with [0,0,0]
    if ver == SemVer::from([0, 0, 0]) {
        return Err(SuspendableError::IncompatibleVersion);
    };

    // Check if state was produced by a later MAJOR or MINOR version;
    // a future version on the same patch stream is ok (if not, then we've broken the rules of semantic versioning);
    let patch_stream = SemVer::from([LIB_VERSION.major, LIB_VERSION.minor, 255]);
    if ver > patch_stream {
        return Err(SuspendableError::IncompatibleVersion);
    }

    Ok(&state[LIB_VERSION_LEN..])
}

/// A piece of state that can be written to, and rebuilt from, a byte slice of a length it names,
/// given a key. See the module docs for why this exists alongside the `SuspendableKeyed` trait.
///
/// `write_state` and `read_state` are given exactly [`STATE_LEN`](Self::STATE_LEN) bytes. The
/// version header is not part of it: a composite writes one header for the whole state, through
/// [`suspend_component`] and [`resume_component`].
pub trait SuspendableComponent: Sized {
    /// The number of bytes `write_state` fills and `read_state` reads.
    const STATE_LEN: usize;
    /// The key that must be re-supplied to resume. It is never written into the state.
    type Key: ?Sized;
    /// Writes the state into `out`, which is exactly `STATE_LEN` bytes.
    fn write_state(&self, out: &mut [u8]);
    /// Rebuilds the component from `state`, exactly `STATE_LEN` bytes, and the key.
    ///
    /// # Errors
    /// [`SuspendableError::InvalidData`] if `state` is not one this component could have
    /// written, or `key` is not a key the component accepts.
    fn read_state(state: &[u8], key: &Self::Key) -> Result<Self, SuspendableError>;
}

/// The `suspend` of a component: the version header, then its state.
///
/// `N` must be `LIB_VERSION_LEN + C::STATE_LEN`, checked at compile time.
pub fn suspend_component<C: SuspendableComponent, const N: usize>(component: &C) -> [u8; N] {
    const {
        assert!(
            N == LIB_VERSION_LEN + C::STATE_LEN,
            "N must be the type's SUSPENDED_STATE_LEN: the version header plus its state"
        )
    };
    let mut out = [0u8; N];
    // `add_lib_ver` hands back exactly `N - LIB_VERSION_LEN == C::STATE_LEN` bytes.
    component.write_state(add_lib_ver(&mut out));
    out
}

/// The `from_suspended` of a component: checks the version header, then reads the state. `N` as
/// for [`suspend_component`].
///
/// # Errors
/// [`SuspendableError::IncompatibleVersion`] from the header check, otherwise whatever
/// [`SuspendableComponent::read_state`] returns.
pub fn resume_component<C: SuspendableComponent, const N: usize>(
    state: &[u8; N],
    key: &C::Key,
) -> Result<C, SuspendableError> {
    const {
        assert!(
            N == LIB_VERSION_LEN + C::STATE_LEN,
            "N must be the type's SUSPENDED_STATE_LEN: the version header plus its state"
        )
    };
    // `check_lib_ver` hands back exactly `N - LIB_VERSION_LEN == C::STATE_LEN` bytes.
    C::read_state(check_lib_ver(state, None)?, key)
}

/// A cursor over a state buffer, so a layout reads as a sequence of fields rather than offset
/// arithmetic. Every length is fixed by the type, so these never fail on a state of the right
/// length; a wrong length is caught by the compile-time check in [`suspend_component`].
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Starts at the beginning of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// The next `len` bytes.
    pub fn bytes(&mut self, len: usize) -> &'a [u8] {
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        out
    }

    /// The next `N` bytes, as an array.
    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N));
        out
    }

    /// The next eight bytes as a little-endian `u64`.
    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.array())
    }

    /// The next byte.
    pub fn u8(&mut self) -> u8 {
        self.bytes(1)[0]
    }

    /// `true` once every byte has been read; a layout asserts this at the end of a read.
    pub fn is_done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// The writing counterpart of [`Cursor`].
pub struct CursorMut<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> CursorMut<'a> {
    /// Starts at the beginning of `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Writes `bytes` next.
    pub fn bytes(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    /// Writes `v` next, as eight little-endian bytes.
    pub fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }

    /// Writes one byte next.
    pub fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }

    /// `true` once every byte has been written; a layout asserts this at the end of a write.
    pub fn is_done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// A `usize` field read back from its `u64` encoding, refused if it is above `max`.
pub fn bounded_usize(v: u64, max: usize) -> Result<usize, SuspendableError> {
    if v > max as u64 { Err(SuspendableError::InvalidData) } else { Ok(v as usize) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmp_lib_ver() {
        use core::cmp::Ordering;

        assert!([0, 0, 0] < [0, 0, 1]);

        let cmp = |a: [u8; 3], b: [u8; 3]| SemVer::from(a).cmp(&SemVer::from(b));
        assert_eq!(cmp([0, 2, 1], [1, 1, 1]), Ordering::Less);
        assert_eq!(cmp([2, 1, 1], [1, 1, 1]), Ordering::Greater);
        assert_eq!(cmp([1, 0, 2], [1, 1, 1]), Ordering::Less);
        assert_eq!(cmp([1, 2, 0], [1, 1, 1]), Ordering::Greater);
        assert_eq!(cmp([1, 1, 0], [1, 1, 1]), Ordering::Less);
        assert_eq!(cmp([1, 1, 2], [1, 1, 1]), Ordering::Greater);
        assert_eq!(cmp([1, 1, 1], [1, 1, 1]), Ordering::Equal);
    }
}
