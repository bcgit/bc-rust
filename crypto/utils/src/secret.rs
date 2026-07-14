//! A transparent wrapper type, [Secret], which is a wrapper that holds a secret value and
//! guarantees it is securely zeroized on drop, and protected from accidintal logging by implementing
//! redacting `fmt::Debug` and `fmt::Display`.
//!
//! # Why write_volatile
//!
//! Plain writes such as `slice.fill(0)` are ordinary, non-observable memory accesses. Under
//! optimization the compiler may prove that a buffer is never read again after it is scrubbed --
//! precisely the situation just before a drop -- and elide the scrub as a dead store. To prevent
//! that, [Secret] erases through [core::ptr::write_volatile], whose accesses are defined by the
//! language as observable side effects and therefore may not be elided or coalesced. Each scrub is
//! followed by a [compiler_fence] with [SeqCst](Ordering::SeqCst) ordering so the volatile
//! writes are not reordered with respect to later memory operations.
//!
//! # Why Sized?
//!
//! The [ZeroizablePrimitive] is bounded on [`Sized`](core::marker::Sized), which explicitly forbids
//! instantiating `Secret<T>` over something like `Vec<T>` whose size is not known at compile time.
//!
//! The reason is that an implementation of `.zeroize()` that is guaranteed not be optimized away
//! by the compiler requires the use of `unsafe{ write_volatile() }` to directly write the `T::ZEROED`
//! byte pattern over top of the provided memory block. With a `Sized` type, this is a single line of
//! unsafe code and it is easy to prove that it is writing the number of bytes that it should be.
//! For a dynamically-sized value such as `Vec<T>`, this is substantially trickier.
//! Taking `Vec` as an example, it is not a flat piece of memory that can be trivially over-written
//! with a static value; `Vec` is actually a stack of structs that implement a smart-pointer that
//! tracks both `length` and `capacity` of the memory referenced by the pointer.
//! Properly zeroizing this means following the pointer, filling the referenced memory with `0x00` up
//! to the `capacity`, then setting `length=0` without changing `capacity` or the pointer.
//! Zeroizing a `Vec` would require a substantial amount of unsafe code that is Vec-specific and
//! tricky to prove the correctness of.
//! Doing this for arbitrary heap-allocated objects (which may contain nested heap-allocated objects)
//! sounds like a whole research project.
//!
//! This is not to say that bc-rust will never attempt this challenge, but since bc-rust is a `[no_std]`
//! library that keeps all of its secrets in stack-allocated variables, this is not a problem that
//! needs to be solved for internal library use.

use crate::ct;
use core::any::type_name;
use core::fmt;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};

/// A `Copy` type whose all-zero value is meaningful and valid, so that a [`Secret`] of it can be
/// default-constructed in a zeroed state.
///
/// This is used instead of [`Default`] for two reasons: it lets [`Secret::new`] produce a zeroed
/// value at compile time via an associated `const`, and -- crucially -- it works for arrays of *any*
/// length, whereas `[T; N]: Default` is only implemented for `N <= 32`.
// Dev note: the `Copy` bound is load-bearing, but only in preventing impl'ng this for additional types
//           that will turn out to be problematic.
//           Specifically: we're using `Copy` to mean 'no Drop' which works because 'Copy' and `Drop` are
//           mutually exclusive, and the byte-scrub semantics here go squirrely if you instantiate a
//           Secret over a type that impls Drop. So we don't actually care about the underlying type
//           impl'ing Copy; we only care that it doesn't impl Drop, and the `Copy` bound is a
//           convenient way to catch that if we in the future do impl_zero_init!(T) for a T that has Drop.
pub trait ZeroizablePrimitive: Copy + Sized {
    /// The zeroed value of this type.
    /// This needs to be a valid static instance of Self that [Secret::zeroize] will internally
    /// convert into a byte array and use to overwrite the memory location of the given instance of
    /// the primitive.
    const ZEROED: Self;
}

macro_rules! impl_zero_init {
    ($($t:ty),+ $(,)?) => {$(
        impl ZeroizablePrimitive for $t {
            const ZEROED: Self = 0 as $t;
        }
    )+};
}

impl_zero_init!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

impl ZeroizablePrimitive for bool {
    const ZEROED: Self = false;
}

impl ZeroizablePrimitive for char {
    const ZEROED: Self = '\0';
}

/// Blanket impl for fixed-size arrays of any length.
/// This is an alternative to `[T; N]: Default` which is capped at `N <= 32`.
impl<T: ZeroizablePrimitive, const N: usize> ZeroizablePrimitive for [T; N] {
    const ZEROED: Self = [T::ZEROED; N];
}

/// A wrapper that holds a secret value of any primitive or fixed-size array type
/// and guarantees it is securely zeroized on drop, and is
/// protected from accidental logging by implementing redacting `fmt::Debug` and `fmt::Display`.
///
/// A `Secret<T>` is created in a zeroed state with [`Secret::new`] / [`Default`] and populated in
/// place through [`DerefMut`]; there is intentionally no by-value constructor (see the [module
/// docs](self)). It behaves transparently as a `&T` / `&mut T` via [`Deref`]/[`DerefMut`], so a
/// `Secret<[u8; 32]>` can be indexed, sliced, and iterated exactly like the underlying array.
///
/// `Secret<T>` deliberately does **not** implement [`Copy`] (it owns a `Drop`), which forces move
/// semantics and prevents silent, unscrubbed duplication of secrets. It *does* implement [`Clone`]
/// for the cases where an explicit, intentional copy is required.
///
/// Its [`Debug`](fmt::Debug) and [`Display`](fmt::Display) impls are redacting: they never print the
/// contained bytes, so a secret cannot leak into logs or panic/crash output.
///
/// # Usage Examples
///
/// `Secret<i32>` and other scalar types
///
/// [Secret] can wrap any of the following scalar types:
/// u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, bool, and char.
///
/// ```
/// use bouncycastle_utils::secret::Secret;
///
/// let mut nonce: Secret<u64> = Secret::default();
/// *nonce = 0xDEAD_BEEF;
/// assert_eq!(*nonce, 0xDEAD_BEEF);
///
///
/// let mut counter: Secret<i32> = Secret::new();
/// // Here you have to explicitly Deref to get at the underlying type, but it all works.
/// *counter += 1;
/// assert_eq!(*counter, 1);
/// ```
///
/// ## `Secret<[u8; 32]>`
///
/// `Secret` can wrap arrays of any of the supported scalar types.
/// There is no bound on how large an array you can make.
///
/// Here we'll construct a zeroed `Secret<[u8; 32]>` and fill them *in place* through [`DerefMut`],
/// so the plaintext is never held in a separate, unprotected variable:
///
/// ```
/// use bouncycastle_utils::secret::Secret;
///
/// let mut key: Secret<[u8; 32]> = Secret::new();
///
/// // Here, .copy_from_slice may still produce a copy in memory, but it's the best we can do in
/// // illustrative example code.
/// // In real code an RNG or KDF or network socket read should be directly handed the mut ref to
/// // Secret so that it can write directly into it.
/// key.copy_from_slice(&[0x42u8; 32]);
///
/// // `Secret<T>` is (mostly) transparent: you can use it exactly as you would the underlying type T
/// // (possibly requiring a dereference).
/// // indexing, slicing, `.len()`, iteration, etc all work automatically via `Deref`.
/// // Just forget the Secret is there
/// assert_eq!(key[0], 0x42);
/// assert_eq!(key.len(), 32);
/// assert!(key.iter().all(|&b| b == 0x42));
/// // `key` is volatile-scrubbed to zero when it drops at the end of this scope.
/// ```
///
/// ## On a custom type
///
/// Since [ZeroizablePrimitive] is a public trait, you can implement it on your own types and then
/// trivially be able to wrap them in a `Secret<T>`. The only requirement is that there is a
/// well-defined "ZEROED" value for the type.
///
/// Toy Example:
///
/// ```
/// use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
///
/// /// Holds a system user
/// #[derive(Clone, Copy)]
/// struct User {
///     userid: i32,
///     name: [u8; 64],
/// }
///
/// /// Provide the const ZEROED value for the type.
/// impl ZeroizablePrimitive for User {
///     const ZEROED: Self = Self{ userid: 0i32, name: [0u8; 64] };
/// }
///
/// /// We will tag the admins as Secret<User> to give them extra protections against
/// /// having their info leaked.
/// struct AllUsers {
///     users: Vec<User>,
///     admins: Vec<Secret<User>>,
/// }
/// ```
///
/// Note that `Secret<T>` is only defined for statically-sized types -- ie types that satisfy
/// [`Sized`](core::marker::Sized). For a justification, see the module docs.
///
/// # Redacting Debug and Display
///
/// [`Debug`](fmt::Debug) and [`Display`](fmt::Display) are redacting, so a `Secret` can be logged
/// without leaking its contents:
///
/// ```
/// use bouncycastle_utils::secret::Secret;
///
/// let mut secret: Secret<u32> = Secret::new();
/// *secret = 0x4141_4141; // would render as "AAAA" if leaked
/// assert_eq!(format!("{secret}"), "<redacted>");
/// assert_eq!(format!("{secret:?}"), "Secret<u32>(<redacted>)");
/// ```
///
/// This will also work for custom types; let's say the `User` struct from the previous example had
/// impl'd Display and Debug; mhen you wrap them in `Secret<User>` then `Secret`'s Display and Debug
/// are invoked instead of `User`'s and you get the "<redacted>" output.
///
/// # Memory Usage
///
/// As a direct wrapper of the type `T`, a `Secret<T>` does not add any memory overhead.
///
/// ```
/// use bouncycastle_utils::secret::Secret;
///
/// print!("{}\n", size_of::<i32>());          // 4
/// print!("{}\n", size_of::<Secret<i32>>()); // also 4
///
/// print!("{}\n", size_of::<[u8; 32]>());          // 32
/// print!("{}\n", size_of::<Secret<[u8; 32]>>());  // also 32
/// ```
///
/// # 🚨 Security 🚨
///
/// What this does NOT guarantee:
///
/// [Secret] only guarantees that the *final* scrub of the wrapped value is emitted. It cannot
/// recover copies that the compiler or CPU made. To minimize copies of the underlying bytes in memory,
/// you should be careful with a few things:
///
/// * Create a new [Secret] instance, then get a mut ref to its internal value via [Secret::deref_mut]
///   and write to that instead of having a copy in an unprotected variable and then copying it into the Secret.
/// * Avoid copying out of Secret for the same reason.
pub struct Secret<T: ZeroizablePrimitive>(T);

impl<T: ZeroizablePrimitive> Secret<T> {
    /// Create a new `Secret` in a zeroed state.
    ///
    /// Populate it afterwards in place via [`DerefMut`] (e.g. by having an RNG or KDF write into
    /// `&mut *secret`), which avoids ever materializing an unprotected copy of the secret.
    #[inline]
    pub const fn new() -> Self {
        Self(T::ZEROED)
    }
}

impl<T: ZeroizablePrimitive> Default for Secret<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: ZeroizablePrimitive> Secret<T> {
    /// Securely overwrite the contained value with zeros.
    /// After this returns, every byte of the wrapped value has been volatile-written to `0`.
    ///
    /// This is called automatically on drop; call it directly only if you need to scrub the value
    /// early, for example before reusing the same `Secret` object.
    /// Though in many circumstances you are zeroizing because you know you're done with the object before
    /// it goes out of scope, in which case you would be better served calling `drop(s)` instead
    /// since this will still call `zeroize()` and also move the object, preventing you from accidentally reusing it.
    #[inline]
    pub fn zeroize(&mut self) {
        // SAFETY: `&mut self.0` is a valid, properly aligned, mutable reference to an initialized
        // `T`, which is exactly the contract `write_volatile` requires.
        // `T::ZEROED` is defined above for each supported primitive and primitive-array as the
        // is the all-zero value of `T`, which is a valid and correctly-sized bit pattern
        // for the primitive scalar/array being zeroized.
        //`write_volatile` (rather than a plain store) is what forbids the compiler from eliding
        // this scrub as a dead write as per its contract:
        // https://doc.rust-lang.org/std/ptr/fn.write_volatile.html

        // Just to make sure -- this should trigger on any unit tests for any instantiation of
        // Secret<T> that causes this assumption to be violated.
        debug_assert_eq!(size_of::<T>(), size_of_val(&T::ZEROED));

        unsafe {
            ptr::write_volatile(&mut self.0, T::ZEROED);
        }
        // Compile-time barrier: keeps the volatile scrub ordered before any later memory ops.
        // (for example, if the user calls .zeroize() outside of a drop and then continues using
        // the object by filling it with new data, which is valid usage.)
        // Emits no machine instructions.
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: ZeroizablePrimitive> Drop for Secret<T> {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: ZeroizablePrimitive> Deref for Secret<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ZeroizablePrimitive> DerefMut for Secret<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

// Intentionally not `Copy`: a `Copy` type cannot have a `Drop`, and we want move semantics so a
// secret is never silently duplicated. `Clone` is provided for deliberate copies.
impl<T: ZeroizablePrimitive> Clone for Secret<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

/// Redacting: prints the wrapped type but never its contents.
impl<T: ZeroizablePrimitive> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{}>(<redacted>)", type_name::<T>())
    }
}

/// Redacting: never prints the contents.
impl<T: ZeroizablePrimitive> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Checks for equality of the secret data by casting to bytes and using a constant-time comparison.
///
/// Both operands are the same type `T`, so both views are exactly `size_of::<T>()` bytes and the
/// comparison never short-circuits: it always inspects every byte, avoiding a timing side channel
/// that would otherwise leak how many leading bytes of two secrets match.
impl<T: ZeroizablePrimitive> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        let len = size_of::<T>();
        // SAFETY: `self.0` / `other.0` are live, initialized `T` values, so the `len` bytes starting
        // at each address lie within that single object. `u8` has alignment 1, so every byte address
        // is well aligned, and the slices are read-only and used only within this call. `T: Copy`
        // (via `ZeroizablePrimitive`) means there is no interior mutability or drop glue to worry
        // about.
        let a = unsafe { core::slice::from_raw_parts((&self.0 as *const T).cast::<u8>(), len) };
        let b = unsafe { core::slice::from_raw_parts((&other.0 as *const T).cast::<u8>(), len) };
        ct::ct_eq_bytes(a, b)
    }
}
impl<T: ZeroizablePrimitive> Eq for Secret<T> {}
