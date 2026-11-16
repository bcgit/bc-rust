//! [`ConstStr`]: a string assembled at compile time from `&str` parts, for an algorithm name
//! built from type parameters (`"ECC-CDH-" + C::NAME`), which a `const` item needs as a
//! `&'static str` and stable Rust has no `concat!` for.

/// Up to `N` bytes of string built by [`ConstStr::concat`], read back by [`ConstStr::as_str`].
/// Held in a `const` of the generic type that names it, so each instantiation gets its own
/// static copy.
pub struct ConstStr<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> ConstStr<N> {
    /// The concatenation of `parts`, which must fit in `N` bytes: a longer result is a
    /// compile-time error where the constant is evaluated.
    pub const fn concat(parts: &[&str]) -> Self {
        let mut buf = [0u8; N];
        let mut len = 0;
        let mut i = 0;
        while i < parts.len() {
            let bytes = parts[i].as_bytes();
            let mut j = 0;
            while j < bytes.len() {
                assert!(len < N, "ConstStr::concat: the parts do not fit in N bytes");
                buf[len] = bytes[j];
                len += 1;
                j += 1;
            }
            i += 1;
        }
        Self { buf, len }
    }

    /// The string.
    pub const fn as_str(&self) -> &str {
        match core::str::from_utf8(self.buf.split_at(self.len).0) {
            Ok(s) => s,
            // Unreachable: the bytes are a concatenation of `str`s, each valid UTF-8, and the
            // boundary between two of them is a character boundary.
            Err(_) => panic!("ConstStr::as_str: the parts were str"),
        }
    }

    /// The string's length in bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the string is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}
