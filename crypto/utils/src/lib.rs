#![forbid(unsafe_code)]

pub mod ct;

/// Basic max function. If they are equal, it returns the first one.
pub fn max<'a, T: PartialOrd>(x: &'a T, y: &'a T) -> &'a T {
    if x >= y { x } else { y }
}

/// Basic min function. If they are equal, it returns the first one.
pub fn min<'a, T: PartialOrd>(x: &'a T, y: &'a T) -> &'a T {
    if x <= y { x } else { y }
}
