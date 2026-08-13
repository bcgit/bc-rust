//! Procedural derive macros that remove per-variant boilerplate from the enum-based algorithm
//! factories in `bouncycastle-factory` (e.g. `HashFactory`).
//!
//! This is a build-time-only proc-macro crate: `syn`/`quote`/`proc-macro2` are used to generate
//! code at compile time and are not linked into any downstream binary.
//!
//! Two derives are provided, meant to be used together on a single-field-tuple-variant enum.
//! Each shares its name with the trait it implements -- the derive lives in the macro namespace
//! and the trait in the type namespace, so e.g. `#[derive(Hash)]` and
//! `impl bouncycastle_core::traits::Hash for X` don't collide, the same way `serde::Serialize`
//! names both a trait and its derive:
//!
//! - [`macro@Hash`] generates the `bouncycastle_core::traits::Hash` trait impl, forwarding every
//!   method to whichever variant the enum currently holds.
//! - [`macro@AlgorithmFactory`] generates `Default` and `crate::AlgorithmFactory` trait impls
//!   (`new`/`default_128_bit`/`default_256_bit`), reading each variant's algorithm-name constant
//!   and default-security-level markers from a `#[factory(...)]` helper attribute.
//!
//! # Usage Examples
//!
//! ```ignore
//! #[derive(Hash, AlgorithmFactory)]
//! pub enum HashFactory {
//!     #[factory(name = SHA224_NAME)]
//!     SHA224(sha2::SHA224),
//!     #[factory(name = SHA3_256_NAME, default_128_bit)]
//!     SHA3_256(sha3::SHA3_256),
//!     #[factory(name = SHA3_512_NAME, default_256_bit)]
//!     SHA3_512(sha3::SHA3_512),
//! }
//! ```
//!
//! # Layout
//!
//! `#[proc_macro_derive]` functions have to live at the crate root, so this file holds only the
//! entry points and the parsing helpers both derives share; each derive's expansion lives in its
//! own module (`hash`, `factory`).

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod factory;
mod hash;

use proc_macro::TokenStream;
use syn::{Data, DataEnum, DeriveInput, Fields, Type, parse_macro_input};

/// Derives `bouncycastle_core::traits::Hash` for an enum whose variants are each a single-field
/// tuple wrapping a type that itself implements that trait. Every method is forwarded to the
/// wrapped variant, so adding a new algorithm only requires adding an enum variant -- no match
/// arms to update by hand.
#[proc_macro_derive(Hash, attributes(factory))]
pub fn derive_hash(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    hash::expand(&input).unwrap_or_else(syn::Error::into_compile_error).into()
}

/// Derives `Default` and `AlgorithmFactory` (`new`/`default_128_bit`/`default_256_bit`) for an
/// enum whose variants are each a single-field tuple, using a `#[factory(...)]` helper attribute
/// on each variant to supply:
///
/// - `name = SOME_NAME_CONST` (required) -- the string constant `AlgorithmFactory::new` matches
///   on to construct that variant.
/// - `default_128_bit` / `default_256_bit` (each required on exactly one variant) -- marks which
///   variant `default_128_bit()`/`default_256_bit()` construct.
///
/// Generated code refers to `AlgorithmFactory`/`FactoryError`/`DEFAULT*` via `crate::`, so this
/// derive is only meant to be used on enums defined inside the `bouncycastle-factory` crate
/// itself.
#[proc_macro_derive(AlgorithmFactory, attributes(factory))]
pub fn derive_algorithm_factory(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    factory::expand(&input).unwrap_or_else(syn::Error::into_compile_error).into()
}

/// Both derives only make sense on enums; anything else gets a pointed error rather than a
/// confusing failure from deeper in the expansion.
fn as_data_enum(input: &DeriveInput) -> syn::Result<&DataEnum> {
    match &input.data {
        Data::Enum(data) => Ok(data),
        _ => Err(syn::Error::new_spanned(input, "this derive only supports enums")),
    }
}

/// The wrapped type of a single-field tuple variant, which is the value both derives forward to.
fn single_field_type(variant: &syn::Variant) -> syn::Result<&Type> {
    match &variant.fields {
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            Ok(&fields.unnamed.first().expect("just checked len == 1").ty)
        }
        _ => Err(syn::Error::new_spanned(
            variant,
            "expected a single-field tuple variant, e.g. `Variant(SomeType)`",
        )),
    }
}
