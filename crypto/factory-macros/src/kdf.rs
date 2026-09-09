//! Expansion for the `KDF` derive -- see the `KDF` entry point in the crate root.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataEnum, DeriveInput, Ident};

use crate::{as_data_enum, single_field_type};

/// Generates the `bouncycastle_core::traits::KDF` impl, forwarding every trait method to the
/// wrapped value of whichever variant the enum currently holds.
pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let enum_name = &input.ident;
    let idents = single_field_variant_idents(as_data_enum(input)?)?;

    Ok(quote! {
        impl ::bouncycastle_core::traits::KDF for #enum_name {
            fn derive_key(
                self,
                key: &impl ::bouncycastle_core::key_material::KeyMaterialTrait,
                additional_input: &[u8],
            ) -> Result<
                ::std::boxed::Box<dyn ::bouncycastle_core::key_material::KeyMaterialTrait>,
                ::bouncycastle_core::errors::KDFError,
            > {
                match self { #(Self::#idents(h) => h.derive_key(key, additional_input),)* }
            }

            fn derive_key_out(
                self,
                key: &impl ::bouncycastle_core::key_material::KeyMaterialTrait,
                additional_input: &[u8],
                output_key: &mut impl ::bouncycastle_core::key_material::KeyMaterialTrait,
            ) -> Result<usize, ::bouncycastle_core::errors::KDFError> {
                match self {
                    #(Self::#idents(h) => h.derive_key_out(key, additional_input, output_key),)*
                }
            }

            fn derive_key_from_multiple(
                self,
                keys: &[&impl ::bouncycastle_core::key_material::KeyMaterialTrait],
                additional_input: &[u8],
            ) -> Result<
                ::std::boxed::Box<dyn ::bouncycastle_core::key_material::KeyMaterialTrait>,
                ::bouncycastle_core::errors::KDFError,
            > {
                match self {
                    #(Self::#idents(h) => h.derive_key_from_multiple(keys, additional_input),)*
                }
            }

            fn derive_key_from_multiple_out(
                self,
                keys: &[&impl ::bouncycastle_core::key_material::KeyMaterialTrait],
                additional_input: &[u8],
                output_key: &mut impl ::bouncycastle_core::key_material::KeyMaterialTrait,
            ) -> Result<usize, ::bouncycastle_core::errors::KDFError> {
                match self {
                    #(Self::#idents(h) => {
                        h.derive_key_from_multiple_out(keys, additional_input, output_key)
                    })*
                }
            }

            fn max_security_strength(&self) -> ::bouncycastle_core::traits::SecurityStrength {
                match self { #(Self::#idents(h) => h.max_security_strength(),)* }
            }
        }
    })
}

/// Collects each variant's ident, rejecting any variant that isn't a single-field tuple since
/// there would be no unambiguous value to forward the trait methods to.
fn single_field_variant_idents(data: &DataEnum) -> syn::Result<Vec<Ident>> {
    data.variants
        .iter()
        .map(|v| {
            single_field_type(v)?;
            Ok(v.ident.clone())
        })
        .collect()
}
