//! Expansion for the `Hash` derive -- see the `Hash` entry point in the crate root.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataEnum, DeriveInput, Ident};

use crate::{as_data_enum, single_field_type};

/// Generates the `bouncycastle_core::traits::Hash` impl, forwarding every trait method to the
/// wrapped value of whichever variant the enum currently holds.
pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let enum_name = &input.ident;
    let idents = single_field_variant_idents(as_data_enum(input)?)?;

    Ok(quote! {
        impl ::bouncycastle_core::traits::Hash for #enum_name {
            fn block_bitlen(&self) -> usize {
                match self { #(Self::#idents(h) => h.block_bitlen(),)* }
            }

            fn output_len(&self) -> usize {
                match self { #(Self::#idents(h) => h.output_len(),)* }
            }

            fn hash(self, data: &[u8]) -> Vec<u8> {
                match self { #(Self::#idents(h) => h.hash(data),)* }
            }

            fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize {
                output.fill(0);
                match self { #(Self::#idents(h) => h.hash_out(data, output),)* }
            }

            fn do_update(&mut self, data: &[u8]) {
                match self { #(Self::#idents(h) => h.do_update(data),)* }
            }

            fn do_final(self) -> Vec<u8> {
                match self { #(Self::#idents(h) => h.do_final(),)* }
            }

            fn do_final_out(self, output: &mut [u8]) -> usize {
                output.fill(0);
                match self { #(Self::#idents(h) => h.do_final_out(output),)* }
            }

            fn do_final_partial_bits(
                self,
                partial_byte: u8,
                num_partial_bits: usize,
            ) -> Result<Vec<u8>, ::bouncycastle_core::errors::HashError> {
                match self {
                    #(Self::#idents(h) => h.do_final_partial_bits(partial_byte, num_partial_bits),)*
                }
            }

            fn do_final_partial_bits_out(
                self,
                partial_byte: u8,
                num_partial_bits: usize,
                output: &mut [u8],
            ) -> Result<usize, ::bouncycastle_core::errors::HashError> {
                match self {
                    #(Self::#idents(h) => {
                        h.do_final_partial_bits_out(partial_byte, num_partial_bits, output)
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
