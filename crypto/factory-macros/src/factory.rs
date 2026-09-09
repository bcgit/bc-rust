//! Expansion for the `AlgorithmFactory` derive -- see the `AlgorithmFactory` entry point in the
//! crate root.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataEnum, DeriveInput, Ident, Path, Type};

use crate::{as_data_enum, single_field_type};

/// Generates the `Default` and `crate::AlgorithmFactory` impls from the per-variant
/// `#[factory(...)]` attributes.
pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let enum_name = &input.ident;
    let variants = parse_factory_variants(as_data_enum(input)?)?;

    let default_128 = variants.iter().find(|v| v.is_default_128_bit);
    let default_256 = variants.iter().find(|v| v.is_default_256_bit);
    let (Some(default_128), Some(default_256)) = (default_128, default_256) else {
        return Err(syn::Error::new_spanned(
            input,
            "exactly one variant needs `#[factory(default_128_bit)]` and one needs \
             `#[factory(default_256_bit)]`",
        ));
    };
    let default_128_ident = &default_128.ident;
    let default_128_ty = &default_128.ty;
    let default_256_ident = &default_256.ident;
    let default_256_ty = &default_256.ty;

    let idents: Vec<&Ident> = variants.iter().map(|v| &v.ident).collect();
    let tys: Vec<&Type> = variants.iter().map(|v| &v.ty).collect();
    let name_consts: Vec<&Path> = variants.iter().map(|v| &v.name_const).collect();

    Ok(quote! {
        impl ::std::default::Default for #enum_name {
            fn default() -> #enum_name {
                <#enum_name as crate::AlgorithmFactory>::default_128_bit()
            }
        }

        impl crate::AlgorithmFactory for #enum_name {
            fn default_128_bit() -> #enum_name {
                Self::#default_128_ident(<#default_128_ty>::new())
            }

            fn default_256_bit() -> #enum_name {
                Self::#default_256_ident(<#default_256_ty>::new())
            }

            fn new(alg_name: &str) -> Result<Self, crate::FactoryError> {
                match alg_name {
                    crate::DEFAULT => Ok(<Self as ::std::default::Default>::default()),
                    crate::DEFAULT_128_BIT => {
                        Ok(<Self as crate::AlgorithmFactory>::default_128_bit())
                    }
                    crate::DEFAULT_256_BIT => {
                        Ok(<Self as crate::AlgorithmFactory>::default_256_bit())
                    }
                    #(#name_consts => Ok(Self::#idents(<#tys>::new())),)*
                    _ => Err(crate::FactoryError::UnsupportedAlgorithm(format!(
                        "The algorithm: \"{}\" is not a known {}",
                        alg_name,
                        stringify!(#enum_name),
                    ))),
                }
            }
        }
    })
}

/// One enum variant's worth of parsed `#[factory(...)]` configuration.
struct FactoryVariant {
    ident: Ident,
    ty: Type,
    name_const: Path,
    is_default_128_bit: bool,
    is_default_256_bit: bool,
}

/// Parses the `#[factory(...)]` helper attribute off every variant.
fn parse_factory_variants(data: &DataEnum) -> syn::Result<Vec<FactoryVariant>> {
    data.variants
        .iter()
        .map(|variant| {
            let ty = single_field_type(variant)?.clone();

            let mut name_const = None;
            let mut is_default_128_bit = false;
            let mut is_default_256_bit = false;

            for attr in &variant.attrs {
                if !attr.path().is_ident("factory") {
                    continue;
                }
                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("name") {
                        name_const = Some(meta.value()?.parse::<Path>()?);
                        Ok(())
                    } else if meta.path.is_ident("default_128_bit") {
                        is_default_128_bit = true;
                        Ok(())
                    } else if meta.path.is_ident("default_256_bit") {
                        is_default_256_bit = true;
                        Ok(())
                    } else {
                        Err(meta.error(
                            "unrecognized `factory` attribute; expected `name`, \
                             `default_128_bit`, or `default_256_bit`",
                        ))
                    }
                })?;
            }

            let name_const = name_const.ok_or_else(|| {
                syn::Error::new_spanned(
                    variant,
                    "every variant needs `#[factory(name = ...)]` giving its algorithm-name constant",
                )
            })?;

            Ok(FactoryVariant {
                ident: variant.ident.clone(),
                ty,
                name_const,
                is_default_128_bit,
                is_default_256_bit,
            })
        })
        .collect()
}
