use std::collections::HashSet;

use crate::utils;
use proc_macro2::TokenStream;
use quote::quote;
#[cfg(not(test))]
use quote::ToTokens;
use syn::parse::{Parse, ParseStream};
#[cfg(not(test))]
use syn::spanned::Spanned;
use synstructure::{Structure, VariantInfo};

mod kw {
    use syn::custom_keyword;

    custom_keyword!(code);
    custom_keyword!(digest);
    custom_keyword!(hasher);
    custom_keyword!(mh);
}

#[derive(Debug)]
enum MhAttr {
    Code(utils::Attr<kw::code, syn::Expr>),
    Hasher(utils::Attr<kw::hasher, Box<syn::Type>>),
}

impl Parse for MhAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(kw::code) {
            Ok(MhAttr::Code(input.parse()?))
        } else {
            Ok(MhAttr::Hasher(input.parse()?))
        }
    }
}

struct Params {
    mh_crate: syn::Ident,
    mh_enum: syn::Ident,
}

#[derive(Debug)]
struct Hash {
    ident: syn::Ident,
    code: syn::Expr,
    hasher: Box<syn::Type>,
    digest: syn::Path,
}

impl Hash {
    fn digest_code(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let mh_enum = &params.mh_enum;
        let code = &self.code;
        quote!(#mh_enum::#ident(_mh) => #code)
    }

    fn digest_size(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let mh_enum = &params.mh_enum;
        let mh = &params.mh_crate;
        quote!(#mh_enum::#ident(mh) => #mh::Digest::size(mh))
    }

    fn digest_digest(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let mh_enum = &params.mh_enum;
        quote!(#mh_enum::#ident(mh) => mh.as_ref())
    }

    fn digest_new(&self) -> TokenStream {
        let code = &self.code;
        let ident = &self.ident;
        let hasher = &self.hasher;
        quote!(#code => Ok(Self::#ident(#hasher::digest(input))))
    }

    fn digest_wrap(&self, params: &Params) -> TokenStream {
        let code = &self.code;
        let ident = &self.ident;
        let mh = &params.mh_crate;
        quote!(#code => Ok(Self::#ident(#mh::Digest::wrap(digest)?)))
    }

    #[cfg(feature = "std")]
    fn digest_read(&self, params: &Params) -> TokenStream {
        let code = &self.code;
        let ident = &self.ident;
        let mh = &params.mh_crate;
        quote!(#code => Ok(Self::#ident(#mh::Digest::from_reader(r)?)))
    }

    fn from_digest(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let digest = &self.digest;
        let mh_enum = &params.mh_enum;
        quote! {
            impl From<#digest> for #mh_enum {
                fn from(digest: #digest) -> Self {
                    Self::#ident(digest)
                }
            }
        }
    }
}

impl<'a> From<&'a VariantInfo<'a>> for Hash {
    fn from(bi: &'a VariantInfo<'a>) -> Self {
        let mut code = None;
        let mut digest = None;
        let mut hasher = None;
        for attr in bi.ast().attrs {
            let attr: Result<utils::Attrs<MhAttr>, _> = syn::parse2(attr.tokens.clone());
            if let Ok(attr) = attr {
                for attr in attr.attrs {
                    match attr {
                        MhAttr::Code(attr) => code = Some(attr.value),
                        MhAttr::Hasher(attr) => hasher = Some(attr.value),
                    }
                }
            }
        }

        if let syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) = bi.ast().fields {
            if let Some(field) = unnamed.first() {
                if let syn::Type::Path(path) = &field.ty {
                    digest = Some(path.path.clone());
                }
            }
        }

        let ident = bi.ast().ident.clone();
        let code = code.unwrap_or_else(|| {
            let msg = "Missing code attribute: e.g. #[mh(code = multihash::SHA3_256)]";
            #[cfg(test)]
            panic!(msg);
            #[cfg(not(test))]
            proc_macro_error::abort!(ident, msg);
        });
        let hasher = hasher.unwrap_or_else(|| {
            let msg = "Missing hasher attribute: e.g. #[mh(hasher = multihash::Sha2_256)]";
            #[cfg(test)]
            panic!(msg);
            #[cfg(not(test))]
            proc_macro_error::abort!(ident, msg);
        });
        let digest = digest.unwrap_or_else(|| {
            let msg = "Missing digest in enum variant: e.g. Sha256(multihash::Sha2Digest<U32>)]";
            #[cfg(test)]
            panic!(msg);
            #[cfg(not(test))]
            proc_macro_error::abort!(ident, msg);
        });
        Self {
            ident,
            code,
            digest,
            hasher,
        }
    }
}

/// Return an error if the same code is used several times.
///
/// This only checks for string equality, though this should still catch most errors caused by
/// copy and pasting.
fn error_code_duplicates(hashes: &[Hash]) {
    // Use a temporary store to determine whether a certain value is unique or not
    let mut uniq = HashSet::new();

    hashes.iter().for_each(|hash| {
        let code = &hash.code;
        let msg = format!(
            "the #mh(code) attribute `{}` is defined multiple times",
            quote!(#code)
        );

        // It's a duplicate
        if !uniq.insert(code) {
            #[cfg(test)]
            panic!(msg);
            #[cfg(not(test))]
            {
                let already_defined = uniq.get(code).unwrap();
                let line = already_defined.to_token_stream().span().start().line;
                proc_macro_error::emit_error!(
                    &hash.code, msg;
                    note = "previous definition of `{}` at line {}", quote!(#code), line;
                );
            }
        }
    });
}

pub fn multihash(s: Structure) -> TokenStream {
    let mh_crate = utils::use_crate("tiny-multihash");
    let mh_enum = &s.ast().ident;
    let hashes: Vec<_> = s.variants().iter().map(Hash::from).collect();

    error_code_duplicates(&hashes);

    let params = Params {
        mh_crate: mh_crate.clone(),
        mh_enum: mh_enum.clone(),
    };

    let digest_code = hashes.iter().map(|h| h.digest_code(&params));
    let digest_size = hashes.iter().map(|h| h.digest_size(&params));
    let digest_digest = hashes.iter().map(|h| h.digest_digest(&params));
    let digest_new = hashes.iter().map(|h| h.digest_new());
    let digest_wrap = hashes.iter().map(|h| h.digest_wrap(&params));
    #[cfg(feature = "std")]
    let digest_read = hashes.iter().map(|h| h.digest_read(&params));
    let from_digest = hashes.iter().map(|h| h.from_digest(&params));

    #[cfg(feature = "std")]
    let std_read = quote! {
            fn read<R: std::io::Read>(mut r: R) -> Result<Self, #mh_crate::Error>
            where
               Self: Sized
            {
               let code = unsigned_varint::io::read_u64(&mut r)?;
               match code {
                   #(#digest_read,)*
                   _ => Err(#mh_crate::Error::UnsupportedCode(code)),
               }
            }
    };
    #[cfg(not(feature = "std"))]
    let std_read = quote! {};

    quote! {
        impl From<#mh_enum> for u64 {
           fn from(mh: #mh_enum) -> Self {
               mh.code()
           }
        }

        impl #mh_crate::MultihashDigest for #mh_enum {
           fn new(code: u64, input: &[u8]) -> Result<Self, #mh_crate::Error> {
              match code {
                  #(#digest_new,)*
                  _ => Err(#mh_crate::Error::UnsupportedCode(code)),
              }
           }

           fn wrap(code: u64, digest: &[u8]) -> Result<Self, #mh_crate::Error> {
               match code {
                  #(#digest_wrap,)*
                  _ => Err(#mh_crate::Error::UnsupportedCode(code)),
              }
           }

           fn code(&self) -> u64 {
               match self {
                   #(#digest_code,)*
               }
            }

            fn size(&self) -> u8 {
                match self {
                    #(#digest_size,)*
                }
            }

            fn digest(&self) -> &[u8] {
                match self {
                    #(#digest_digest,)*
                }
            }

            #std_read

        }

        #(#from_digest)*
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multihash_derive() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           pub enum Multihash {
               #[mh(code = tiny_multihash::IDENTITY, hasher = tiny_multihash::Identity256)]
               Identity256(tiny_multihash::IdentityDigest<U32>),
               /// Multihash array for hash function.
               #[mh(code = 0x38b64f, hasher = tiny_multihash::Strobe256)]
               Strobe256(tiny_multihash::StrobeDigest<U32>),
            }
        };
        let expected = quote! {
            impl From<Multihash> for u64 {
                fn from(mh: Multihash) -> Self {
                    mh.code()
                }
            }
            impl tiny_multihash::MultihashDigest for Multihash {
                fn new(code: u64, input: &[u8]) -> Result<Self, tiny_multihash::Error> {
                    match code {
                        tiny_multihash::IDENTITY => Ok(Self::Identity256(tiny_multihash::Identity256::digest(input))),
                        0x38b64f => Ok(Self::Strobe256(tiny_multihash::Strobe256::digest(input))),
                        _ => Err(tiny_multihash::Error::UnsupportedCode(code)),
                    }
                }
                fn wrap(code: u64, digest: &[u8]) -> Result<Self, tiny_multihash::Error> {
                    match code {
                        tiny_multihash::IDENTITY => Ok(Self::Identity256(tiny_multihash::Digest::wrap(digest)?)),
                        0x38b64f => Ok(Self::Strobe256(tiny_multihash::Digest::wrap(digest)?)),
                        _ => Err(tiny_multihash::Error::UnsupportedCode(code)),
                    }
                }
                fn code(&self) -> u64 {
                    match self {
                        Multihash::Identity256(_mh) => tiny_multihash::IDENTITY,
                        Multihash::Strobe256(_mh) => 0x38b64f,
                    }
                }
                fn size(&self) -> u8 {
                    match self {
                        Multihash::Identity256(mh) => tiny_multihash::Digest::size(mh),
                        Multihash::Strobe256(mh) => tiny_multihash::Digest::size(mh),
                    }
                }
                fn digest(&self) -> &[u8] {
                    match self {
                        Multihash::Identity256(mh) => mh.as_ref(),
                        Multihash::Strobe256(mh) => mh.as_ref(),
                    }
                }
                fn read<R: std::io::Read>(mut r: R) -> Result<Self, tiny_multihash::Error>
                where
                    Self: Sized
                {
                    let code = unsigned_varint::io::read_u64(&mut r)?;
                    match code {
                        tiny_multihash::IDENTITY => Ok(Self::Identity256(tiny_multihash::Digest::from_reader(r)?)),
                        0x38b64f => Ok(Self::Strobe256(tiny_multihash::Digest::from_reader(r)?)),
                        _ => Err(tiny_multihash::Error::UnsupportedCode(code)),
                    }
                }
            }
            impl From<tiny_multihash::IdentityDigest<U32> > for Multihash {
                fn from(digest: tiny_multihash::IdentityDigest<U32>) -> Self {
                    Self::Identity256(digest)
                }
            }
            impl From<tiny_multihash::StrobeDigest<U32> > for Multihash {
                fn from(digest: tiny_multihash::StrobeDigest<U32>) -> Self {
                    Self::Strobe256(digest)
                }
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        let result = multihash(s);
        utils::assert_proc_macro(result, expected);
    }

    #[test]
    #[should_panic(
        expected = "the #mh(code) attribute `tiny_multihash :: SHA2_256` is defined multiple times"
    )]
    fn test_multihash_error_code_duplicates() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           pub enum Multihash {
               #[mh(code = tiny_multihash::SHA2_256, hasher = tiny_multihash::Sha2_256)]
               Identity256(tiny_multihash::Sha2Digest<U32>),
               #[mh(code = tiny_multihash::SHA2_256, hasher = tiny_multihash::Sha2_256)]
               Identity256(tiny_multihash::Sha2Digest<U32>),
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }

    #[test]
    #[should_panic(expected = "the #mh(code) attribute `0x14` is defined multiple times")]
    fn test_multihash_error_code_duplicates_numbers() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           pub enum Multihash {
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256)]
               Identity256(tiny_multihash::Sha2Digest<U32>),
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256)]
               Identity256(tiny_multihash::Sha2Digest<U32>),
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }
}
