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
    Digest(utils::Attr<kw::digest, syn::Path>),
}

impl Parse for MhAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(kw::code) {
            Ok(MhAttr::Code(input.parse()?))
        } else if input.peek(kw::hasher) {
            Ok(MhAttr::Hasher(input.parse()?))
        } else {
            Ok(MhAttr::Digest(input.parse()?))
        }
    }
}

struct Params {
    mh_crate: syn::Ident,
    code_enum: syn::Ident,
}

#[derive(Debug)]
struct Hash {
    ident: syn::Ident,
    code: syn::Expr,
    hasher: Box<syn::Type>,
    digest: syn::Path,
}

impl Hash {
    fn code_into_u64(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let code_enum = &params.code_enum;
        let code = &self.code;
        quote!(#code_enum::#ident => #code)
    }

    fn code_from_u64(&self) -> TokenStream {
        let ident = &self.ident;
        let code = &self.code;
        quote!(#code => Ok(Self::#ident))
    }

    fn code_digest(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let hasher = &self.hasher;
        let code = &self.code;
        let mh_crate = &params.mh_crate;
        quote!(Self::#ident => {
           let digest = #hasher::digest(input);
           #mh_crate::Multihash::wrap(#code, &digest.as_ref()).unwrap()
        })
    }

    fn from_digest(&self, params: &Params) -> TokenStream {
        let digest = &self.digest;
        let code_enum = &params.code_enum;
        let ident = &self.ident;
        quote! {
           impl From<&#digest> for #code_enum {
               fn from(digest: &#digest) -> Self {
                   Self::#ident
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
                        MhAttr::Digest(attr) => digest = Some(attr.value),
                    }
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
            let msg = "Missing digest atttibute: e.g. #[mh(digest = multihash::Sha2Digest<U32>)]";
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
    let code_enum = &s.ast().ident;
    let hashes: Vec<_> = s.variants().iter().map(Hash::from).collect();

    error_code_duplicates(&hashes);

    let params = Params {
        mh_crate: mh_crate.clone(),
        code_enum: code_enum.clone(),
    };

    let code_into_u64 = hashes.iter().map(|h| h.code_into_u64(&params));
    let code_from_u64 = hashes.iter().map(|h| h.code_from_u64());
    let code_digest = hashes.iter().map(|h| h.code_digest(&params));
    let from_digest = hashes.iter().map(|h| h.from_digest(&params));

    quote! {
        impl #code_enum {
            /// Calculate the hash of some input data.
            ///
            /// # Example
            ///
            /// ```
            /// use tiny_multihash::Code;
            ///
            /// let hash = Code::Sha3_256.digest(b"Hello world!");
            /// println!("{:02x?}", hash);
            /// ```
            // TODO vmx 2020-09-21: Don't hardcode the size here, define it in the code enum
            pub fn digest(&self, input: &[u8]) -> Multihash<U64> {
                match self {
                    #(#code_digest,)*
                }
            }

            /// Create a multihash from an existing [`Digest`].
            ///
            /// # Example
            ///
            /// ```
            /// use tiny_multihash::{Code, Sha3_256, StatefulHasher};
            ///
            /// let mut hasher = Sha3_256::default();
            /// hasher.update(b"Hello world!");
            /// let hash = Code::multihash_from_digest(&hasher.finalize());
            /// println!("{:02x?}", hash);
            /// ```
            pub fn multihash_from_digest<'a, S, D>(digest: &'a D) -> Multihash<U64>
            where
                S: Size,
                D: #mh_crate::Digest<S>,
                Self: From<&'a D>,
            {
                let code = Self::from(&digest);
                #mh_crate::Multihash::wrap(code.into(), &digest.as_ref()).unwrap()
            }
        }

        impl From<#code_enum> for u64 {
            fn from(code: #code_enum) -> Self {
                match code {
                    #(#code_into_u64,)*
                }
            }
        }

        impl core::convert::TryFrom<u64> for #code_enum {
            type Error = #mh_crate::Error;

            fn try_from(code: u64) -> Result<Self, Self::Error> {
                match code {
                    #(#code_from_u64,)*
                    _ => Err(#mh_crate::Error::UnsupportedCode(code))
                }
            }
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
           pub enum Code {
               #[mh(code = tiny_multihash::IDENTITY, hasher = tiny_multihash::Identity256, digest = tiny_multihash::IdentityDigest<U32>)]
               Identity256,
               /// Multihash array for hash function.
               #[mh(code = 0x38b64f, hasher = tiny_multihash::Strobe256, digest = tiny_multihash::StrobeDigest<U32>)]
               Strobe256,
            }
        };
        let expected = quote! {
            impl Code {
               /// Calculate the hash of some input data.
               ///
               /// # Example
               ///
               /// ```
               /// use tiny_multihash::Code;
               ///
               /// let hash = Code::Sha3_256.digest(b"Hello world!");
               /// println!("{:02x?}", hash);
               /// ```
               pub fn digest(&self, input: &[u8]) -> Multihash<U64> {
                   match self {
                       Self::Identity256 => {
                           let digest = tiny_multihash::Identity256::digest(input);
                           tiny_multihash::Multihash::wrap(tiny_multihash::IDENTITY, &digest.as_ref()).unwrap()
                       },
                       Self::Strobe256 => {
                           let digest = tiny_multihash::Strobe256::digest(input);
                           tiny_multihash::Multihash::wrap(0x38b64f, &digest.as_ref()).unwrap()
                       },
                   }
               }

               /// Create a multihash from an existing [`Digest`].
               ///
               /// # Example
               ///
               /// ```
               /// use tiny_multihash::{Code, Sha3_256, StatefulHasher};
               ///
               /// let mut hasher = Sha3_256::default();
               /// hasher.update(b"Hello world!");
               /// let hash = Code::multihash_from_digest(&hasher.finalize());
               /// println!("{:02x?}", hash);
               /// ```
               pub fn multihash_from_digest<'a, S, D>(digest: &'a D) -> Multihash<U64>
               where
                   S: Size,
                   D: tiny_multihash::Digest<S>,
                   Self: From<&'a D>,
               {
                   let code = Self::from(&digest);
                   tiny_multihash::Multihash::wrap(code.into(), &digest.as_ref()).unwrap()
               }
            }


            impl From<Code> for u64 {
                fn from(code: Code) -> Self {
                    match code {
                        Code::Identity256 => tiny_multihash::IDENTITY,
                        Code::Strobe256 => 0x38b64f,
                    }
                }
            }

            impl core::convert::TryFrom<u64> for Code {
                type Error = tiny_multihash::Error;

                fn try_from(code: u64) -> Result<Self, Self::Error> {
                    match code {
                        tiny_multihash::IDENTITY => Ok(Self::Identity256),
                        0x38b64f => Ok(Self::Strobe256),
                        _ => Err(tiny_multihash::Error::UnsupportedCode(code))
                    }
                }
            }

            impl From<&tiny_multihash::IdentityDigest<U32> > for Code {
                fn from(digest: &tiny_multihash::IdentityDigest<U32>) -> Self {
                    Self::Identity256
                }
            }
            impl From<&tiny_multihash::StrobeDigest<U32> > for Code {
                fn from(digest: &tiny_multihash::StrobeDigest<U32>) -> Self {
                    Self::Strobe256
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
               #[mh(code = tiny_multihash::SHA2_256, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
               Identity256,
               #[mh(code = tiny_multihash::SHA2_256, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
               Identity256,
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
           pub enum Code {
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
               Identity256,
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
               Identity256,
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }
}
