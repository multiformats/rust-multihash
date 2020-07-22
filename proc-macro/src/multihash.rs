use crate::utils;
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use synstructure::{Structure, VariantInfo};

mod kw {
    use syn::custom_keyword;

    custom_keyword!(code);
    custom_keyword!(mh);
    custom_keyword!(module);
}

#[derive(Debug)]
enum MhAttr {
    Code(utils::Attr<kw::code, syn::LitInt>),
    Module(utils::Attr<kw::module, syn::Path>),
}

impl Parse for MhAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(kw::code) {
            Ok(MhAttr::Code(input.parse()?))
        } else {
            Ok(MhAttr::Module(input.parse()?))
        }
    }
}

struct Params {
    mh: syn::Ident,
    code: syn::Ident,
    digest: syn::Ident,
}

#[derive(Debug)]
struct Hash {
    ident: syn::Ident,
    code: syn::LitInt,
    module: syn::Path,
}

impl Hash {
    fn match_arm_u64(&self, tokens: TokenStream) -> TokenStream {
        let code = &self.code;
        quote! {
            #code => #tokens
        }
    }

    fn match_arm_code(&self, params: &Params, tokens: TokenStream) -> TokenStream {
        let ident = &self.ident;
        let code = &params.code;
        quote! {
            #code::#ident => #tokens
        }
    }

    fn match_arm_digest(&self, params: &Params, tokens: TokenStream) -> TokenStream {
        let ident = &self.ident;
        let digest = &params.digest;
        quote! {
            #digest::#ident(mh) => #tokens
        }
    }

    fn to_u64(&self, params: &Params) -> TokenStream {
        let code = &self.code;
        self.match_arm_code(params, quote!(#code))
    }

    fn try_from_u64(&self, _params: &Params) -> TokenStream {
        let ident = &self.ident;
        self.match_arm_u64(quote!(Ok(Self::#ident)))
    }

    fn multihash(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let module = &self.module;
        let mh = &params.mh;
        quote! {
            /// Multihash array for hash function.
            #ident(<#module as #mh::Hasher>::Digest)
        }
    }

    fn digest_code(&self, params: &Params) -> TokenStream {
        let code = &params.code;
        let ident = &self.ident;
        self.match_arm_digest(params, quote!(#code::#ident))
    }

    fn digest_digest(&self, params: &Params) -> TokenStream {
        self.match_arm_digest(params, quote!(mh.as_ref()))
    }

    fn digest_read(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let mh = &params.mh;
        self.match_arm_code(params, quote!(Ok(Self::#ident(#mh::read_digest(r)?))))
    }

    fn code_size(&self, params: &Params) -> TokenStream {
        let module = &self.module;
        self.match_arm_code(params, quote!(#module::size()))
    }

    fn code_digest(&self, params: &Params) -> TokenStream {
        let digest = &params.digest;
        let ident = &self.ident;
        let module = &self.module;
        self.match_arm_code(params, quote!(#digest::#ident(#module::digest(input))))
    }

    fn from_digest(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let module = &self.module;
        let mh = &params.mh;
        let digest = &params.digest;
        quote! {
            impl From<<#module as #mh::Hasher>::Digest> for #digest {
                fn from(digest: <#module as #mh::Hasher>::Digest) -> Self {
                    Self::#ident(digest)
                }
            }
        }
    }
}

impl<'a> From<&'a VariantInfo<'a>> for Hash {
    fn from(bi: &'a VariantInfo<'a>) -> Self {
        let mut code = None;
        let mut module = None;
        for attr in bi.ast().attrs {
            let attr: Result<utils::Attrs<MhAttr>, _> = syn::parse2(attr.tokens.clone());
            if let Ok(attr) = attr {
                for attr in attr.attrs {
                    match attr {
                        MhAttr::Code(attr) => code = Some(attr.value),
                        MhAttr::Module(attr) => module = Some(attr.value),
                    }
                }
            }
        }
        let ident = bi.ast().ident.clone();
        let code = code.unwrap_or_else(|| {
            abort!(ident, "Missing code attribute: #[mh(code = 0x42)]");
        });
        let module = module.unwrap_or_else(|| {
            abort!(
                ident,
                "Missing module attribute: #[mh(module = multihash::Sha2_256)]"
            );
        });
        Self {
            ident,
            code,
            module,
        }
    }
}

pub fn multihash(s: Structure) -> TokenStream {
    let mh = utils::use_crate("multihash");
    let code = &s.ast().ident;
    let digest = format_ident!("Multihash");
    let hashes: Vec<_> = s.variants().iter().map(Hash::from).collect();
    let params = Params {
        mh: mh.clone(),
        code: code.clone(),
        digest: digest.clone(),
    };

    let to_u64 = hashes.iter().map(|h| h.to_u64(&params));
    let try_from_u64 = hashes.iter().map(|h| h.try_from_u64(&params));
    let multihash = hashes.iter().map(|h| h.multihash(&params));
    let digest_code = hashes.iter().map(|h| h.digest_code(&params));
    let digest_digest = hashes.iter().map(|h| h.digest_digest(&params));
    let digest_read = hashes.iter().map(|h| h.digest_read(&params));
    let from_digest = hashes.iter().map(|h| h.from_digest(&params));
    let code_size = hashes.iter().map(|h| h.code_size(&params));
    let code_digest = hashes.iter().map(|h| h.code_digest(&params));

    quote! {
        impl From<#code> for u64 {
            fn from(c: #code) -> Self {
                match c {
                    #(#to_u64,)*
                }
            }
        }

        impl core::convert::TryFrom<u64> for #code {
            type Error = #mh::Error;

            fn try_from(n: u64) -> Result<Self, Self::Error> {
                match n {
                    #(#try_from_u64,)*
                    _ => Err(Self::Error::UnsupportedCode(n)),
                }
            }
        }

        /// Multihash.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub enum #digest {
            #(#multihash,)*
        }

        impl #mh::MultihashDigest<#code> for #digest {
            fn code(&self) -> #code {
                match self {
                    #(#digest_code,)*
                }
            }

            fn digest(&self) -> &[u8] {
                match self {
                    #(#digest_digest,)*
                }
            }

            #[cfg(feature = "std")]
            fn read<R: std::io::Read>(mut r: R) -> Result<Self, #mh::Error>
            where
                Self: Sized
            {
                let code = #mh::read_code(&mut r)?;
                match code {
                    #(#digest_read,)*
                }
            }
        }

        #(#from_digest)*

        impl #mh::MultihashCode for #code {
            type Multihash = Multihash;

            fn size(&self) -> u8 {
                use #mh::Hasher;
                match self {
                    #(#code_size,)*
                }
            }

            fn digest(&self, input: &[u8]) -> Self::Multihash {
                use #mh::Hasher;
                match self {
                    #(#code_digest,)*
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multihash_derive() {
        let input = quote! {
            #[derive(Clone, Copy, Multihash)]
            pub enum Code {
                #[mh(code = 0x00, module = multihash::Identity256)]
                Identity256,
                #[mh(code = 0x01, module = multihash::Strobe256, feature = "strobe")]
                Strobe256,
            }
        };
        let expected = quote! {
            impl From<Code> for u64 {
                fn from(c: Code) -> Self {
                    match c {
                        Code::Identity256 => 0x00,
                        #[cfg(feature = "strobe")]
                        Code::Strobe256 => 0x01,
                    }
                }
            }

            impl core::convert::TryFrom<u64> for Code {
                type Error = multihash::Error;

                fn try_from(n: u64) -> Result<Self, Self::Error> {
                    match n {
                        0x00 => Ok(Self::Identity256),
                        #[cfg(feature = "strobe")]
                        0x01 => Ok(Self::Strobe256),
                        _ => Err(Self::Error::UnsupportedCode(n)),
                    }
                }
            }

            /// Multihash.
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub enum Multihash {
                /// Multihash array for hash function.
                Identity256(<multihash::Identity256 as multihash::Hasher>::Digest),
                /// Multihash array for hash function.
                #[cfg(feature = "strobe")]
                Strobe256(<multihash::Strobe256 as multihash::Hasher>::Digest),
            }

            impl multihash::MultihashDigest<Code> for Multihash {
                fn code(&self) -> Code {
                    match self {
                        Multihash::Identity256(mh) => Code::Identity256,
                        #[cfg(feature = "strobe")]
                        Multihash::Strobe256(mh) => Code::Strobe256,
                    }
                }

                fn digest(&self) -> &[u8] {
                    match self {
                        Multihash::Identity256(mh) => mh.as_ref(),
                        #[cfg(feature = "strobe")]
                        Multihash::Strobe256(mh) => mh.as_ref(),
                    }
                }

                #[cfg(feature = "std")]
                fn read<R: std::io::Read>(mut r: R) -> Result<Self, multihash::Error>
                where
                    Self: Sized
                {
                    let code = multihash::read_code(&mut r)?;
                    match code {
                        Code::Identity256 => Ok(Self::Identity256(multihash::read_digest(r)?)),
                        #[cfg(feature = "strobe")]
                        Code::Strobe256 => Ok(Self::Strobe256(multihash::read_digest(r)?)),
                    }
                }
            }

            impl From<<multihash::Identity256 as multihash::Hasher>::Digest> for Multihash {
                fn from(digest: <multihash::Identity256 as multihash::Hasher>::Digest) -> Self {
                    Self::Identity256(digest)
                }
            }

            #[cfg(feature = "strobe")]
            impl From<<multihash::Strobe256 as multihash::Hasher>::Digest> for Multihash {
                fn from(digest: <multihash::Strobe256 as multihash::Hasher>::Digest) -> Self {
                    Self::Strobe256(digest)
                }
            }

            impl multihash::MultihashCode for Code {
                type Multihash = Multihash;

                fn size(&self) -> u8 {
                    use multihash::Hasher;
                    match self {
                        Code::Identity256 => multihash::Identity256::size(),
                        #[cfg(feature = "strobe")]
                        Code::Strobe256 => multihash::Strobe256::size(),
                    }
                }

                fn digest(&self, input: &[u8]) -> Self::Multihash {
                    use multihash::Hasher;
                    match self {
                        Code::Identity256 => Multihash::Identity256(multihash::Identity256::digest(input)),
                        #[cfg(feature = "strobe")]
                        Code::Strobe256 => Multihash::Strobe256(multihash::Strobe256::digest(input)),
                    }
                }
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        let result = multihash(s);
        utils::assert_proc_macro(result, expected);
    }
}
