use crate::utils;
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use synstructure::{Structure, VariantInfo};

mod kw {
    use syn::custom_keyword;

    custom_keyword!(code);
    custom_keyword!(feature);
    custom_keyword!(mh);
    custom_keyword!(module);
}

#[derive(Debug)]
enum MhAttr {
    Code(utils::Attr<kw::code, syn::LitInt>),
    Feature(utils::Attr<kw::feature, syn::LitStr>),
    Module(utils::Attr<kw::module, syn::Path>),
}

impl Parse for MhAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(kw::code) {
            Ok(MhAttr::Code(input.parse()?))
        } else if input.peek(kw::feature) {
            Ok(MhAttr::Feature(input.parse()?))
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
    feature: Option<syn::LitStr>,
    module: syn::Path,
}

impl Hash {
    fn cfg(&self) -> TokenStream {
        if let Some(feature) = self.feature.as_ref() {
            quote!(#[cfg(feature = #feature)])
        } else {
            quote!()
        }
    }

    fn match_arm_u64(&self, tokens: TokenStream) -> TokenStream {
        let cfg = self.cfg();
        let code = &self.code;
        quote! {
            #cfg
            #code => #tokens
        }
    }

    fn match_arm_code(&self, params: &Params, tokens: TokenStream) -> TokenStream {
        let cfg = self.cfg();
        let ident = &self.ident;
        let code = &params.code;
        quote! {
            #cfg
            #code::#ident => #tokens
        }
    }

    fn match_arm_digest(&self, params: &Params, tokens: TokenStream) -> TokenStream {
        let cfg = self.cfg();
        let ident = &self.ident;
        let digest = &params.digest;
        quote! {
            #cfg
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
        let cfg = self.cfg();
        let ident = &self.ident;
        let module = &self.module;
        let mh = &params.mh;
        let code = &params.code;
        quote! {
            /// Multihash array for hash function.
            #cfg
            #ident(#mh::MultihashArray<#code, <#module as #mh::Hasher>::Size>)
        }
    }

    fn digest_code(&self, params: &Params) -> TokenStream {
        self.match_arm_digest(params, quote!(mh.code()))
    }

    fn digest_size(&self, params: &Params) -> TokenStream {
        self.match_arm_digest(params, quote!(mh.size()))
    }

    fn digest_digest(&self, params: &Params) -> TokenStream {
        self.match_arm_digest(params, quote!(mh.digest()))
    }

    fn digest_read(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let mh = &params.mh;
        self.match_arm_code(params, quote!(Ok(Self::#ident(#mh::read_mh(r, code)?))))
    }

    fn digest_write(&self, params: &Params) -> TokenStream {
        self.match_arm_digest(params, quote!(mh.write(w)))
    }

    fn code_size(&self, params: &Params) -> TokenStream {
        let module = &self.module;
        self.match_arm_code(params, quote!(<#module as Hasher>::Size::to_u8()))
    }

    fn code_digest(&self, params: &Params) -> TokenStream {
        let digest = &params.digest;
        let ident = &self.ident;
        let module = &self.module;
        self.match_arm_code(
            params,
            quote!(#digest::#ident(#module::multi_digest(input))),
        )
    }

    fn multihasher_code(&self, params: &Params) -> TokenStream {
        let cfg = self.cfg();
        let ident = &self.ident;
        let module = &self.module;
        let mh = &params.mh;
        let code = &params.code;
        quote! {
            #cfg
            impl #mh::MultihasherCode<#code> for #module {
                const CODE: #code = #code::#ident;
            }
        }
    }
}

impl<'a> From<&'a VariantInfo<'a>> for Hash {
    fn from(bi: &'a VariantInfo<'a>) -> Self {
        let mut code = None;
        let mut feature = None;
        let mut module = None;
        for attr in bi.ast().attrs {
            let attr: Result<utils::Attrs<MhAttr>, _> = syn::parse2(attr.tokens.clone());
            if let Ok(attr) = attr {
                for attr in attr.attrs {
                    match attr {
                        MhAttr::Code(attr) => code = Some(attr.value),
                        MhAttr::Feature(attr) => feature = Some(attr.value),
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
            abort!(ident, "Missing module attribute: #[mh(module = multihash::Sha2_256)]");
        });
        Self {
            ident,
            code,
            feature,
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
    let digest_size = hashes.iter().map(|h| h.digest_size(&params));
    let digest_digest = hashes.iter().map(|h| h.digest_digest(&params));
    let digest_read = hashes.iter().map(|h| h.digest_read(&params));
    let digest_write = hashes.iter().map(|h| h.digest_write(&params));
    let code_size = hashes.iter().map(|h| h.code_size(&params));
    let code_digest = hashes.iter().map(|h| h.code_digest(&params));
    let multihasher_code = hashes.iter().map(|h| h.multihasher_code(&params));

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

            #[cfg(feature = "std")]
            fn write<W: std::io::Write>(&self, w: W) -> Result<(), #mh::Error> {
                match self {
                    #(#digest_write,)*
                }
            }
        }

        impl #mh::MultihashCode for #code {
            type Multihash = Multihash;

            fn size(&self) -> u8 {
                use #mh::{Hasher, Unsigned};
                match self {
                    #(#code_size,)*
                }
            }

            fn digest(&self, input: &[u8]) -> Self::Multihash {
                use #mh::Multihasher;
                match self {
                    #(#code_digest,)*
                }
            }
        }

        #(#multihasher_code)*
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
                Identity256(multihash::MultihashArray<Code, <multihash::Identity256 as multihash::Hasher>::Size>),
                /// Multihash array for hash function.
                #[cfg(feature = "strobe")]
                Strobe256(multihash::MultihashArray<Code, <multihash::Strobe256 as multihash::Hasher>::Size>),
            }

            impl multihash::MultihashDigest<Code> for Multihash {
                fn code(&self) -> Code {
                    match self {
                        Multihash::Identity256(mh) => mh.code(),
                        #[cfg(feature = "strobe")]
                        Multihash::Strobe256(mh) => mh.code(),
                    }
                }

                fn size(&self) -> u8 {
                    match self {
                        Multihash::Identity256(mh) => mh.size(),
                        #[cfg(feature = "strobe")]
                        Multihash::Strobe256(mh) => mh.size(),
                    }
                }

                fn digest(&self) -> &[u8] {
                    match self {
                        Multihash::Identity256(mh) => mh.digest(),
                        #[cfg(feature = "strobe")]
                        Multihash::Strobe256(mh) => mh.digest(),
                    }
                }

                #[cfg(feature = "std")]
                fn read<R: std::io::Read>(mut r: R) -> Result<Self, multihash::Error>
                where
                    Self: Sized
                {
                    let code = multihash::read_code(&mut r)?;
                    match code {
                        Code::Identity256 => Ok(Self::Identity256(multihash::read_mh(r, code)?)),
                        #[cfg(feature = "strobe")]
                        Code::Strobe256 => Ok(Self::Strobe256(multihash::read_mh(r, code)?)),
                    }
                }

                #[cfg(feature = "std")]
                fn write<W: std::io::Write>(&self, w: W) -> Result<(), multihash::Error> {
                    match self {
                        Multihash::Identity256(mh) => mh.write(w),
                        #[cfg(feature = "strobe")]
                        Multihash::Strobe256(mh) => mh.write(w),
                    }
                }
            }

            impl multihash::MultihashCode for Code {
                type Multihash = Multihash;

                fn size(&self) -> u8 {
                    use multihash::{Hasher, Unsigned};
                    match self {
                        Code::Identity256 => <multihash::Identity256 as Hasher>::Size::to_u8(),
                        #[cfg(feature = "strobe")]
                        Code::Strobe256 => <multihash::Strobe256 as Hasher>::Size::to_u8(),
                    }
                }

                fn digest(&self, input: &[u8]) -> Self::Multihash {
                    use multihash::Multihasher;
                    match self {
                        Code::Identity256 => Multihash::Identity256(multihash::Identity256::multi_digest(input)),
                        #[cfg(feature = "strobe")]
                        Code::Strobe256 => Multihash::Strobe256(multihash::Strobe256::multi_digest(input)),
                    }
                }
            }

            impl multihash::MultihasherCode<Code> for multihash::Identity256 {
                const CODE: Code = Code::Identity256;
            }

            #[cfg(feature = "strobe")]
            impl multihash::MultihasherCode<Code> for multihash::Strobe256 {
                const CODE: Code = Code::Strobe256;
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        let result = multihash(s);
        utils::assert_proc_macro(result, expected);
    }
}
