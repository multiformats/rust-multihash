use crate::utils;
use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
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
    Code(utils::Attr<kw::code, syn::Path>),
    Hasher(utils::Attr<kw::hasher, syn::Path>),
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
    code: syn::Path,
    hasher: syn::Path,
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
        let hasher = &self.hasher;
        quote!(#mh_enum::#ident(_mh) => #hasher::size())
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

    fn digest_read(&self, params: &Params) -> TokenStream {
        let code = &self.code;
        let ident = &self.ident;
        let mh = &params.mh_crate;
        quote!(#code => Ok(Self::#ident(#mh::read_digest(r)?)))
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

pub fn multihash(s: Structure) -> TokenStream {
    let mh_crate = utils::use_crate("multihash");
    let mh_enum = &s.ast().ident;
    let hashes: Vec<_> = s.variants().iter().map(Hash::from).collect();
    let params = Params {
        mh_crate: mh_crate.clone(),
        mh_enum: mh_enum.clone(),
    };

    let digest_code = hashes.iter().map(|h| h.digest_code(&params));
    let digest_size = hashes.iter().map(|h| h.digest_size(&params));
    let digest_digest = hashes.iter().map(|h| h.digest_digest(&params));
    let digest_new = hashes.iter().map(|h| h.digest_new());
    let digest_read = hashes.iter().map(|h| h.digest_read(&params));
    let from_digest = hashes.iter().map(|h| h.from_digest(&params));

    quote! {
        impl From<#mh_enum> for u64 {
           fn from(mh: #mh_enum) -> Self {
               mh.code()
           }
        }

        impl #mh_crate::MultihashDigest for #mh_enum {
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

            #[cfg(feature = "std")]
            fn read<R: std::io::Read>(mut r: R) -> Result<Self, #mh_crate::Error>
            where
                Self: Sized
            {
                let code = #mh_crate::read_code(&mut r)?;
                match code {
                    #(#digest_read,)*
                    _ => Err(#mh_crate::Error::UnsupportedCode(code)),
                }
            }
        }

        impl #mh_crate::MultihashCreate for #mh_enum {
           fn new(code: u64, input: &[u8]) -> Result<Self, #mh_crate::Error> {
              match code {
                  #(#digest_new,)*
                  _ => Err(#mh_crate::Error::UnsupportedCode(code)),
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
           pub enum Multihash {
               #[mh(code = multihash::IDENTITY, hasher = multihash::Identity256)]
               Identity256(multihash::IdentityDigest<U32>),
               /// Multihash array for hash function.
               #[mh(code = multihash::STROBE_256, hasher = multihash::Strobe256)]
               Strobe256(multihash::StrobeDigest<U32>),
            }
        };
        let expected = quote! {
            impl From<Multihash> for u64 {
                fn from(mh: Multihash) -> Self {
                    mh.code()
                }
            }
            impl multihash::MultihashDigest for Multihash {
                fn code(&self) -> u64 {
                    match self {
                        Multihash::Identity256(_mh) => multihash::IDENTITY,
                        Multihash::Strobe256(_mh) => multihash::STROBE_256,
                    }
                }
                fn size(&self) -> u8 {
                    match self {
                        Multihash::Identity256(_mh) => multihash::Identity256::size(),
                        Multihash::Strobe256(_mh) => multihash::Strobe256::size(),
                    }
                }
                fn digest(&self) -> &[u8] {
                    match self {
                        Multihash::Identity256(mh) => mh.as_ref(),
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
                        multihash::IDENTITY => Ok(Self::Identity256(multihash::read_digest(r)?)),
                        multihash::STROBE_256 => Ok(Self::Strobe256(multihash::read_digest(r)?)),
                        _ => Err(multihash::Error::UnsupportedCode(code)),
                    }
                }
            }
            impl multihash::MultihashCreate for Multihash {
                fn new(code: u64, input: &[u8]) -> Result<Self, multihash::Error> {
                    match code {
                        multihash::IDENTITY => Ok(Self::Identity256(multihash::Identity256::digest(input))),
                        multihash::STROBE_256 => Ok(Self::Strobe256(multihash::Strobe256::digest(input))),
                        _ => Err(multihash::Error::UnsupportedCode(code)),
                    }
                }
            }
            impl From<multihash::IdentityDigest<U32> > for Multihash {
                fn from(digest: multihash::IdentityDigest<U32>) -> Self {
                    Self::Identity256(digest)
                }
            }
            impl From<multihash::StrobeDigest<U32> > for Multihash {
                fn from(digest: multihash::StrobeDigest<U32>) -> Self {
                    Self::Strobe256(digest)
                }
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        let result = multihash(s);
        utils::assert_proc_macro(result, expected);
    }
}
