#![recursion_limit = "1024"]

extern crate proc_macro;
extern crate proc_macro2;
extern crate syn;
#[macro_use]
extern crate quote;
extern crate integer_encoding;

use integer_encoding::VarIntWriter;

#[proc_macro_derive(MultihashDigest, attributes(Code, Size, Digest))]
pub fn multihash_digest_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Construct a represntation of Rust code as a syntax tree
    // that we can manipulate
    let ast = syn::parse(input).unwrap();

    // Build the trait implementation
    impl_multihash_digest(&ast).into()
}

fn impl_multihash_digest(ast: &syn::DeriveInput) -> proc_macro2::TokenStream {
    match ast.data {
        syn::Data::Enum(ref data) => {
            let impls = data
                .variants
                .iter()
                .map(|variant| impl_variant(&ast.ident, variant));

            let code_matches_from_u32 = data.variants.iter().map(|variant| {
                let name = &variant.ident;
                let code = fetch_discriminant(&variant.discriminant)
                    .expect("Please provide the code as discriminant")
                    as u32;

                quote!{ #code => Some(Code::#name), }
            });

            let code_matches_into_str = data.variants.iter().map(|variant| {
                let name = &variant.ident;

                quote!{ Code::#name => stringify!(#name), }
            });

            let res = quote!{
                /// Decodes the raw value into a `Multihash`. If the input data is not a valid
                /// multihash an error is returned.
                pub fn decode(raw: &[u8]) -> Result<Multihash, Error> {
                    Multihash::from_slice(raw)
                }

                impl Into<u32> for Code {
                    fn into(self) -> u32 {
                        self as u32
                    }
                }

                impl Into<&'static str> for Code {
                    fn into(self) -> &'static str {
                        match self {
                            #(#code_matches_into_str)*
                        }
                    }
                }

                impl Code {
                    pub fn from_u32(val: u32) -> Option<Self> {
                        match val {
                            #(#code_matches_from_u32)*
                            _ => None
                        }
                    }
                //     fn new_hasher(&self) -> Box<MultihashDigest> {
                //         match *self {
                //             Code::Sha1 => {
                //                 Box::new(Sha1::new())
                //             },
                //             Code::Sha2256 => {
                //                 Box::new(Sha2256::new())
                //             },
                //             _ => unimplemented!(),
                //         }
                //     }
                }

                #(#impls)*
            };

            res
        }
        _ => panic!("Multihash can only be derived on an enum"),
    }
}

fn impl_variant(_code_name: &syn::Ident, variant: &syn::Variant) -> proc_macro2::TokenStream {
    let name = &variant.ident;
    let attrs = &variant.attrs;

    let size: usize = fetch_attr("Size", &attrs)
        .expect("Please supply a Size attribute")
        .parse()
        .expect("Size should be a number");

    if size > 255 {
        panic!("Sizes larger than 255 are not yet supported");
    }

    let code =
        fetch_discriminant(&variant.discriminant).expect("Please provide the code as discriminant");

    let mut code_varint = Vec::with_capacity(16);
    code_varint.write_varint(code).unwrap();
    let code_len = code_varint.len();
    let code_iter = code_varint
        .iter()
        .enumerate()
        .map(|(i, v)| quote!(out[#i] = #v;));

    let original_digest: syn::Path =
        syn::parse_str(&fetch_attr("Digest", &attrs).expect("Please provide a Digest"))
            .expect("invalid digest provided");

    // TODO: actually derive this from the encoded size of the size.
    let prefix_len = 1 + code_len;

    quote!{
        #[derive(Debug, Default, Clone)]
        pub struct #name(#original_digest);

        impl Reset for #name {
            fn reset(&mut self) {
                digest::Digest::reset(&mut self.0);
            }
        }

        impl Input for #name {
            fn input<B: AsRef<[u8]>>(&mut self, data: B) {
                digest::Digest::input(&mut self.0, data);
            }
        }

        impl BlockInput for #name {
            type BlockSize = <#original_digest as BlockInput>::BlockSize;
        }

        impl MultihashDigest for #name {
            fn new() -> Self {
                #name(<#original_digest as Digest>::new())
            }

            fn size() -> usize {
                #size
            }

            fn to_string() -> &'static str {
                stringify!(#name)
            }

            fn code() -> Code {
                Code::#name
            }

            fn wrap(
                raw: &[u8],
            ) -> Multihash {
                let mut out = vec![0u8; raw.len() + #prefix_len];

                #( #code_iter )*

                // TODO: varint - handle larger sizes
                out[#code_len] = Self::size() as u8;

                out[#prefix_len..].copy_from_slice(raw);

                Multihash(out.into())
            }

            fn result(self) -> Multihash {
                Self::wrap(&self.0.result())
            }

            fn result_reset(&mut self) -> Multihash {
                Self::wrap(&self.0.result_reset())
            }

            fn digest(data: &[u8]) -> Multihash {
                Self::wrap(&<#original_digest as Digest>::digest(data))
            }
        }
    }
}

/// Fetch an attribute string from the derived struct.
fn fetch_attr(name: &str, attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if let Some(meta) = attr.interpret_meta() {
            match meta {
                syn::Meta::NameValue(nv) => {
                    if nv.ident == name {
                        match nv.lit {
                            syn::Lit::Str(ref s) => return Some(s.value()),
                            _ => {
                                panic!("attribute {} should be a string", name);
                            }
                        }
                    }
                }
                _ => {
                    panic!("attribute {} should be a string", name);
                }
            }
        }
    }

    None
}

fn fetch_discriminant(disc: &Option<(syn::token::Eq, syn::Expr)>) -> Option<u64> {
    match disc {
        Some(ref raw_code) => match &raw_code.1 {
            syn::Expr::Lit(nv) => match nv.lit {
                syn::Lit::Int(ref val) => Some(val.value()),
                _ => None,
            },
            _ => None,
        },
        None => None,
    }
}
