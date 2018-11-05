#![recursion_limit = "1024"]

extern crate proc_macro;
extern crate proc_macro2;
extern crate syn;
#[macro_use]
extern crate quote;

#[proc_macro_derive(MultihashDigest, attributes(Code, Size, digest))]
pub fn multihash_digest_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Construct a represntation of Rust code as a syntax tree
    // that we can manipulate
    let ast = syn::parse(input).unwrap();

    // Build the trait implementation
    impl_multihash_digest(&ast)
}

fn impl_multihash_digest(ast: &syn::DeriveInput) -> proc_macro::TokenStream {
    let name = &ast.ident;

    let size: usize = fetch_attr("Size", &ast.attrs)
        .expect("Please supply a Size attribute")
        .parse()
        .expect("Size should be a number");

    let raw_code = fetch_attr("Code", &ast.attrs).expect("Please supply a Code attribute");
    let code: u8 = u8::from_str_radix(raw_code.trim_left_matches("0x"), 16)
        .expect("Code should be a hex number");

    let original_digest = match &ast.data {
        syn::Data::Struct(ds) => {
            fetch_attr_inner("digest", &ds.fields).expect("Please mark the original digest")
        }
        _ => {
            panic!("can only derive MultihashDigest on a struct");
        }
    };

    // TODO: actually derive this from the size of the code and the size.
    let prefix_size = 2;
    let output_size: syn::Path =
        syn::parse_str(&format!("generic_array::typenum::U{}", size + prefix_size)).unwrap();

    let gen = quote!{
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

        impl FixedOutput for #name {
            type OutputSize = #output_size;

            fn fixed_result(self) -> generic_array::GenericArray<u8, Self::OutputSize> {
                Self::wrap(&self.0.fixed_result())
            }
        }

        impl MultihashDigest for #name {
            type RawSize = <#original_digest as FixedOutput>::OutputSize;

            fn size() -> usize {
                Self::RawSize::to_usize()
            }

            fn name() -> &'static str {
                stringify!(#name)
            }

            fn code() -> u8 {
                #code
            }

            fn wrap(
                raw: &generic_array::GenericArray<u8, Self::RawSize>,
            ) -> generic_array::GenericArray<u8, Self::OutputSize> {
                let mut out = generic_array::GenericArray::default();
                // TODO: varint - handle larger codes
                out[0] = Self::code() as u8;
                // TODO: varint - handle larger sizes
                out[1] = Self::size() as u8;

                assert_eq!(raw.len(), out.len() - 2, "raw value has invalid size: expected {}, got {}", out.len() - 2, raw.len());
                out[2..].copy_from_slice(&raw[..]);

                out

            }
        }
    };

    gen.into()
}

/// Fetch an attribute string from the derived struct.
fn fetch_attr(name: &str, attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if let Some(meta) = attr.interpret_meta() {
            match meta {
                syn::Meta::NameValue(nv) => {
                    if nv.ident.to_string() == name {
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

/// Fetch an inner attribute string from the derived struct.
fn fetch_attr_inner<'a>(name: &str, fields: &'a syn::Fields) -> Option<&'a syn::Type> {
    for field in fields {
        for attr in &field.attrs {
            if let Some(meta) = attr.interpret_meta() {
                match meta {
                    syn::Meta::Word(nv) => {
                        if nv.to_string() == name {
                            return Some(&field.ty);
                        }
                    }
                    _ => {
                        panic!("attribute {} should be a word", name);
                    }
                }
            }
        }
    }

    None
}
