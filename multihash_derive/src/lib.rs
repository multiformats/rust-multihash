#![recursion_limit = "1024"]

extern crate proc_macro;
extern crate proc_macro2;
extern crate syn;
#[macro_use]
extern crate quote;

#[proc_macro_derive(MultihashDigest, attributes(Code, Size, Name))]
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

    let print_name = fetch_attr("Name", &ast.attrs).expect("Please supply a Name attribute");

    let block_size: syn::Path =
        syn::parse_str(&format!("generic_array::typenum::U{}", size)).unwrap();

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
            type BlockSize = #block_size;
        }

        impl FixedOutput for #name {
            type OutputSize = #output_size;

            fn fixed_result(self) -> generic_array::GenericArray<u8, Self::OutputSize> {
                let raw = self.0.fixed_result();
                let mut out = generic_array::GenericArray::default();
                // TODO: varint - handle larger codes
                out[0] = Self::code() as u8;
                // TODO: varint - handle larger sizes
                out[1] = Self::size() as u8;

                out[2..].copy_from_slice(&raw[..]);

                out
            }
        }

        impl MultihashDigest for #name {
            fn size() -> usize {
                #size
            }
            fn name() -> &'static str {
                #print_name
            }

            fn code() -> u8 {
                #code
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
