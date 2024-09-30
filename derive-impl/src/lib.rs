//! This is an internal crate that implements the actual `MultihashDigest` derive.
//!
//! The `multihash-derive` crate acts as a facade and defines additional symbols that our derive depends on.
//! For example, the actual trait that we are deriving `MultihashDigest`, as well as the `Hasher` trait and
//! the `UnsupportedCode` error type.

mod multihash;
mod utils;

use proc_macro::TokenStream;
use proc_macro_error2::proc_macro_error;
use synstructure::macros::{parse, DeriveInput};
use synstructure::{MacroResult, Structure};

#[proc_macro_derive(Multihash, attributes(mh))]
#[allow(non_snake_case)]
#[proc_macro_error]
#[deprecated(since = "0.8.1", note = "Use `MultihashDigest` derive instead.")]
pub fn Multihash(i: TokenStream) -> TokenStream {
    match parse::<DeriveInput>(i) {
        Ok(p) => match Structure::try_new(&p) {
            Ok(s) => multihash::multihash(s).into_stream(),
            Err(e) => e.to_compile_error().into(),
        },
        Err(e) => e.to_compile_error().into(),
    }
}

/// Custom derive for the `MultihashDigest` trait.
#[proc_macro_derive(MultihashDigest, attributes(mh))]
#[allow(non_snake_case)]
#[proc_macro_error]
pub fn MultihashDigest(i: TokenStream) -> TokenStream {
    #[allow(deprecated)]
    Multihash(i)
}
