//! This proc macro derives a custom Multihash code table from a list of hashers. It also
//! generates a public type called `Multihash` which corresponds to the specified `alloc_size`.
//!
//! The digests are stack allocated with a fixed size. That size needs to be big enough to hold any
//! of the specified hash digests. This cannot be determined reliably on compile-time, hence it
//! needs to set manually via the `alloc_size` attribute. Also you might want to set it to bigger
//! sizes then necessarily needed for backwards/forward compatibility.
//!
//! If you set `#mh(alloc_size = …)` to a too low value, you will get compiler errors. Please note
//! the the sizes are checked only on a syntactic level and *not* on the type level. This means
//! that digest need to have a size const generic, which is a valid `usize`, for example `32` or
//! `64`.
//!
//! You can disable those compiler errors with setting the `no_alloc_size_errors` attribute. This
//! can be useful if you e.g. have specified type aliases for your hash digests and you are sure
//! you use the correct value for `alloc_size`.
//!
//! # Example
//!
//! ```
//! use multihash::derive::Multihash;
//! use multihash::MultihashDigest;
//!
//! #[derive(Clone, Copy, Debug, Eq, Multihash, PartialEq)]
//! #[mh(alloc_size = 64)]
//! pub enum Code {
//!     #[mh(code = 0x01, hasher = multihash::Sha2_256)]
//!     Foo,
//!     #[mh(code = 0x02, hasher = multihash::Sha2_512)]
//!     Bar,
//! }
//!
//! let hash = Code::Foo.digest(b"hello world!");
//! println!("{:02x?}", hash);
//! ```
extern crate proc_macro;

mod multihash;
mod utils;

use proc_macro::TokenStream;
use proc_macro_error::proc_macro_error;
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

#[proc_macro_derive(MultihashDigest, attributes(mh))]
#[allow(non_snake_case)]
#[proc_macro_error]
pub fn MultihashDigest(i: TokenStream) -> TokenStream {
    #[allow(deprecated)]
    Multihash(i)
}
