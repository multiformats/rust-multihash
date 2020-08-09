//! This proc macro derives a [`MultihashDigest`] implementation from a list of hashers.
//!
//! # Example
//!
//! ```compile_fail
//! use multihash::derive::Multihash;
//! use multihash::{Hasher, MultihashDigest};
//!
//! const FOO: u64 = 0x01;
//! const BAR: u64 = 0x02;
//!
//! #[derive(Clone, Debug, Eq, Multihash, PartialEq)]
//! pub enum Multihash {
//!     #[mh(code = FOO, hasher = multihash::Sha2_256)]
//!     Foo(multihash::Sha2Digest<multihash::U32>),
//!     #[mh(code = BAR, hasher = multihash::Sha2_512)]
//!     Bar(multihash::Sha2Digest<multihash::U64>),
//! }
//! ```
//!
//! [`MultihashDigest`]: ../multihash/trait.MultihashDigest.html
extern crate proc_macro;

mod multihash;
mod utils;

use proc_macro::TokenStream;
use proc_macro_error::proc_macro_error;
use synstructure::{decl_derive, Structure};

decl_derive!([Multihash, attributes(mh)] => #[proc_macro_error] multihash);
fn multihash(s: Structure) -> TokenStream {
    multihash::multihash(s).into()
}
