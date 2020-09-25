//! This proc macro derives a custom Multihash code table from a list of hashers.
//!
//! The digests are stack allocated with a fixed size. That size needs to be big enough to hold any
//! of the specified hash digests. This cannot be determined automatically on compile-time, hence
//! it needs to set manually via the `max_size` attribute.
//!
//! If you set `#mh(max_size = …)` to a too low value, e.g. to `U32` in the example below, your
//! hasher will panic when it tried to generate the `Sha2_512` hash. If you set it to a value
//! larger than strictly needed, e.g. to `U128` in the example blow, it will use more memory, but
//! it won't have any consequences on the correctness.
//!
//! # Example
//!
//! ```
//! use tiny_multihash::derive::Multihash;
//! use tiny_multihash::{U32, U64, MultihashCode};
//!
//! #[derive(Clone, Debug, Eq, Multihash, PartialEq)]
//! #[mh(max_size = U64)]
//! pub enum Code {
//!     #[mh(code = 0x01, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
//!     Foo,
//!     #[mh(code = 0x02, hasher = tiny_multihash::Sha2_512, digest = tiny_multihash::Sha2Digest<U64>)]
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
use synstructure::{decl_derive, Structure};

decl_derive!([Multihash, attributes(mh)] => #[proc_macro_error] multihash);
fn multihash(s: Structure) -> TokenStream {
    multihash::multihash(s).into()
}
