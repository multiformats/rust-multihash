/// ! # multihash
/// !
/// ! Implementation of [multihash](https://github.com/multiformats/multihash)
/// ! in Rust.
/// Representation of a Multiaddr.
pub extern crate digest;

#[macro_use]
extern crate multihash_derive;
#[macro_use]
extern crate failure;

mod code;
mod digests;
mod errors;
mod multihash_digest;

pub use crate::code::*;
pub use crate::digests::*;
pub use crate::errors::Error;
pub use crate::multihash_digest::MultihashDigest;
pub use multihash_derive::*;
