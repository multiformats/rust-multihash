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
extern crate blake2;
extern crate integer_encoding;
extern crate sha1;
extern crate sha2;
extern crate sha3;

#[cfg(test)]
extern crate hex;

mod digests;
mod errors;
mod multihash_digest;

pub use digests::*;
pub use errors::Error;
pub use multihash_derive::*;
pub use multihash_digest::MultihashDigest;
