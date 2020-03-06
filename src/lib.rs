//! # Multihash
//!
//! Implementation of [multihash](https://github.com/multiformats/multihash) in Rust.
//!
//! A `Multihash` is a structure that contains a hashing algorithm, plus some hashed data.
//! A `MultihashRef` is the same as a `Multihash`, except that it doesn't own its data.

#![deny(missing_docs)]

mod digests;
mod errors;
mod hashes;
mod storage;

#[cfg(any(test, feature = "test"))]
mod arb;

pub use digests::{wrap, Multihash, MultihashDigest, MultihashGeneric, MultihashRef};
pub use errors::{DecodeError, DecodeOwnedError, EncodeError};
pub use hashes::*;
