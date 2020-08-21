//! # Multihash
//!
//! Implementation of [multihash](https://github.com/multiformats/multihash) in Rust.
//!
//! A `Multihash` is a structure that contains a hashing algorithm, plus some hashed data.
//! A `MultihashRef` is the same as a `Multihash`, except that it doesn't own its data.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

extern crate alloc;

mod digests;
mod errors;
mod hashes;
mod storage;

#[cfg(any(test, feature = "test"))]
mod arb;

pub use digests::{
    wrap, BoxedMultihashDigest, Multihash, MultihashDigest, MultihashGeneric, MultihashRef,
    MultihashRefGeneric, Multihasher,
};
pub use errors::{DecodeError, DecodeOwnedError, EncodeError};
pub use hashes::*;
