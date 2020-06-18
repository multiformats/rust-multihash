//! Multihash implementation.
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(any(test, feature = "test"))]
mod arb;
#[cfg(feature = "derive")]
mod code;
mod error;
mod hasher;
mod hasher_impl;
mod multihash;

#[cfg(feature = "derive")]
pub use crate::code::{Code, Multihash};
pub use crate::error::{Error, Result};
#[cfg(feature = "std")]
pub use crate::hasher::WriteHasher;
pub use crate::hasher::{Digest, Hasher};
#[cfg(feature = "std")]
pub use crate::multihash::{read_code, read_mh, write_mh};
pub use crate::multihash::{
    MultihashArray, MultihashCode, MultihashDigest, Multihasher, MultihasherCode,
};
pub use generic_array::typenum;
#[cfg(feature = "derive")]
pub use generic_array::typenum::marker_traits::Unsigned;
#[cfg(feature = "derive")]
pub use multihash_proc_macro::Multihash;

#[cfg(feature = "blake2b")]
pub use crate::hasher_impl::blake2b::{Blake2b256, Blake2b512, Blake2bHasher};
#[cfg(feature = "blake2s")]
pub use crate::hasher_impl::blake2s::{Blake2s128, Blake2s256, Blake2sHasher};
pub use crate::hasher_impl::identity::{Identity256, IdentityHasher};
#[cfg(feature = "sha1")]
pub use crate::hasher_impl::sha1::Sha1;
#[cfg(feature = "sha2")]
pub use crate::hasher_impl::sha2::{Sha2_256, Sha2_512};
#[cfg(feature = "sha3")]
pub use crate::hasher_impl::sha3::{Keccak224, Keccak256, Keccak384, Keccak512};
#[cfg(feature = "sha3")]
pub use crate::hasher_impl::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
#[cfg(feature = "strobe")]
pub use crate::hasher_impl::strobe::{Strobe256, Strobe512, StrobeHasher};
