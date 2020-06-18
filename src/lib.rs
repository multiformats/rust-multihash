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
pub use crate::hasher::{Digest, Hasher, Size};
#[cfg(feature = "std")]
pub use crate::multihash::{read_code, read_digest, write_mh};
pub use crate::multihash::{MultihashCode, MultihashDigest};
pub use generic_array::typenum;
#[cfg(feature = "derive")]
pub use multihash_proc_macro::Multihash;

#[cfg(feature = "blake2b")]
pub use crate::hasher_impl::blake2b::{Blake2b256, Blake2b512, Blake2bDigest, Blake2bHasher};
#[cfg(feature = "blake2s")]
pub use crate::hasher_impl::blake2s::{Blake2s128, Blake2s256, Blake2sDigest, Blake2sHasher};
pub use crate::hasher_impl::identity::{Identity256, IdentityDigest, IdentityHasher};
#[cfg(feature = "sha1")]
pub use crate::hasher_impl::sha1::{Sha1, Sha1Digest};
#[cfg(feature = "sha2")]
pub use crate::hasher_impl::sha2::{Sha2Digest, Sha2_256, Sha2_512};
#[cfg(feature = "sha3")]
pub use crate::hasher_impl::sha3::{Keccak224, Keccak256, Keccak384, Keccak512, KeccakDigest};
#[cfg(feature = "sha3")]
pub use crate::hasher_impl::sha3::{Sha3Digest, Sha3_224, Sha3_256, Sha3_384, Sha3_512};
#[cfg(feature = "strobe")]
pub use crate::hasher_impl::strobe::{Strobe256, Strobe512, StrobeDigest, StrobeHasher};
