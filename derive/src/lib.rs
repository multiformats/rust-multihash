//! A procedural macro for custom Multihash code tables.
//!
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
//! use multihash_derive::{Hasher, MultihashDigest};
//!
//! struct FooHasher;
//!
//! impl Hasher for FooHasher {
//!     // Implement hasher ...
//! #    fn update(&mut self, input: &[u8]) {
//! #
//! #    }
//! #
//! #    fn finalize(&mut self) -> &[u8] {
//! #        &[]
//! #    }
//! #
//! #    fn reset(&mut self) {
//! #
//! #    }
//! }
//!
//! #[derive(Clone, Copy, Debug, Eq, MultihashDigest, PartialEq)]
//! #[mh(alloc_size = 64)]
//! pub enum Code {
//!     #[mh(code = 0x01, hasher = FooHasher)]
//!     Foo
//! }
//!
//! let hash = Code::Foo.digest(b"hello world!");
//!
//! println!("{:02x?}", hash);
//! ```

mod hasher;

use std::convert::TryFrom;
use std::fmt;

pub use hasher::Hasher;
#[doc(inline)]
pub use multihash_derive_impl::MultihashDigest;

pub use multihash::*;

/// The given code is not supported by this codetable.
#[derive(Debug)]
pub struct UnsupportedCode(pub u64);

impl fmt::Display for UnsupportedCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the code {} is not supported by this codetable", self.0)
    }
}

impl std::error::Error for UnsupportedCode {}

/// Trait that implements hashing.
///
/// Typically, you won't implement this yourself but use the [`MultihashDigest`](multihash_derive_impl::MultihashDigest) custom-derive.
pub trait MultihashDigest<const S: usize>:
    TryFrom<u64, Error = UnsupportedCode>
    + Into<u64>
    + Send
    + Sync
    + Unpin
    + Copy
    + Eq
    + fmt::Debug
    + 'static
{
    /// Calculate the hash of some input data.
    ///
    /// # Example
    ///
    /// ```
    /// // `Code` implements `MultihashDigest`
    /// use multihash::{Code, MultihashDigest};
    ///
    /// let hash = Code::Sha3_256.digest(b"Hello world!");
    /// println!("{:02x?}", hash);
    /// ```
    fn digest(&self, input: &[u8]) -> Multihash<S>;

    /// Create a multihash from an existing multihash digest.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Code, Hasher, MultihashDigest, Sha3_256};
    ///
    /// let mut hasher = Sha3_256::default();
    /// hasher.update(b"Hello world!");
    /// let hash = Code::Sha3_256.wrap(&hasher.finalize()).unwrap();
    /// println!("{:02x?}", hash);
    /// ```
    fn wrap(&self, digest: &[u8]) -> std::result::Result<Multihash<S>, multihash::Error>;
}
