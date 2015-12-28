// For explanation of lint checks, run `rustc -W help`
// This is adapted from
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, //missing_docs,
non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, unused_extern_crates, unused_import_braces,
unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
missing_debug_implementations)]

///! # multihash
///!
///! Implementation of [multihash](https://github.com/jbenet/multihash)
///! in Rust.
/// Representation of a Multiaddr.

extern crate sodiumoxide;
extern crate rust_base58;

use sodiumoxide::crypto::hash::{sha256, sha512};
use std::io;
use rust_base58::ToBase58;

pub use self::hashes::*;
pub mod hashes;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Multihash {
    bytes: Vec<u8>
}

impl Multihash {
    /// Create a new multihash
    ///
    /// # Examples
    ///
    /// Simple construction
    ///
    /// ```
    /// use multihash::{Multihash, HashTypes};
    ///
    /// assert_eq!(
    ///     Multihash::new(HashTypes::SHA2256, "hello world").unwrap().to_str(),
    ///     "1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    /// );
    /// ```
    ///
    pub fn new(wanttype: HashTypes, input: &str) -> io::Result<Multihash> {
        let digest = match wanttype {
            HashTypes::SHA2256 => dig_to_vec(&(sha256::hash(input.as_bytes())[..])),
            HashTypes::SHA2512 => dig_to_vec(&(sha512::hash(input.as_bytes())[..])),
            _ => None,
        };

        match digest {
            Some(digest) => {
                let mut bytes = Vec::new();

                bytes.push(wanttype.to_u8());
                bytes.push(digest.len() as u8);
                bytes.extend(digest);

                Ok(Multihash {
                    bytes: bytes,
                })
            },
            None => Err(io::Error::new(io::ErrorKind::Other, "Unsupported hash type"))
        }
    }

    /// Return a copy to disallow changing the bytes directly
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_owned()
    }

    /// Convert bytes to a hex representation
    pub fn to_str(&self) -> String {
        self.bytes.iter().rev().map(|x| {
            format!("{:02x}", x)
        }).rev().collect()
    }

    pub fn to_base58(&self) -> String {
        let bytes = self.to_bytes();
        (&bytes[..]).to_base58()
    }
}


fn dig_to_vec (input: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend(&input[..]);
    Some(bytes)
}
