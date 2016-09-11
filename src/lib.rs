// For explanation of lint checks, run `rustc -W help`
// This is adapted from
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, //missing_docs,
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
extern crate rustc_serialize;

use rustc_serialize::hex::FromHex;

use sodiumoxide::crypto::hash::{sha256, sha512};
use std::io;

pub use self::hashes::*;
pub mod hashes;


/// Encode a string into a multihash
///
/// # Examples
///
/// Simple construction
///
/// ```
/// use multihash::{encode, HashTypes};
///
/// assert_eq!(
///     encode(HashTypes::SHA2256, "hello world").unwrap(),
///     "1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
/// );
/// ```
///
pub fn encode(wanttype: HashTypes, input: &str) -> io::Result<String> {
    let digest = match wanttype {
        HashTypes::SHA2256 => dig_to_vec(&(sha256::hash(input.as_bytes())[..])),
        HashTypes::SHA2512 => dig_to_vec(&(sha512::hash(input.as_bytes())[..])),
        _ => None,
    };

    match digest {
        Some(digest) => {
            let mut bytes = Vec::new();

            bytes.push(wanttype.code());
            bytes.push(digest.len() as u8);
            bytes.extend(digest);

            Ok(to_hex(bytes))
        },
        None => Err(io::Error::new(io::ErrorKind::Other, "Unsupported hash type"))
    }
}

/// Encode a string into a multihash
///
/// # Examples
///
/// Simple construction
///
/// ```
/// use multihash::{decode, HashTypes, Multihash};
///
/// assert_eq!(
///     decode("1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").unwrap(),
///     Multihash {
///         alg: HashTypes::SHA2256,
///         digest: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
///     }
/// );
/// ```
///
pub fn decode(input: &str) -> io::Result<Multihash> {
    if input.len() > 129 {
        return Err(io::Error::new(io::ErrorKind::Other, "Too long"));
    }

    if input.len() < 3 {
        return Err(io::Error::new(io::ErrorKind::Other, "Too short"));
    }

    let hex_input = input.from_hex();

    if hex_input.is_err() {
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to parse hex string"));
    }

    let code = hex_input.unwrap()[0];

    match HashTypes::from_code(code) {
        Some(alg) => {
            Ok(Multihash {
                alg: alg,
                digest: &input[4..],
            })
        },
        None => {
            Err(io::Error::new(io::ErrorKind::Other, format!("Unkown code {:?}", code)))
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Multihash<'a> {
    pub alg: HashTypes,
    pub digest: &'a str,
}

/// Convert bytes to a hex representation
fn to_hex(bytes: Vec<u8>) -> String {
    bytes.iter().rev().map(|x| {
        format!("{:02x}", x)
    }).rev().collect()
}


fn dig_to_vec (input: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend(&input[..]);
    Some(bytes)
}
