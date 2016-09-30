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

extern crate crypto;

use crypto::digest::Digest;

use crypto::sha1::Sha1;
use crypto::sha2::{Sha256, Sha512};
use crypto::sha3::Sha3;
use crypto::blake2b::Blake2b;
use crypto::blake2s::Blake2s;

use std::io;

mod hashes;
pub use hashes::*;



/// Encodes data into a multihash.
///
/// The returned data is raw bytes.  To make is more human-friendly, you can encode it (hex,
/// base58, base64, etc).
///
/// # Errors
///
/// Will return an error if the specified hash type is not supported.  See the docs for `HashTypes`
/// to see what is supported.
///
/// # Examples
///
/// ```
/// use multihash::{encode, HashTypes};
///
/// assert_eq!(
///     encode(HashTypes::SHA2256, "hello world".as_bytes()).unwrap(),
///     vec![18, 32, 185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196,
///     132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233]
/// );
/// ```
///
pub fn encode(wanttype: HashTypes, input: &[u8]) -> io::Result<Vec<u8>> {
    let digest: Vec<u8> = match wanttype {

        HashTypes::SHA1 => {
            let mut buf : Vec<u8> = Vec::new();
            let mut hasher = Sha1::new();
            hasher.input(input);
            hasher.result(&mut buf);
            buf
        },

        HashTypes::SHA2256  => {
            let mut buf : Vec<u8> = Vec::new();
            let mut hasher = Sha256::new();
            hasher.input(input);
            hasher.result(&mut buf);
            buf
        },

        HashTypes::SHA2512  => {
            let mut buf : Vec<u8> = Vec::new();
            let mut hasher = Sha512::new();
            hasher.input(input);
            hasher.result(&mut buf);
            buf
        },

        HashTypes::SHA3512  => {
            let mut buf : Vec<u8> = Vec::new();
            let mut hasher = Sha3::sha3_512();
            hasher.input(input);
            hasher.result(&mut buf);
            buf
        },

        HashTypes::SHA3384  => {
            let mut buf : Vec<u8> = Vec::new();
            let mut hasher = Sha3::sha3_384();
            hasher.input(input);
            hasher.result(&mut buf);
            buf
        },

        HashTypes::SHA3224  => {
            let mut buf : Vec<u8> = Vec::new();
            let mut hasher = Sha3::sha3_224();
            hasher.input(input);
            hasher.result(&mut buf);
            buf
        },

        HashTypes::SHAKE128 => {
            let mut buf : Vec<u8> = Vec::new();
            let mut hasher = Sha3::shake_128();
            hasher.input(input);
            hasher.result(&mut buf);
            buf
        },

        HashTypes::SHAKE256 => {
            let mut buf : Vec<u8> = Vec::new();
            let mut hasher = Sha3::shake_256();
            hasher.input(input);
            hasher.result(&mut buf);
            buf
        },

        HashTypes::Blake2b  => {
            let mut buf : Vec<u8> = Vec::new();
            let mut hasher = Blake2b::new(64);
            hasher.input(input);
            hasher.result(&mut buf);
            buf
        },

        HashTypes::Blake2s  => {
            let mut buf : Vec<u8> = Vec::new();
            let mut hasher = Blake2s::new(32);
            hasher.input(input);
            hasher.result(&mut buf);
            buf
        },

        _ => return Err(io::Error::new(io::ErrorKind::Other, "Unsupported hash type"))
    };


    let mut bytes = Vec::with_capacity(digest.len() + 2);

    bytes.push(wanttype.code());
    bytes.push(digest.len() as u8);
    bytes.extend(digest);

    Ok(bytes)
}

/// Decodes bytes into a multihash
///
/// # Errors
///
/// Returns an error if the bytes are not a valid multihash.
///
/// # Examples
///
/// ```
/// use multihash::{decode, HashTypes, Multihash};
///
/// // use the data from the `encode` example
/// let data = vec![18, 32, 185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218,
/// 125, 171, 250, 196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233];
///
/// assert_eq!(
///     decode(&data).unwrap(),
///     Multihash {
///         alg: HashTypes::SHA2256,
///         digest: &data[2..]
///     }
/// );
/// ```
///
pub fn decode(input: &[u8]) -> io::Result<Multihash> {

    let code = input[0];

    match HashTypes::from_code(code) {
        Some(alg) => {
            let hash_len = alg.size() as usize;
            // length of input should be exactly hash_len + 2
            if input.len() != hash_len + 2 {
                Err(io::Error::new(io::ErrorKind::Other, format!("Bad input length.  Expected {}, found {}", hash_len + 2, input.len())))
            } else {
                Ok(Multihash {
                    alg: alg,
                    digest: &input[2..],
                })
            }
        },
        None => {
            Err(io::Error::new(io::ErrorKind::Other, format!("Unkown code {:?}", code)))
        }
    }
}

/// Represents a valid multihash, by associating the hash algorithm with the data
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Multihash<'a> {
    pub alg: HashTypes,
    pub digest: &'a [u8]
}

/// Convert bytes to a hex representation
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| {
        format!("{:02x}", x)
    }).collect()
}
