/// ! # multihash
/// !
/// ! Implementation of [multihash](https://github.com/multiformats/multihash)
/// ! in Rust.
/// Representation of a Multiaddr.
extern crate digest;
extern crate generic_array;
#[macro_use]
extern crate multihash_derive;
extern crate sha1;
extern crate sha2;

#[cfg(test)]
extern crate hex;

mod errors;
mod hashes;
mod multihash_digest;

pub use digest::Digest;
pub use errors::*;
pub use hashes::*;
pub use multihash_derive::*;
pub use multihash_digest::MultihashDigest;

// /// Decodes bytes into a multihash
// ///
// /// # Errors
// ///
// /// Returns an error if the bytes are not a valid multihash.
// ///
// /// # Examples
// ///
// /// ```
// /// use multihash::{decode, Hash, Multihash};
// ///
// /// // use the data from the `encode` example
// /// let data = vec![18, 32, 185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218,
// /// 125, 171, 250, 196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233];
// ///
// /// assert_eq!(
// ///     decode(&data).unwrap(),
// ///     Multihash {
// ///         alg: Hash::SHA2256,
// ///         digest: &data[2..]
// ///     }
// /// );
// /// ```
// ///
// pub fn decode(input: &[u8]) -> Result<Multihash, Error> {
//     if input.is_empty() {
//         return Err(Error::BadInputLength);
//     }

//     let code = input[0];

//     let alg = Hash::from_code(code)?;
//     let hash_len = alg.size() as usize;

//     // length of input should be exactly hash_len + 2
//     if input.len() != hash_len + 2 {
//         return Err(Error::BadInputLength);
//     }

//     Ok(Multihash {
//         alg: alg,
//         digest: &input[2..],
//     })
// }

// /// Represents a valid multihash, by associating the hash algorithm with the data
// #[derive(PartialEq, Eq, Clone, Copy, Debug)]
// pub struct Multihash<'a> {
//     pub alg: Hash,
//     pub digest: &'a [u8],
// }

// /// Convert bytes to a hex representation
// pub fn to_hex(bytes: &[u8]) -> String {
//     let mut hex = String::with_capacity(bytes.len() * 2);

//     for byte in bytes {
//         write!(hex, "{:02x}", byte).expect("Can't fail on writing to string");
//     }

//     hex
// }
