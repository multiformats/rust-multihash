/// ! # multihash
/// !
/// ! Implementation of [multihash](https://github.com/multiformats/multihash)
/// ! in Rust.
/// Representation of a Multiaddr.

extern crate ring;

use ring::digest;

mod hashes;
pub use hashes::*;

mod errors;
pub use errors::*;

/// Encodes data into a multihash.
///
/// The returned data is raw bytes.  To make is more human-friendly, you can encode it (hex,
/// base58, base64, etc).
///
/// # Errors
///
/// Will return an error if the specified hash type is not supported.  See the docs for `Hash`
/// to see what is supported.
///
/// # Examples
///
/// ```
/// use multihash::{encode, Hash};
///
/// assert_eq!(
///     encode(Hash::SHA2256, b"hello world").unwrap(),
///     vec![18, 32, 185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196,
///     132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233]
/// );
/// ```
///
pub fn encode(wanttype: Hash, input: &[u8]) -> Result<Vec<u8>, Error> {
    let encoded = encode_digest(wanttype, input)?;
    let mut bytes = Vec::with_capacity(encoded.len() + 2);

    bytes.push(wanttype.code());
    bytes.push(encoded.len() as u8);
    bytes.extend(encoded);

    Ok(bytes)
}

fn encode_digest(wanttype: Hash, input: &[u8]) -> Result<Vec<u8>, Error> {
    let digest_type = match wanttype {
        Hash::SHA1 => &digest::SHA1,
        Hash::SHA2256 => &digest::SHA256,
        Hash::SHA2512 => &digest::SHA512,
        _ => return Err(Error::UnsupportedType),
    };

    Ok(digest::digest(digest_type, input).as_ref().to_owned())
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
/// use multihash::{decode, Hash, Multihash};
///
/// // use the data from the `encode` example
/// let data = vec![18, 32, 185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218,
/// 125, 171, 250, 196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233];
///
/// assert_eq!(
///     decode(&data).unwrap(),
///     Multihash {
///         alg: Hash::SHA2256,
///         digest: &data[2..]
///     }
/// );
/// ```
///
pub fn decode(input: &[u8]) -> Result<Multihash, Error> {
    let code = input[0];

    let alg = Hash::from_code(code)?;
    let hash_len = alg.size() as usize;

    // length of input should be exactly hash_len + 2
    if input.len() != hash_len + 2 {
        return Err(Error::BadInputLength);
    }

    Ok(Multihash {
        alg: alg,
        digest: &input[2..],
    })
}

/// Represents a valid multihash, by associating the hash algorithm with the data
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Multihash<'a> {
    pub alg: Hash,
    pub digest: &'a [u8],
}

/// Convert bytes to a hex representation
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|x| format!("{:02x}", x))
        .collect()
}
