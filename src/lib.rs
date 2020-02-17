//! # Multihash
//!
//! Implementation of [multihash](https://github.com/multiformats/multihash) in Rust.
//!
//! A `Multihash` is a structure that contains a hashing algorithm, plus some hashed data.
//! A `MultihashRef` is the same as a `Multihash`, except that it doesn't own its data.
//!

mod errors;
mod hashes;
mod storage;

use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash;

use blake2b_simd::{blake2b, Params as Blake2bVariable};
use blake2s_simd::{blake2s, Params as Blake2sVariable};
use sha2::Digest;
use tiny_keccak::Keccak;
use unsigned_varint::{decode, encode};

pub use errors::{DecodeError, DecodeOwnedError, EncodeError};
pub use hashes::Hash;
use std::fmt;
use storage::Storage;

// Helper macro for encoding input into output using sha1, sha2, tiny_keccak, or blake2
macro_rules! encode {
    (sha1, Sha1, $input:expr, $output:expr) => {{
        let mut hasher = sha1::Sha1::new();
        hasher.update($input);
        $output.copy_from_slice(&hasher.digest().bytes());
    }};
    (sha2, $algorithm:ident, $input:expr, $output:expr) => {{
        let mut hasher = sha2::$algorithm::default();
        hasher.input($input);
        $output.copy_from_slice(hasher.result().as_ref());
    }};
    (tiny, $constructor:ident, $input:expr, $output:expr) => {{
        let mut kec = Keccak::$constructor();
        kec.update($input);
        kec.finalize($output);
    }};
    (blake2, $algorithm:ident, $input:expr, $output:expr) => {{
        let hash = $algorithm($input);
        $output.copy_from_slice(hash.as_ref());
    }};
    (blake2_256, $constructor:ident, $input:expr, $output:expr) => {{
        let hash = $constructor::new()
            .hash_length(32)
            .to_state()
            .update($input)
            .finalize();
        $output.copy_from_slice(hash.as_ref());
    }};
    (blake2_128, $constructor:ident, $input:expr, $output:expr) => {{
        let hash = $constructor::new()
            .hash_length(16)
            .to_state()
            .update($input)
            .finalize();
        $output.copy_from_slice(hash.as_ref());
    }};
}

// And another one to keep the matching DRY
macro_rules! match_encoder {
    ($hash:ident for ($input:expr, $output:expr) {
        $( $hashtype:ident => $lib:ident :: $method:ident, )*
    }) => ({
        match $hash {
            $(
                Hash::$hashtype => encode!($lib, $method, $input, $output),
            )*

            _ => return Err(EncodeError::UnsupportedType)
        }
    })
}

/// Encodes data into a multihash.
///
/// # Errors
///
/// Will return an error if the specified hash type is not supported. See the docs for `Hash`
/// to see what is supported.
///
/// # Examples
///
/// ```
/// use multihash::{encode, Hash};
///
/// assert_eq!(
///     encode(Hash::SHA2256, b"hello world").unwrap().to_vec(),
///     vec![18, 32, 185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196,
///     132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233]
/// );
/// ```
///
pub fn encode(hash: Hash, input: &[u8]) -> Result<Multihash, EncodeError> {
    // Custom length encoding for the identity multihash
    if let Hash::Identity = hash {
        if u64::from(std::u32::MAX) < as_u64(input.len()) {
            return Err(EncodeError::UnsupportedInputLength);
        }
        let mut buf = encode::u16_buffer();
        let code = encode::u16(hash.code(), &mut buf);
        let mut len_buf = encode::u32_buffer();
        let size = encode::u32(input.len() as u32, &mut len_buf);
        Ok(Multihash {
            storage: Storage::from_slices(&[&code, &size, &input]),
        })
    } else {
        let (offset, mut output) = encode_hash(hash);
        match_encoder!(hash for (input, &mut output[offset ..]) {
            SHA1 => sha1::Sha1,
            SHA2256 => sha2::Sha256,
            SHA2512 => sha2::Sha512,
            SHA3224 => tiny::new_sha3_224,
            SHA3256 => tiny::new_sha3_256,
            SHA3384 => tiny::new_sha3_384,
            SHA3512 => tiny::new_sha3_512,
            Keccak224 => tiny::new_keccak224,
            Keccak256 => tiny::new_keccak256,
            Keccak384 => tiny::new_keccak384,
            Keccak512 => tiny::new_keccak512,
            Blake2b512 => blake2::blake2b,
            Blake2b256 => blake2_256::Blake2bVariable,
            Blake2s256 => blake2::blake2s,
            Blake2s128 => blake2_128::Blake2sVariable,
        });

        Ok(Multihash {
            storage: Storage::from_slice(&output),
        })
    }
}

// Encode the given [`Hash`] value and ensure the returned [`Vec<u8>`]
// has enough capacity to hold the actual digest.
fn encode_hash(hash: Hash) -> (usize, Vec<u8>) {
    let mut buf = encode::u16_buffer();
    let code = encode::u16(hash.code(), &mut buf);

    let len = code.len() + 1 + usize::from(hash.size());

    let mut output = Vec::with_capacity(len);
    output.extend_from_slice(code);
    output.push(hash.size());
    output.resize(len, 0);

    (code.len() + 1, output)
}

/// Represents a valid multihash.
#[derive(Clone)]
pub struct Multihash {
    storage: Storage,
}

impl Debug for Multihash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Multihash").field(&self.as_bytes()).finish()
    }
}

impl PartialEq for Multihash {
    fn eq(&self, other: &Self) -> bool {
        self.storage.bytes() == other.storage.bytes()
    }
}

impl Eq for Multihash {}

impl hash::Hash for Multihash {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.storage.bytes().hash(state);
    }
}

impl Multihash {
    /// Verifies whether `bytes` contains a valid multihash, and if so returns a `Multihash`.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Multihash, DecodeOwnedError> {
        if let Err(err) = MultihashRef::from_slice(&bytes) {
            return Err(DecodeOwnedError {
                error: err,
                data: bytes,
            });
        }
        Ok(Multihash {
            storage: Storage::from_slice(&bytes),
        })
    }

    /// Returns the bytes representation of the multihash.
    pub fn into_bytes(self) -> Vec<u8> {
        self.to_vec()
    }

    /// Returns the bytes representation of the multihash.
    pub fn to_vec(&self) -> Vec<u8> {
        Vec::from(self.as_bytes())
    }

    /// Returns the bytes representation of this multihash.
    pub fn as_bytes(&self) -> &[u8] {
        self.storage.bytes()
    }

    /// Builds a `MultihashRef` corresponding to this `Multihash`.
    pub fn as_ref(&self) -> MultihashRef {
        MultihashRef {
            bytes: self.as_bytes(),
        }
    }

    /// Returns which hashing algorithm is used in this multihash.
    pub fn algorithm(&self) -> Hash {
        self.as_ref().algorithm()
    }

    /// Returns the hashed data.
    pub fn digest(&self) -> &[u8] {
        self.as_ref().digest()
    }
}

impl AsRef<[u8]> for Multihash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> PartialEq<MultihashRef<'a>> for Multihash {
    fn eq(&self, other: &MultihashRef<'a>) -> bool {
        &*self.as_bytes() == other.as_bytes()
    }
}

impl TryFrom<Vec<u8>> for Multihash {
    type Error = DecodeOwnedError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Multihash::from_bytes(value)
    }
}

/// Represents a valid multihash.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct MultihashRef<'a> {
    bytes: &'a [u8],
}

impl<'a> MultihashRef<'a> {
    /// Creates a `MultihashRef` from the given `input`.
    pub fn from_slice(input: &'a [u8]) -> Result<Self, DecodeError> {
        if input.is_empty() {
            return Err(DecodeError::BadInputLength);
        }

        // Ensure `Hash::code` returns a `u16` so that our `decode::u16` here is correct.
        std::convert::identity::<fn(Hash) -> u16>(Hash::code);
        let (code, bytes) = decode::u16(&input).map_err(|_| DecodeError::BadInputLength)?;

        let alg = Hash::from_code(code).ok_or(DecodeError::UnknownCode)?;

        // handle the identity case
        if alg == Hash::Identity {
            let (hash_len, bytes) = decode::u32(&bytes).map_err(|_| DecodeError::BadInputLength)?;
            if as_u64(bytes.len()) != u64::from(hash_len) {
                return Err(DecodeError::BadInputLength);
            }
            return Ok(MultihashRef { bytes: input });
        }

        let hash_len = usize::from(alg.size());

        // Length of input after hash code should be exactly hash_len + 1
        if bytes.len() != hash_len + 1 {
            return Err(DecodeError::BadInputLength);
        }

        if usize::from(bytes[0]) != hash_len {
            return Err(DecodeError::BadInputLength);
        }

        Ok(MultihashRef { bytes: input })
    }

    /// Returns which hashing algorithm is used in this multihash.
    pub fn algorithm(&self) -> Hash {
        let code = decode::u16(&self.bytes)
            .expect("multihash is known to be valid algorithm")
            .0;
        Hash::from_code(code).expect("multihash is known to be valid")
    }

    /// Returns the hashed data.
    pub fn digest(&self) -> &'a [u8] {
        let bytes = decode::u16(&self.bytes)
            .expect("multihash is known to be valid digest")
            .1;
        &bytes[1..]
    }

    /// Builds a `Multihash` that owns the data.
    ///
    /// This operation allocates.
    pub fn to_owned(&self) -> Multihash {
        Multihash {
            storage: Storage::from_slice(self.bytes),
        }
    }

    /// Returns the bytes representation of this multihash.
    pub fn as_bytes(&self) -> &'a [u8] {
        &self.bytes
    }
}

impl<'a> PartialEq<Multihash> for MultihashRef<'a> {
    fn eq(&self, other: &Multihash) -> bool {
        self.as_bytes() == &*other.as_bytes()
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
fn as_u64(a: usize) -> u64 {
    a as u64
}
