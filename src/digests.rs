use std::convert::TryFrom;
use std::{cmp, fmt, hash};

use unsigned_varint::{decode as varint_decode, encode as varint_encode};

use crate::errors::{DecodeError, DecodeOwnedError};
use crate::hashes::Code;
use crate::storage::Storage;

/// Represents a valid multihash.
#[derive(Clone)]
pub struct Multihash {
    storage: Storage,
}

impl fmt::Debug for Multihash {
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
    pub fn algorithm(&self) -> Code {
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

impl PartialOrd for Multihash {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Multihash {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_ref().cmp(&other.as_ref())
    }
}

/// Represents a valid multihash.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MultihashRef<'a> {
    bytes: &'a [u8],
}

impl<'a> MultihashRef<'a> {
    /// Creates a `MultihashRef` from the given `input`.
    pub fn from_slice(input: &'a [u8]) -> Result<Self, DecodeError> {
        if input.is_empty() {
            return Err(DecodeError::BadInputLength);
        }

        let (_code, bytes) = varint_decode::u64(&input).map_err(|_| DecodeError::BadInputLength)?;

        let (hash_len, bytes) =
            varint_decode::u64(&bytes).map_err(|_| DecodeError::BadInputLength)?;
        if (bytes.len() as u64) != hash_len {
            return Err(DecodeError::BadInputLength);
        }

        Ok(MultihashRef { bytes: input })
    }

    /// Returns which hashing algorithm is used in this multihash.
    pub fn algorithm(&self) -> Code {
        let (code, _bytes) =
            varint_decode::u64(&self.bytes).expect("multihash is known to be valid algorithm");
        Code::from_u64(code)
    }

    /// Returns the hashed data.
    pub fn digest(&self) -> &'a [u8] {
        let (_code, bytes) =
            varint_decode::u64(&self.bytes).expect("multihash is known to be valid digest");
        let (_hash_len, bytes) =
            varint_decode::u64(&bytes).expect("multihash is known to be a valid digest");
        &bytes[..]
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

/// The `MultihashDigest` trait specifies an interface common for all multihash functions.
pub trait MultihashDigest {
    /// The Mutlihash byte value.
    fn code(&self) -> Code;

    /// Hash some input and return the digest.
    ///
    /// # Panics
    ///
    /// Panics if the digest length is bigger than 2^32. This only happens for identity hasing.
    fn digest(&self, data: &[u8]) -> Multihash;
}

/// Wraps a hash digest in Multihash with the given Mutlihash code.
///
/// The size of the hash is determoned by the size of the input hash. If it should be truncated
/// the input data must already be the truncated hash.
pub fn wrap(code: &Code, data: &[u8]) -> Multihash {
    let mut code_buf = varint_encode::u64_buffer();
    let code = varint_encode::u64(code.to_u64(), &mut code_buf);

    let mut size_buf = varint_encode::u64_buffer();
    let size = varint_encode::u64(data.len() as u64, &mut size_buf);

    Multihash {
        storage: Storage::from_slices(&[code, &size, &data]),
    }
}
