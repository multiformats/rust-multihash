use std::borrow::Borrow;
use std::convert::TryFrom;
use std::{cmp, fmt, hash, ops};

use unsigned_varint::{decode as varint_decode, encode as varint_encode};

use crate::errors::{DecodeError, DecodeOwnedError};
use crate::hashes::Code;
use crate::storage::Storage;

/// Representation of a valid multihash. This enforces validity on construction,
/// so it can be assumed this is always a valid multihash.
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
    /// Creates a new `Multihash` from a `Vec<u8>`, consuming it.
    /// If the input data is not a valid multihash an error is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Sha2_256, Multihash};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    ///
    /// // valid multihash
    /// let mh2 = Multihash::from_bytes(mh.into_bytes()).unwrap();
    ///
    /// // invalid multihash
    /// assert!(Multihash::from_bytes(vec![1,2,3]).is_err());
    /// ```
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

    /// Returns the algorithm used in this multihash.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Code, Sha2_256};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    /// assert_eq!(mh.algorithm(), Code::Sha2_256);
    /// ```
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

impl ops::Deref for Multihash {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.as_bytes()
    }
}

impl Borrow<[u8]> for Multihash {
    fn borrow(&self) -> &[u8] {
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

impl Into<Vec<u8>> for Multihash {
    fn into(self) -> Vec<u8> {
        self.to_vec()
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
    /// Creates a new `MultihashRef` from a `&[u8]`.
    /// If the input data is not a valid multihash an error is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Sha2_256, Multihash, MultihashRef};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    ///
    /// // valid multihash
    /// let mh2 = MultihashRef::from_slice(&mh).unwrap();
    ///
    /// // invalid multihash
    /// assert!(MultihashRef::from_slice(&vec![1,2,3]).is_err());
    /// ```
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

    /// Returns the algorithm used in this multihash.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Code, Sha2_256, MultihashRef};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    ///
    /// // valid multihash
    /// let mh2 = MultihashRef::from_slice(&mh).unwrap();
    /// assert_eq!(mh2.algorithm(), Code::Sha2_256);
    /// ```
    pub fn algorithm(&self) -> Code {
        let (code, _bytes) =
            varint_decode::u64(&self.bytes).expect("multihash is known to be valid algorithm");
        Code::from(code)
    }

    /// Returns the hash digest.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{wrap, Code, Sha2_256};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    /// let digest = mh.digest();
    /// let wrapped = wrap(Code::Sha2_256, &digest);
    /// assert_eq!(wrapped.digest(), digest);
    /// ```
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

impl<'a> ops::Deref for MultihashRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl<'a> Into<Vec<u8>> for MultihashRef<'a> {
    fn into(self) -> Vec<u8> {
        self.to_vec()
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

    /// Digest input data.
    ///
    /// This method can be called repeatedly for use with streaming messages.
    ///
    /// # Panics
    ///
    /// Panics if the digest length is bigger than 2^32. This only happens for identity hashing.
    fn input(&mut self, data: &[u8]);

    /// Retrieve the computed `Multihash`, consuming the hasher.
    fn result(self) -> Multihash;

    /// Retrieve result and reset hasher instance.
    ///
    /// This method sometimes can be more efficient compared to hasher re-creation.
    fn result_reset(&mut self) -> Multihash;

    /// Reset hasher instance to its initial state.
    fn reset(&mut self);
}

/// Wraps a hash digest in Multihash with the given Mutlihash code.
///
/// The size of the hash is determoned by the size of the input hash. If it should be truncated
/// the input data must already be the truncated hash.
///
/// # Example
///
/// ```
/// use multihash::{wrap, Code, Sha2_256};
///
/// let mh = Sha2_256::digest(b"hello world");
/// let digest = mh.digest();
/// let wrapped = wrap(Code::Sha2_256, &digest);
/// assert_eq!(wrapped.digest(), digest);
/// ```
pub fn wrap(code: Code, data: &[u8]) -> Multihash {
    let mut code_buf = varint_encode::u64_buffer();
    let code = varint_encode::u64(code.into(), &mut code_buf);

    let mut size_buf = varint_encode::u64_buffer();
    let size = varint_encode::u64(data.len() as u64, &mut size_buf);

    Multihash {
        storage: Storage::from_slices(&[code, &size, &data]),
    }
}
