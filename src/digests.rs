use std::borrow::Borrow;
use std::convert::{Into, TryFrom};
use std::marker::PhantomData;
use std::{cmp, fmt, hash, ops};

use unsigned_varint::{decode as varint_decode, encode as varint_encode};

use crate::errors::{DecodeError, DecodeOwnedError};
use crate::hashes::Code;
use crate::storage::Storage;

// It would be nice if default generics would work well with `PhantomData`, so that instead of this
// custom type `Multihash<T = Code>` would work.
/// This type is using the default Multihash code table
pub type Multihash = MultihashGeneric<Code>;

/// This type is using the default Multihash code table
pub type MultihashRef<'a> = MultihashRefGeneric<'a, Code>;

/// Representation of a valid multihash. This enforces validity on construction,
/// so it can be assumed this is always a valid multihash.
///
/// This generic type can be used with your own code table.
///
/// # Example
///
/// ```
/// use multihash::{wrap, MultihashGeneric};
/// use std::convert::TryFrom;
///
/// #[derive(Debug)]
/// pub enum MyCodeTable {
///     Foo = 0x01,
///     Bar = 0x02,
/// }
///
/// impl TryFrom<u64> for MyCodeTable {
///     type Error = String;
///
///     fn try_from(raw: u64) -> Result<Self, Self::Error> {
///         match raw {
///             0x01 => Ok(Self::Foo),
///             0x02 => Ok(Self::Bar),
///             _ => Err("invalid code".to_string()),
///         }
///     }
/// }
///
/// impl From<MyCodeTable> for u64 {
///     fn from(code: MyCodeTable) -> Self {
///         code as u64
///     }
/// }
///
/// #[derive(Clone, Debug)]
/// struct SameHash;
/// impl SameHash {
///     pub const CODE: MyCodeTable = MyCodeTable::Foo;
///     /// Hash some input and return the sha1 digest.
///     pub fn digest(_data: &[u8]) -> MultihashGeneric<MyCodeTable> {
///         let digest = b"alwaysthesame";
///         wrap(Self::CODE, digest)
///     }
/// }
///
/// let my_hash = SameHash::digest(b"abc");
/// assert_eq!(my_hash.digest(), b"alwaysthesame");
/// ```
///
/// This mechanism can also be used if you want to extend the existing code table
///
/// # Example
///
/// ```
/// use multihash::Code;
/// use std::convert::TryFrom;
///
/// #[derive(Debug, PartialEq)]
/// enum ExtendedCode {
///     Foo,
///     Bar,
///     NormalCode(Code),
/// }
///
/// impl TryFrom<u64> for ExtendedCode {
///     type Error = String;
///
///     /// Return the `Code` based on the integer value
///     fn try_from(raw: u64) -> Result<Self, Self::Error> {
///         match raw {
///             0x01 => Ok(Self::Foo),
///             0x02 => Ok(Self::Bar),
///             // Fallback to the default values
///             _ => match Code::try_from(raw) {
///                 Ok(code) => Ok(Self::NormalCode(code)),
///                 Err(_) => Err("invalid code".to_string()),
///             }, //_ => Err("invalid code".to_string()),
///         }
///     }
/// }
///
/// impl From<ExtendedCode> for u64 {
///     fn from(code: ExtendedCode) -> Self {
///         match code {
///             ExtendedCode::Foo => 0x01,
///             ExtendedCode::Bar => 0x02,
///             ExtendedCode::NormalCode(normal_code) => normal_code.into(),
///         }
///     }
/// }
///
/// impl TryFrom<ExtendedCode> for Code {
///     type Error = String;
///
///     fn try_from(extended: ExtendedCode) -> Result<Self, Self::Error> {
///         match extended {
///             ExtendedCode::NormalCode(code) => Ok(code),
///             _ => Err("Not a default code".to_string()),
///         }
///     }
/// }
///
/// assert_eq!(ExtendedCode::try_from(0x02).unwrap(), ExtendedCode::Bar);
/// assert_eq!(
///     ExtendedCode::try_from(0x12).unwrap(),
///     ExtendedCode::NormalCode(Code::Sha2_256)
/// );
/// assert_eq!(
///     Code::try_from(ExtendedCode::try_from(0x12).unwrap()).unwrap(),
///     Code::Sha2_256
/// );
/// ```
#[derive(Clone)]
pub struct MultihashGeneric<T: TryFrom<u64>> {
    storage: Storage,
    // Use `PhantomData` in order to be able to make the `Multihash` struct take a generic
    _code: PhantomData<T>,
}

impl<T: TryFrom<u64>> fmt::Debug for MultihashGeneric<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Multihash").field(&self.as_bytes()).finish()
    }
}

impl<T: TryFrom<u64>> PartialEq for MultihashGeneric<T> {
    fn eq(&self, other: &Self) -> bool {
        self.storage.bytes() == other.storage.bytes()
    }
}

impl<T: TryFrom<u64>> Eq for MultihashGeneric<T> {}

impl<T: TryFrom<u64>> hash::Hash for MultihashGeneric<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.storage.bytes().hash(state);
    }
}

impl<T: TryFrom<u64>> MultihashGeneric<T> {
    /// Creates a new `Multihash` from a `Vec<u8>`, consuming it.
    /// If the input data is not a valid multihash an error is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Multihash, Sha2_256};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    ///
    /// // valid multihash
    /// let mh2 = Multihash::from_bytes(mh.into_bytes()).unwrap();
    ///
    /// // invalid multihash
    /// assert!(Multihash::from_bytes(vec![1, 2, 3]).is_err());
    /// ```
    pub fn from_bytes(bytes: Vec<u8>) -> Result<MultihashGeneric<T>, DecodeOwnedError> {
        if let Err(err) = MultihashRefGeneric::<T>::from_slice(&bytes) {
            return Err(DecodeOwnedError {
                error: err,
                data: bytes,
            });
        }
        Ok(Self {
            storage: Storage::from_slice(&bytes),
            _code: PhantomData,
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
    pub fn as_ref(&self) -> MultihashRefGeneric<T> {
        MultihashRefGeneric {
            bytes: self.as_bytes(),
            _code: PhantomData,
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
    pub fn algorithm(&self) -> T
    where
        <T as TryFrom<u64>>::Error: std::fmt::Debug,
    {
        self.as_ref().algorithm()
    }

    /// Returns the hashed data.
    pub fn digest(&self) -> &[u8] {
        self.as_ref().digest()
    }
}

impl<T: TryFrom<u64>> AsRef<[u8]> for MultihashGeneric<T> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<T: TryFrom<u64>> ops::Deref for MultihashGeneric<T> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.as_bytes()
    }
}

impl<T: TryFrom<u64>> Borrow<[u8]> for MultihashGeneric<T> {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a, T: TryFrom<u64>> PartialEq<MultihashRefGeneric<'a, T>> for MultihashGeneric<T> {
    fn eq(&self, other: &MultihashRefGeneric<'a, T>) -> bool {
        &*self.as_bytes() == other.as_bytes()
    }
}

impl<T: TryFrom<u64>> TryFrom<Vec<u8>> for MultihashGeneric<T> {
    type Error = DecodeOwnedError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        MultihashGeneric::from_bytes(value)
    }
}

impl<T: TryFrom<u64>> Into<Vec<u8>> for MultihashGeneric<T> {
    fn into(self) -> Vec<u8> {
        self.to_vec()
    }
}

impl<T: TryFrom<u64>> PartialOrd for MultihashGeneric<T> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: TryFrom<u64>> Ord for MultihashGeneric<T> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_ref().cmp(&other.as_ref())
    }
}

/// Represents a valid multihash.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MultihashRefGeneric<'a, T> {
    bytes: &'a [u8],
    _code: PhantomData<T>,
}

impl<'a, T: TryFrom<u64>> MultihashRefGeneric<'a, T> {
    /// Creates a new `MultihashRef` from a `&[u8]`.
    /// If the input data is not a valid multihash an error is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{MultihashRef, Sha2_256};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    ///
    /// // valid multihash
    /// let mh2 = MultihashRef::from_slice(&mh).unwrap();
    ///
    /// // invalid multihash
    /// assert!(MultihashRef::from_slice(&vec![1, 2, 3]).is_err());
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

        Ok(Self {
            bytes: input,
            _code: PhantomData,
        })
    }

    /// Returns the algorithm used in this multihash.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Code, MultihashRef, Sha2_256};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    ///
    /// // valid multihash
    /// let mh2 = MultihashRef::from_slice(&mh).unwrap();
    /// assert_eq!(mh2.algorithm(), Code::Sha2_256);
    /// ```
    pub fn algorithm(&self) -> T
    where
        <T as TryFrom<u64>>::Error: std::fmt::Debug,
    {
        let (rawcode, _bytes) =
            varint_decode::u64(&self.bytes).expect("multihash is known to be valid algorithm");
        T::try_from(rawcode).expect("multihash is known to be a valid algorithm")
    }

    /// Returns the hash digest.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{wrap, Code, Multihash, Sha2_256};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    /// let digest = mh.digest();
    /// let wrapped: Multihash = wrap(Code::Sha2_256, &digest);
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
    pub fn to_owned(&self) -> MultihashGeneric<T> {
        MultihashGeneric {
            storage: Storage::from_slice(self.bytes),
            _code: PhantomData,
        }
    }

    /// Returns the bytes representation of this multihash.
    pub fn as_bytes(&self) -> &'a [u8] {
        &self.bytes
    }
}

impl<'a, T: TryFrom<u64>> PartialEq<MultihashGeneric<T>> for MultihashRefGeneric<'a, T> {
    fn eq(&self, other: &MultihashGeneric<T>) -> bool {
        self.as_bytes() == &*other.as_bytes()
    }
}

impl<'a, T: TryFrom<u64>> ops::Deref for MultihashRefGeneric<'a, T> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl<'a, T: TryFrom<u64>> Into<Vec<u8>> for MultihashRefGeneric<'a, T> {
    fn into(self) -> Vec<u8> {
        self.to_vec()
    }
}

/// The `MultihashDigest` trait specifies an interface common for all multihash functions.
pub trait MultihashDigest<T = Code>
where
    T: TryFrom<u64>,
{
    /// The Mutlihash byte value.
    fn code(&self) -> T;

    /// Hash some input and return the digest.
    ///
    /// # Panics
    ///
    /// Panics if the digest length is bigger than 2^32. This only happens for identity hasing.
    fn digest(&self, data: &[u8]) -> MultihashGeneric<T>;

    /// Digest input data.
    ///
    /// This method can be called repeatedly for use with streaming messages.
    ///
    /// # Panics
    ///
    /// Panics if the digest length is bigger than 2^32. This only happens for identity hashing.
    fn input(&mut self, data: &[u8]);

    /// Retrieve the computed `MultihashGeneric`, consuming the hasher.
    fn result(self) -> MultihashGeneric<T>;

    /// Retrieve result and reset hasher instance.
    ///
    /// This method sometimes can be more efficient compared to hasher re-creation.
    fn result_reset(&mut self) -> MultihashGeneric<T>;

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
/// use multihash::{wrap, Code, Multihash, Sha2_256};
///
/// let mh = Sha2_256::digest(b"hello world");
/// let digest = mh.digest();
/// let wrapped: Multihash = wrap(Code::Sha2_256, &digest);
/// assert_eq!(wrapped.digest(), digest);
/// ```
pub fn wrap<T: Into<u64> + TryFrom<u64>>(code: T, data: &[u8]) -> MultihashGeneric<T> {
    let mut code_buf = varint_encode::u64_buffer();
    let code = varint_encode::u64(code.into(), &mut code_buf);

    let mut size_buf = varint_encode::u64_buffer();
    let size = varint_encode::u64(data.len() as u64, &mut size_buf);

    MultihashGeneric {
        storage: Storage::from_slices(&[code, &size, &data]),
        _code: PhantomData,
    }
}
