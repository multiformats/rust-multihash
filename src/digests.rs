use std::convert::TryFrom;

use digest::{BlockInput, Digest, Input, Reset};
use integer_encoding::VarInt;

use crate::errors::Error;
use crate::multihash_digest::MultihashDigest;

/// Representation of a valid multihash. This enforces validity on construction,
/// so it can be assumed this is always a valid multihash.
#[derive(Clone, Debug, PartialEq, Hash)]
pub struct Multihash(Box<[u8]>);

impl AsRef<[u8]> for Multihash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Hash)]
pub struct MultihashRef<'a>(&'a [u8]);

impl<'a> AsRef<[u8]> for MultihashRef<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl Into<Vec<u8>> for Multihash {
    fn into(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

impl<'a> Into<Vec<u8>> for MultihashRef<'a> {
    fn into(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl std::ops::Deref for Multihash {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> std::ops::Deref for MultihashRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl TryFrom<Vec<u8>> for Multihash {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Multihash::from_bytes(value)
    }
}

impl Multihash {
    /// Creates a new `Multihash` from a `Vec<u8>`, consuming it.
    /// If the input data is not a valid multihash an error is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Sha2_256, MultihashDigest, Multihash, Code};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    ///
    /// // valid multihash
    /// let mh2 = Multihash::from_bytes(mh.to_bytes()).unwrap();
    ///
    /// // invalid multihash
    /// assert!(Multihash::from_bytes(vec![1,2,3]).is_err());
    /// ```
    pub fn from_bytes(raw: Vec<u8>) -> Result<Self, Error> {
        // validate code
        let (raw_code, code_size) = u32::decode_var(&raw[..]);
        Code::from_u32(raw_code).ok_or_else(|| Error::Invalid)?;

        // validate size
        let (size, size_size) = u64::decode_var(&raw[code_size..]);
        if size != (raw.len() - code_size - size_size) as u64 {
            return Err(Error::BadInputLength);
        }

        Ok(Multihash(raw.into_boxed_slice()))
    }

    /// Creates a new `Multihash` from a slice.
    /// If the input data is not a valid multihash an error is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Sha2_256, MultihashDigest, Multihash, Code};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    ///
    /// // valid multihash
    /// let mh2 = Multihash::from_slice(&mh).unwrap();
    ///
    /// // invalid multihash
    /// assert!(Multihash::from_slice(&vec![1,2,3]).is_err());
    /// ```
    pub fn from_slice(raw: &[u8]) -> Result<Self, Error> {
        Multihash::from_bytes(raw.into())
    }

    /// Creates a new `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Returns the `Code` of this multihash.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Sha2_256, MultihashDigest, Code};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    /// assert_eq!(mh.code(), Code::Sha2_256);
    /// ```
    pub fn code(&self) -> Code {
        let (raw_code, _) = u32::decode_var(&self.0);
        Code::from_u32(raw_code).unwrap()
    }

    /// Returns the algorithm used in this multihash as a string.
    ///
    /// # Example
    ///
    /// ```
    /// use multihash::{Sha2_256, MultihashDigest};
    ///
    /// let mh = Sha2_256::digest(b"hello world");
    /// assert_eq!(mh.algorithm(), "Sha2_256");
    /// ```
    pub fn algorithm(&self) -> &'static str {
        self.code().into()
    }

    /// Create a `MultihashRef` matching this `Multihash`.
    pub fn as_ref(&self) -> MultihashRef<'_> {
        MultihashRef(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, MultihashDigest)]
#[repr(u32)]
pub enum Code {
    #[Size = "20"]
    #[Digest = "sha1::Sha1"]
    Sha1 = 0x11,

    #[Size = "32"]
    #[Digest = "sha2::Sha256"]
    Sha2_256 = 0x12,

    #[Size = "64"]
    #[Digest = "sha2::Sha512"]
    Sha2_512 = 0x13,

    #[Size = "28"]
    #[Digest = "sha3::Sha3_224"]
    Sha3_224 = 0x17,

    #[Size = "32"]
    #[Digest = "sha3::Sha3_256"]
    Sha3_256 = 0x16,

    #[Size = "48"]
    #[Digest = "sha3::Sha3_384"]
    Sha3_384 = 0x15,

    #[Size = "64"]
    #[Digest = "sha3::Sha3_512"]
    Sha3_512 = 0x14,

    #[Size = "28"]
    #[Digest = "sha3::Keccak224"]
    Keccak224 = 0x1A,

    #[Size = "32"]
    #[Digest = "sha3::Keccak256"]
    Keccak256 = 0x1B,

    #[Size = "48"]
    #[Digest = "sha3::Keccak384"]
    Keccak384 = 0x1C,

    #[Size = "64"]
    #[Digest = "sha3::Keccak512"]
    Keccak512 = 0x1D,

    #[Size = "64"]
    #[Digest = "blake2::Blake2b"]
    Blake2b = 0xb240,

    #[Size = "32"]
    #[Digest = "blake2::Blake2s"]
    Blake2s = 0xb260,
}

#[cfg(test)]
mod tests {
    use super::super::MultihashDigest;
    use super::{decode, Code, Sha2_256};
    use digest::{Digest, Input};

    use hex;
    use sha2::Sha256;

    #[test]
    fn test_multihash_sha2_265() {
        assert_eq!(Sha2_256::size(), 32);
        assert_eq!(Sha2_256::to_string(), "Sha2_256");

        let expected =
            hex::decode("1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af")
                .expect("invalid hex fixture");

        let mut hasher = Sha2_256::new();
        hasher.input(b"hello");
        hasher.input(b"world");
        let res = hasher.result();
        assert_eq!(&res[..], &expected[..]);
        assert_eq!(res.code(), Code::Sha2_256);

        assert_eq!(&Sha2_256::digest(b"helloworld")[..], &expected[..]);
    }

    #[test]
    fn test_wrap() {
        let expected =
            hex::decode("1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af")
                .expect("invalid hex fixture");

        let raw_digest = Sha256::digest(b"helloworld");

        assert_eq!(&Sha2_256::wrap(raw_digest)[..], &expected[..]);
    }

    #[test]
    fn test_decode_default() {
        let bytes = hex::decode("11147c8357577f51d4f0a8d393aa1aaafb28863d9421").unwrap();
        let decoded = decode(&bytes).unwrap();

        assert_eq!(decoded.algorithm(), "Sha1");
        assert_eq!(&decoded[..], &bytes[..]);
        assert_eq!(decoded.to_vec(), bytes);
    }
}
