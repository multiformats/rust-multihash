use crate::error::Error;
use core::fmt::Debug;

/// Trait for reading and writhing Multihashes.
///
/// This traits operates on existing hashes. Creation of new hashes is done by the
/// [`MultihashCreate`] trait.
pub trait MultihashDigest: Clone + Debug + Eq + Send + Sync + 'static {
    //const CODE: u64;

    /// Returns the code of the multihash.
    fn code(&self) -> u64;

    /// Returns the size of the digest.
    fn size(&self) -> u8;

    /// Returns the digest.
    fn digest(&self) -> &[u8];

    /// Reads a multihash from a byte stream.
    #[cfg(feature = "std")]
    fn read<R: std::io::Read>(r: R) -> Result<Self, Error>
    where
        Self: Sized;

    /// Parses a multihash from a bytes.
    #[cfg(feature = "std")]
    fn from_bytes(mut bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Self::read(&mut bytes)
    }

    /// Writes a multihash to a byte stream.
    #[cfg(feature = "std")]
    fn write<W: std::io::Write>(&self, w: W) -> Result<(), Error> {
        write_mh(w, self)
    }

    /// Returns the bytes of a multihash.
    #[cfg(feature = "std")]
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.write(&mut bytes)
            .expect("writing to a vec should never fail");
        bytes
    }
}

/// Trait that makes it possible to create a new hash from some data.
pub trait MultihashCreate: Clone + Debug + Eq + Send + Sync + 'static {
    /// Returns the hash of the input.
    fn new(code: u64, input: &[u8]) -> Result<Self, Error>;
}

/// A Multihash instance that only supports the basic functionality and no hashing.
///
/// With this Multihash implementation you can operate on Multihashes in a generic way, but
/// no hasher implementation is associated with the code.
///
/// # Example
///
/// ```
/// use multihash::{MultihashDigest, RawMultihash};
///
/// const Sha3_256: u64 = 0x16;
/// let digest_bytes = [
///     0x16, 0x20, 0x64, 0x4b, 0xcc, 0x7e, 0x56, 0x43, 0x73, 0x04, 0x09, 0x99, 0xaa, 0xc8, 0x9e,
///     0x76, 0x22, 0xf3, 0xca, 0x71, 0xfb, 0xa1, 0xd9, 0x72, 0xfd, 0x94, 0xa3, 0x1c, 0x3b, 0xfb,
///     0xf2, 0x4e, 0x39, 0x38,
/// ];
/// let mh = RawMultihash::from_bytes(&digest_bytes).unwrap();
/// assert_eq!(mh.code(), Sha3_256);
/// assert_eq!(mh.size(), 32);
/// assert_eq!(mh.digest(), &digest_bytes[2..]);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMultihash {
    /// The code of the Multihash.
    code: u64,
    /// The actual size of the digest in bytes (not the allocated size).
    size: u8,
    /// The digest.
    digest: crate::UnknownDigest<crate::U32>,
}

impl MultihashDigest for RawMultihash {
    fn code(&self) -> u64 {
        self.code
    }

    fn size(&self) -> u8 {
        self.size
    }

    fn digest(&self) -> &[u8] {
        self.digest.as_ref()
    }

    #[cfg(feature = "std")]
    fn read<R: std::io::Read>(r: R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let (code, size, digest) = read_multihash(r)?;
        Ok(Self { code, size, digest })
    }
}

/// Writes the multihash to a byte stream.
#[cfg(feature = "std")]
pub fn write_mh<W, D>(mut w: W, mh: &D) -> Result<(), Error>
where
    W: std::io::Write,
    D: MultihashDigest,
{
    use unsigned_varint::encode as varint_encode;

    let mut code_buf = varint_encode::u64_buffer();
    let code = varint_encode::u64(mh.code(), &mut code_buf);

    let mut size_buf = varint_encode::u8_buffer();
    let size = varint_encode::u8(mh.size(), &mut size_buf);

    w.write_all(code)?;
    w.write_all(size)?;
    w.write_all(mh.digest())?;
    Ok(())
}

/// Reads a code from a byte stream.
#[cfg(feature = "std")]
pub fn read_code<R>(mut r: R) -> Result<u64, Error>
where
    R: std::io::Read,
{
    use unsigned_varint::io::read_u64;
    Ok(read_u64(&mut r)?)
}

/// Reads a multihash from a byte stream that contains the digest prefixed with the size.
///
/// The byte stream must not contain the code as prefix.
#[cfg(feature = "std")]
pub fn read_digest<R, S, D>(mut r: R) -> Result<D, Error>
where
    R: std::io::Read,
    S: crate::hasher::Size,
    D: crate::hasher::Digest<S>,
{
    use generic_array::GenericArray;
    use unsigned_varint::io::read_u64;

    let size = read_u64(&mut r)?;
    if size != S::to_u64() {
        return Err(Error::InvalidSize(size));
    }
    let mut digest = GenericArray::default();
    r.read_exact(&mut digest)?;
    Ok(D::from(digest))
}

/// Reads a multihash from a byte stream that contains a full multihash (code, size and the digest)
///
/// Returns the code, size and the digest. The size is the actual size and not the
/// maximum/allocated size of the digest.
///
/// Currently the maximum size for a digest is 255 bytes.
#[cfg(feature = "std")]
pub fn read_multihash<R, S, D>(mut r: R) -> Result<(u64, u8, D), Error>
where
    R: std::io::Read,
    S: crate::hasher::Size,
    D: crate::hasher::Digest<S>,
{
    use generic_array::GenericArray;
    use unsigned_varint::io::read_u64;

    let code = read_u64(&mut r)?;
    let size = read_u64(&mut r)?;

    if size > S::to_u64() || size > u8::MAX as u64 {
        return Err(Error::InvalidSize(size));
    }

    let mut digest = GenericArray::default();
    r.read_exact(&mut digest)?;
    Ok((code, size as u8, D::from(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::Multihash;
    use crate::hasher::Hasher;
    use crate::hasher_impl::strobe::Strobe256;

    #[test]
    fn roundtrip() {
        let digest = Strobe256::digest(b"hello world");
        let hash = Multihash::from(digest);
        let mut buf = [0u8; 35];
        hash.write(&mut buf[..]).unwrap();
        let hash2 = Multihash::read(&buf[..]).unwrap();
        assert_eq!(hash, hash2);
    }
}
