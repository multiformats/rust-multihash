use crate::error::Error;
use crate::hasher::Hasher;
use core::convert::TryFrom;
use core::fmt::Debug;

/// Trait for a multihash digest.
pub trait MultihashDigest<C: MultihashCode>: Clone + Debug + Eq + Send + Sync + 'static {
    /// Returns the code of the multihash.
    fn code(&self) -> C;

    /// Returns the size of the digest.
    fn size(&self) -> u8 {
        self.code().size()
    }

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

/// Trait to compute the digest of a multihash code.
pub trait MultihashCode:
    Into<u64> + TryFrom<u64, Error = Error> + Copy + Debug + Eq + Send + Sync + 'static
{
    /// Multihash type.
    type Multihash: MultihashDigest<Self>;

    /// Returns the size of the digest.
    fn size(&self) -> u8;

    /// Returns the hash of the input.
    fn digest(&self, input: &[u8]) -> Self::Multihash;
}

/// Trait to extend a `Hasher` with support for a code.
pub trait MultihasherCode<C: MultihashCode>: Hasher {
    /// The code of the hash function.
    const CODE: C;

    /// Get the code at runtime.
    fn code(&self) -> C {
        Self::CODE
    }
}

/// Writes the multihash to a byte stream.
#[cfg(feature = "std")]
pub fn write_mh<W, C, D>(mut w: W, mh: &D) -> Result<(), Error>
where
    W: std::io::Write,
    C: MultihashCode,
    D: MultihashDigest<C>,
{
    use unsigned_varint::encode as varint_encode;

    let mut code_buf = varint_encode::u64_buffer();
    let code = varint_encode::u64(mh.code().into(), &mut code_buf);

    let mut size_buf = varint_encode::u8_buffer();
    let size = varint_encode::u8(mh.size(), &mut size_buf);

    w.write_all(code)?;
    w.write_all(size)?;
    w.write_all(mh.digest())?;
    Ok(())
}

/// Reads a code from a byte stream.
#[cfg(feature = "std")]
pub fn read_code<R, C>(mut r: R) -> Result<C, Error>
where
    R: std::io::Read,
    C: MultihashCode,
{
    use unsigned_varint::io::read_u64;
    C::try_from(read_u64(&mut r)?)
}

/// Reads a multihash from a byte stream.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::Multihash;
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
