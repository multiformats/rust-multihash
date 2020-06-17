use crate::error::Error;
use crate::hasher::{Digest, Hasher};
use core::convert::TryFrom;
use generic_array::ArrayLength;

/// Stack allocated multihash storage backend for codes up to 127.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultihashArray<Code, Size>
where
    Code: MultihashCode,
    Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static,
{
    code: Code,
    digest: Digest<Size>,
}

impl<Code, Size> MultihashArray<Code, Size>
where
    Code: MultihashCode,
    Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static,
{
    /// Create a multihash from a code and a digest.
    pub fn new(code: Code, digest: Digest<Size>) -> Self {
        Self { code, digest }
    }
}

/// Trait for a multihash digest.
pub trait MultihashDigest<Code: MultihashCode>: Clone + core::fmt::Debug + Eq + Send + Sync + 'static {
    /// Returns the code of the multihash.
    fn code(&self) -> Code;

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
    fn write<W: std::io::Write>(&self, w: W) -> Result<(), Error>;

    /// Returns the bytes of a multihash.
    #[cfg(feature = "std")]
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.write(&mut bytes)
            .expect("writing to a vec should never fail");
        bytes
    }
}

impl<Code, Size> MultihashDigest<Code> for MultihashArray<Code, Size>
where
    Code: MultihashCode,
    Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static,
{
    fn code(&self) -> Code {
        self.code
    }

    fn size(&self) -> u8 {
        Size::to_u8()
    }

    fn digest(&self) -> &[u8] {
        self.digest.as_ref()
    }

    #[cfg(feature = "std")]
    fn read<R: std::io::Read>(mut r: R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let code = read_code(&mut r)?;
        read_mh(r, code)
    }

    #[cfg(feature = "std")]
    fn write<W: std::io::Write>(&self, w: W) -> Result<(), Error> {
        write_mh(w, self)
    }
}

/// Trait to compute the digest of a multihash code.
pub trait MultihashCode: Into<u64> + TryFrom<u64, Error = Error> + Copy + core::fmt::Debug + Eq + Send + Sync + 'static {
    /// Multihash type.
    type Multihash: MultihashDigest<Self>;

    /// Returns the size of the digest.
    fn size(&self) -> u8;

    /// Returns the hash of the input.
    fn digest(&self, input: &[u8]) -> Self::Multihash;
}

/// Trait to extend a `Hasher` with support for a code.
pub trait MultihasherCode<Code: MultihashCode>: Hasher {
    /// The code of the hash function.
    const CODE: Code;

    /// Get the code at runtime.
    fn code(&self) -> Code {
        Self::CODE
    }
}

/// Trait that extends a `Hasher` with support for multihashes.
pub trait Multihasher<Code>: MultihasherCode<Code>
where
    Code: MultihashCode,
    <Self as Hasher>::Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static,
{
    /// Returns the multihash of the input.
    fn multi_digest(input: &[u8]) -> MultihashArray<Code, <Self as Hasher>::Size>;

    /// Returns the multihash of the internal state.
    fn multi_sum(self) -> MultihashArray<Code, <Self as Hasher>::Size>;
}

impl<Code, H: MultihasherCode<Code>> Multihasher<Code> for H
where
    Code: MultihashCode,
    H::Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static,
{
    fn multi_digest(input: &[u8]) -> MultihashArray<Code, <Self as Hasher>::Size> {
        let digest = <H as Hasher>::digest(input);
        let code = <H as MultihasherCode<Code>>::CODE;
        MultihashArray::new(code, digest)
    }

    fn multi_sum(self) -> MultihashArray<Code, <Self as Hasher>::Size> {
        let sum = Hasher::sum(self);
        let code = <H as MultihasherCode<Code>>::CODE;
        MultihashArray::new(code, sum)
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
pub fn read_mh<R, C, S>(mut r: R, code: C) -> Result<MultihashArray<C, S>, Error>
where
    R: std::io::Read,
    C: MultihashCode,
    S: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static,
{
    use generic_array::GenericArray;
    use unsigned_varint::io::read_u64;

    let size = read_u64(&mut r)?;
    if size != S::to_u64() {
        return Err(Error::InvalidSize(size));
    }
    let mut buf = GenericArray::default();
    r.read_exact(&mut buf)?;
    let digest = Digest::new(buf);
    Ok(MultihashArray::new(code, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::Code;
    use crate::hasher_impl::strobe::Strobe256;

    #[test]
    fn roundtrip() {
        let digest = Strobe256::digest(b"hello world");
        let hash = MultihashArray::new(Code::Strobe256, digest);
        let mut buf = [0u8; 35];
        hash.write(&mut buf[..]).unwrap();
        let hash2 = MultihashArray::read(&buf[..]).unwrap();
        assert_eq!(hash, hash2);
    }
}
