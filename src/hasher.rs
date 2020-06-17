use generic_array::{ArrayLength, GenericArray};

/// Stack allocated digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Digest<Size: ArrayLength<u8>>(GenericArray<u8, Size>);

impl<Size: ArrayLength<u8>> Digest<Size> {
    /// Creates a new digest from an array.
    pub fn new(digest: GenericArray<u8, Size>) -> Self {
        Self(digest)
    }
}

impl<Size: ArrayLength<u8>> AsRef<[u8]> for Digest<Size> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Trait implemented by a hash function implementation.
pub trait Hasher: Default {
    /// Digest size.
    type Size: ArrayLength<u8> + core::fmt::Debug + Eq;

    /// Consume input and update internal state.
    fn write(&mut self, input: &[u8]);

    /// Returns the internal state digest.
    fn sum(self) -> Digest<Self::Size>;

    /// Returns the digest of the input.
    fn digest(input: &[u8]) -> Digest<Self::Size>
    where
        Self: Sized,
    {
        let mut hasher = Self::default();
        hasher.write(input);
        hasher.sum()
    }
}

/// New type wrapper for a hasher that implements the `std::io::Write` trait.
#[cfg(feature = "std")]
pub struct WriteHasher<H: Hasher>(H);

#[cfg(feature = "std")]
impl<H: Hasher> std::io::Write for WriteHasher<H> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
