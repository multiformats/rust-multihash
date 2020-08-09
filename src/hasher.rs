use crate::error::Error;
use core::fmt::Debug;
use generic_array::typenum::marker_traits::Unsigned;
use generic_array::{ArrayLength, GenericArray};

/// Size marker trait.
pub trait Size: ArrayLength<u8> + Debug + Default + Eq + Send + Sync + 'static {}

impl<T: ArrayLength<u8> + Debug + Default + Eq + Send + Sync + 'static> Size for T {}

/// Stack allocated digest trait.
pub trait Digest<S: Size>:
    AsRef<[u8]>
    + From<GenericArray<u8, S>>
    + Into<GenericArray<u8, S>>
    + Clone
    + Debug
    + Default
    + Eq
    + Send
    + Sync
    + 'static
{
    /// Wraps the digest bytes.
    fn wrap(digest: &[u8]) -> Result<Self, Error> {
        if digest.len() != S::to_u8() as _ {
            return Err(Error::InvalidSize(digest.len() as _));
        }
        let mut array = GenericArray::default();
        array.copy_from_slice(digest);
        Ok(array.into())
    }
}

/// Trait implemented by a hash function implementation.
///
/// It specifies its own Digest type, so that the output of the hash function can later be
/// distinguished. This way you can create a [`MultihashDigest`] from a `Digest`.
///
/// Every hashing algorithm that is used with Multihash needs to implement those. This trait is
/// very similar to the external [`digest::Digest` trait]. There is a small significant
/// difference, which needed the introduction of this `Hasher` trait instead of re-using the
/// widely used `digest::Digest` trait.
///
/// The external `digest::Digest` trait has a single return type called [`Output`], which is used
/// for all hashers that implement it. It's basically a wrapper around the hashed result bytes.
/// For Multihashes we need to distinguish those bytes, as we care about which hash function they
/// were created with (which is the whole point of [Multihashes]). Therefore the [`Hasher`] trait
/// defines an [associated type] [`Hasher::Digest`] for the output of the hasher. This way the
/// implementers can specify their own, hasher specific type (which implements [`Digest`]) for
/// their output.
///
/// [`digest::Digest` trait]: https://docs.rs/digest/0.9.0/digest/trait.Digest.html
/// [`Output`]: https://docs.rs/digest/0.9.0/digest/type.Output.html
/// [Multihashes]: https://github.com/multiformats/multihash
/// [associated type]: https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#specifying-placeholder-types-in-trait-definitions-with-associated-types
/// [`MultihashDigest`]: crate::MultihashDigest
pub trait Hasher: Default {
    /// The maximum Digest size for that hasher (it is stack allocated).
    type Size: Size;

    /// The Digest type to distinguish the output of different `Hasher` implementations.
    type Digest: Digest<Self::Size>;

    /// Consume input and update internal state.
    fn update(&mut self, input: &[u8]);

    /// Returns the final digest.
    fn finalize(&self) -> Self::Digest;

    /// Reset the internal hasher state.
    fn reset(&mut self);

    /// Returns the allocated size of the digest.
    fn size() -> u8 {
        Self::Size::to_u8()
    }

    /// Hashes the given `input` data and returns its hash digest.
    fn digest(input: &[u8]) -> Self::Digest
    where
        Self: Sized,
    {
        let mut hasher = Self::default();
        hasher.update(input);
        hasher.finalize()
    }
}

/// New type wrapper for a hasher that implements the `std::io::Write` trait.
#[cfg(feature = "std")]
pub struct WriteHasher<H: Hasher>(H);

#[cfg(feature = "std")]
impl<H: Hasher> std::io::Write for WriteHasher<H> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
