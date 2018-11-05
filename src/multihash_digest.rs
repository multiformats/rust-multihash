use digest::Digest;
use generic_array::ArrayLength;

/// The `MultihashDigest` trait specifies an interface common for
/// all multihash functions. It is heavily based on the `digest::Digest` trait.
pub trait MultihashDigest: ::std::fmt::Debug + Digest {
    type RawSize: ArrayLength<u8>;

    fn size() -> usize;
    fn name() -> &'static str;
    fn code() -> u8;

    /// Wraps a raw digest, into its multihash version.
    fn wrap(
        &generic_array::GenericArray<u8, Self::RawSize>,
    ) -> generic_array::GenericArray<u8, Self::OutputSize>;
}
