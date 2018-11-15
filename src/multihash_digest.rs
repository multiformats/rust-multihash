use digest::{BlockInput, Input, Reset};

use digests::{Code, Multihash};

/// The `MultihashDigest` trait specifies an interface common for
/// all multihash functions. It is heavily based on the `digest::Digest` trait.
pub trait MultihashDigest:
    ::std::fmt::Debug + BlockInput + Input + Reset + Clone + Default
{
    /// Creates a new hasher, that can be used for streaming inputs.
    fn new() -> Self;

    /// Returns the default size for this hash (the raw hash, not the multihash).
    fn size() -> u32;
    /// Returns a string representation of the hashing algorithm.
    fn to_string() -> &'static str;
    /// Returns the multihash code for this algorithm based on [this table](https://github.com/multiformats/multicodec/blob/master/table.csv).
    fn code() -> Code;

    /// Convenience method to immediately hash some input and return the digest.
    fn digest(data: &[u8]) -> Multihash;

    /// Wraps a raw hash, into its multihash version.
    fn wrap<T: AsRef<[u8]>>(T) -> Multihash;

    /// Finishes the hashing and returns the result. The hasher can not be used afterwards.
    fn result(self) -> Multihash;

    /// Finishes the hashing and resets the internal hasher, so it can be reused.
    fn result_reset(&mut self) -> Multihash;
}
