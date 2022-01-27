#[cfg(feature = "std")]
use std::io;

#[cfg(not(feature = "std"))]
use core2::io;

/// Trait implemented by a hash function implementation.
pub trait Hasher: io::Write {
    /// The maximum size of the resulting digest.
    const MAX_SIZE: usize;

    /// Consume input and update internal state.
    fn update(&mut self, input: &[u8]);

    /// Returns the final digest.
    fn finalize(&mut self) -> &[u8];

    /// Reset the internal hasher state.
    fn reset(&mut self);
}
