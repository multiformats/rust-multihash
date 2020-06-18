use crate::hasher::{Digest, Hasher};
use generic_array::typenum::U32;
use generic_array::{ArrayLength, GenericArray};

/// Identity hasher.
#[derive(Default)]
pub struct IdentityHasher<Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static> {
    bytes: GenericArray<u8, Size>,
    i: usize,
}

impl<Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static> Hasher
    for IdentityHasher<Size>
{
    type Size = Size;

    fn update(&mut self, input: &[u8]) {
        let start = self.i;
        let end = start + input.len();
        self.bytes[start..end].copy_from_slice(input);
        self.i = end;
    }

    fn finalize(&self) -> Digest<Self::Size> {
        Digest::new(self.bytes.clone())
    }

    fn reset(&mut self) {
        self.bytes = Default::default();
        self.i = 0;
    }
}

/// 256 bit identity
pub type Identity256 = IdentityHasher<U32>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        let hash = Identity256::digest(b"hello world");
        let mut hasher = Identity256::default();
        hasher.update(b"hello world");
        let hash2 = hasher.finalize();
        assert_eq!(hash, hash2);
    }
}
