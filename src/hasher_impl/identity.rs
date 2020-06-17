use crate::hasher::{Digest, Hasher};
use generic_array::typenum::U32;
use generic_array::{ArrayLength, GenericArray};

/// Identity hasher.
#[derive(Default)]
pub struct IdentityHasher<Size: ArrayLength<u8>> {
    bytes: GenericArray<u8, Size>,
    i: usize,
}

impl<Size: ArrayLength<u8>> Hasher for IdentityHasher<Size> {
    type Size = Size;

    fn write(&mut self, input: &[u8]) {
        let start = self.i;
        let end = start + input.len();
        self.bytes[start..end].copy_from_slice(input);
        self.i = end;
    }

    fn sum(self) -> Digest<Self::Size> {
        Digest::new(self.bytes)
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
        hasher.write(b"hello world");
        let hash2 = hasher.sum();
        assert_eq!(hash, hash2);
    }
}
