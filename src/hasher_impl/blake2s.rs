use crate::hasher::{Digest, Hasher};
use blake2s_simd::{Params, State};
use core::marker::PhantomData;
use generic_array::typenum::{U16, U32};
use generic_array::{ArrayLength, GenericArray};

/// Blake2s hasher.
pub struct Blake2sHasher<Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static> {
    _marker: PhantomData<Size>,
    state: State,
}

impl<Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static> Default for Blake2sHasher<Size> {
    fn default() -> Self {
        let mut params = Params::new();
        params.hash_length(Size::to_usize());
        Self {
            _marker: PhantomData,
            state: params.to_state(),
        }
    }
}

impl<Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static> Hasher for Blake2sHasher<Size> {
    type Size = Size;

    fn write(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    fn sum(self) -> Digest<Self::Size> {
        Digest::new(GenericArray::clone_from_slice(
            self.state.finalize().as_bytes(),
        ))
    }
}

/// 128 bit blake2s hasher.
pub type Blake2s128 = Blake2sHasher<U16>;

/// 256 bit blake2s hasher.
pub type Blake2s256 = Blake2sHasher<U32>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2s128() {
        let hash = Blake2s128::digest(b"hello world");
        let mut hasher = Blake2s128::default();
        hasher.write(b"hello world");
        let hash2 = hasher.sum();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_blake2s256() {
        let hash = Blake2s256::digest(b"hello world");
        let mut hasher = Blake2s256::default();
        hasher.write(b"hello world");
        let hash2 = hasher.sum();
        assert_eq!(hash, hash2);
    }
}
