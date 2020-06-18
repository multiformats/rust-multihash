use crate::hasher::{Digest, Hasher};
use blake2b_simd::{Params, State};
use core::fmt::Debug;
use core::marker::PhantomData;
use generic_array::typenum::{U32, U64};
use generic_array::{ArrayLength, GenericArray};

/// Blake2b hasher.
pub struct Blake2bHasher<Size: ArrayLength<u8> + Debug + Eq + Send + Sync + 'static> {
    _marker: PhantomData<Size>,
    state: State,
}

impl<Size: ArrayLength<u8> + Debug + Eq + Send + Sync + 'static> Default for Blake2bHasher<Size> {
    fn default() -> Self {
        let mut params = Params::new();
        params.hash_length(Size::to_usize());
        Self {
            _marker: PhantomData,
            state: params.to_state(),
        }
    }
}

impl<Size: ArrayLength<u8> + Debug + Eq + Send + Sync + 'static> Hasher for Blake2bHasher<Size> {
    type Size = Size;

    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    fn finalize(&self) -> Digest<Self::Size> {
        Digest::new(GenericArray::clone_from_slice(
            self.state.finalize().as_bytes(),
        ))
    }

    fn reset(&mut self) {
        let Self { state, .. } = Self::default();
        self.state = state;
    }
}

/// 256 bit blake2b hasher.
pub type Blake2b256 = Blake2bHasher<U32>;

/// 512 bit blake2b hasher.
pub type Blake2b512 = Blake2bHasher<U64>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b256() {
        let hash = Blake2b256::digest(b"hello world");
        let mut hasher = Blake2b256::default();
        hasher.update(b"hello world");
        let hash2 = hasher.finalize();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_blake2b512() {
        let hash = Blake2b512::digest(b"hello world");
        let mut hasher = Blake2b512::default();
        hasher.update(b"hello world");
        let hash2 = hasher.finalize();
        assert_eq!(hash, hash2);
    }
}
