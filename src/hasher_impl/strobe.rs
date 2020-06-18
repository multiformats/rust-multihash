use crate::hasher::{Digest, Hasher};
use core::marker::PhantomData;
use generic_array::typenum::{U32, U64};
use generic_array::{ArrayLength, GenericArray};
use strobe_rs::{SecParam, Strobe};

/// Strobe hasher.
pub struct StrobeHasher<Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static> {
    _marker: PhantomData<Size>,
    strobe: Strobe,
    initialized: bool,
}

impl<Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static> Default
    for StrobeHasher<Size>
{
    fn default() -> Self {
        Self {
            _marker: PhantomData,
            strobe: Strobe::new(b"StrobeHash", SecParam::B128),
            initialized: false,
        }
    }
}

impl<Size: ArrayLength<u8> + core::fmt::Debug + Eq + Send + Sync + 'static> Hasher
    for StrobeHasher<Size>
{
    type Size = Size;

    fn update(&mut self, input: &[u8]) {
        self.strobe.ad(input, self.initialized);
        self.initialized = true;
    }

    fn finalize(&self) -> Digest<Self::Size> {
        let mut hash = GenericArray::default();
        self.strobe.clone().prf(&mut hash, false);
        Digest::new(hash)
    }

    fn reset(&mut self) {
        let Self { strobe, .. } = Self::default();
        self.strobe = strobe;
        self.initialized = false;
    }
}

/// 256 bit strobe hasher.
pub type Strobe256 = StrobeHasher<U32>;

/// 512 bit strobe hasher.
pub type Strobe512 = StrobeHasher<U64>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strobe_256() {
        let hash = Strobe256::digest(b"hello world");
        let mut hasher = Strobe256::default();
        hasher.update(b"hello world");
        let hash2 = hasher.finalize();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_strobe_512() {
        let hash = Strobe512::digest(b"hello world");
        let mut hasher = Strobe512::default();
        hasher.update(b"hello world");
        let hash2 = hasher.finalize();
        assert_eq!(hash, hash2);
    }
}
