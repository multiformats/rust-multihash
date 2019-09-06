use digest::{BlockInput, FixedOutput, Input, Reset};
use digest::generic_array::GenericArray;
use fasthash::FastHash;

macro_rules! fasthash {
    ($name:ident, $size:ident, $hash:ident, $hasher:ident) => {
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            bytes: Vec<u8>,
        }

        impl BlockInput for $name {
            type BlockSize = digest::generic_array::typenum::$size;
        }

        impl FixedOutput for $name {
            type OutputSize = digest::generic_array::typenum::$size;

            fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
               fasthash::$hash::$hasher::hash_with_seed(&self.bytes, Default::default()).to_le_bytes().into()
            }
        }

        impl Input for $name {
            fn input<T: AsRef<[u8]>>(&mut self, bytes: T) {
                self.bytes.extend(bytes.as_ref());
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                self.bytes.clear();
            }
        }
    }
}

fasthash!(Murmur3_32, U4, murmur3, Hash32);
fasthash!(Murmur3_128X64, U16, murmur3, Hash128_x64);
