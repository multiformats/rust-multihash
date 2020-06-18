#[cfg(feature = "digest")]
macro_rules! digest {
    ($module:ty, $name:ident, $size:ty) => {
        /// $name hasher.
        #[derive(Default)]
        pub struct $name {
            state: $module,
        }

        impl $crate::hasher::Hasher for $name {
            type Size = $size;

            fn update(&mut self, input: &[u8]) {
                use digest::Digest;
                self.state.update(input)
            }

            fn finalize(&self) -> $crate::hasher::Digest<Self::Size> {
                use digest::Digest;
                $crate::hasher::Digest::new(self.state.clone().finalize())
            }

            fn reset(&mut self) {
                use digest::Digest;
                self.state.reset();
            }
        }
    };
}

#[cfg(feature = "sha1")]
pub mod sha1 {
    use generic_array::typenum::U20;

    digest!(::sha1::Sha1, Sha1, U20);

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::hasher::Hasher;

        #[test]
        fn test_sha1() {
            let hash = Sha1::digest(b"hello world");
            let mut hasher = Sha1::default();
            hasher.update(b"hello world");
            let hash2 = hasher.finalize();
            assert_eq!(hash, hash2);
        }
    }
}

#[cfg(feature = "sha2")]
pub mod sha2 {
    use generic_array::typenum::{U32, U64};

    digest!(sha_2::Sha256, Sha2_256, U32);
    digest!(sha_2::Sha512, Sha2_512, U64);

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::hasher::Hasher;

        #[test]
        fn test_sha2_256() {
            let hash = Sha2_256::digest(b"hello world");
            let mut hasher = Sha2_256::default();
            hasher.update(b"hello world");
            let hash2 = hasher.finalize();
            assert_eq!(hash, hash2);
        }
    }
}

#[cfg(feature = "sha3")]
pub mod sha3 {
    use generic_array::typenum::{U28, U32, U48, U64};

    digest!(sha_3::Sha3_224, Sha3_224, U28);
    digest!(sha_3::Sha3_256, Sha3_256, U32);
    digest!(sha_3::Sha3_384, Sha3_384, U48);
    digest!(sha_3::Sha3_512, Sha3_512, U64);

    digest!(sha_3::Keccak224, Keccak224, U28);
    digest!(sha_3::Keccak256, Keccak256, U32);
    digest!(sha_3::Keccak384, Keccak384, U48);
    digest!(sha_3::Keccak512, Keccak512, U64);

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::hasher::Hasher;

        #[test]
        fn test_sha3_256() {
            let hash = Sha3_256::digest(b"hello world");
            let mut hasher = Sha3_256::default();
            hasher.update(b"hello world");
            let hash2 = hasher.finalize();
            assert_eq!(hash, hash2);
        }
    }
}

pub mod identity;

#[cfg(feature = "blake2b")]
pub mod blake2b;
#[cfg(feature = "blake2s")]
pub mod blake2s;
#[cfg(feature = "strobe")]
pub mod strobe;
