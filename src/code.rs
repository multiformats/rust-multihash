use multihash_proc_macro::Multihash;

/// Default code enum.
#[derive(Clone, Copy, Debug, Eq, Hash, Multihash, PartialEq)]
pub enum Code {
    /// Identity (32-byte size)
    #[mh(code = 0x00, module = crate::Identity256)]
    Identity256,
    /// SHA-1 (20-byte hash size)
    #[cfg(feature = "sha1")]
    #[mh(code = 0x11, module = crate::Sha1)]
    Sha1,
    /// SHA-256 (32-byte hash size)
    #[cfg(feature = "sha2")]
    #[mh(code = 0x12, module = crate::Sha2_256)]
    Sha2_256,
    /// SHA-512 (64-byte hash size)
    #[cfg(feature = "sha2")]
    #[mh(code = 0x13, module = crate::Sha2_512)]
    Sha2_512,
    /// SHA3-224 (28-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x17, module = crate::Sha3_224)]
    Sha3_224,
    /// SHA3-256 (32-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x16, module = crate::Sha3_256)]
    Sha3_256,
    /// SHA3-384 (48-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x15, module = crate::Sha3_384)]
    Sha3_384,
    /// SHA3-512 (64-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x14, module = crate::Sha3_512)]
    Sha3_512,
    /// Keccak-224 (28-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x1a, module = crate::Keccak224)]
    Keccak224,
    /// Keccak-256 (32-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x1b, module = crate::Keccak256)]
    Keccak256,
    /// Keccak-384 (48-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x1c, module = crate::Keccak384)]
    Keccak384,
    /// Keccak-512 (64-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x1d, module = crate::Keccak512)]
    Keccak512,
    /// BLAKE2b-256 (32-byte hash size)
    #[cfg(feature = "blake2b")]
    #[mh(code = 0xb220, module = crate::Blake2b256)]
    Blake2b256,
    /// BLAKE2b-512 (64-byte hash size)
    #[cfg(feature = "blake2b")]
    #[mh(code = 0xb240, module = crate::Blake2b512)]
    Blake2b512,
    /// BLAKE2s-128 (16-byte hash size)
    #[cfg(feature = "blake2s")]
    #[mh(code = 0xb250, module = crate::Blake2s128)]
    Blake2s128,
    /// BLAKE2s-256 (32-byte hash size)
    #[cfg(feature = "blake2s")]
    #[mh(code = 0xb260, module = crate::Blake2s256)]
    Blake2s256,
    /// Strobe 256 (32-byte hash size)
    #[cfg(feature = "strobe")]
    #[mh(code = 0xa0, module = crate::Strobe256)]
    Strobe256,
    /// Strobe 512 (64-byte hash size)
    #[cfg(feature = "strobe")]
    #[mh(code = 0xa1, module = crate::Strobe512)]
    Strobe512,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Hasher;
    use crate::hasher_impl::strobe::{Strobe256, Strobe512};
    use crate::multihash::{MultihashCode, MultihashDigest};

    #[test]
    fn test_hasher_256() {
        let digest = Strobe256::digest(b"hello world");
        let hash = Multihash::from(digest.clone());
        let hash2 = Code::Strobe256.digest(b"hello world");
        assert_eq!(hash.code(), Code::Strobe256);
        assert_eq!(hash.size(), 32);
        assert_eq!(hash.digest(), digest.as_ref());
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hasher_512() {
        let digest = Strobe512::digest(b"hello world");
        let hash = Multihash::from(digest.clone());
        let hash2 = Code::Strobe512.digest(b"hello world");
        assert_eq!(hash.code(), Code::Strobe512);
        assert_eq!(hash.size(), 64);
        assert_eq!(hash.digest(), digest.as_ref());
        assert_eq!(hash, hash2);
    }
}
