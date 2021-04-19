use multihash_derive::Multihash;

/// Default (cryptographically secure) Multihash implementation.
///
/// This is a default set of hashing algorithms. Usually applications would use their own subset of
/// algorithms. See the [`Multihash` derive] for more information.
///
/// [`Multihash` derive]: crate::derive
#[derive(Copy, Clone, Debug, Eq, Multihash, PartialEq)]
#[mh(alloc_size = crate::U64)]
pub enum Code {
    /// SHA-256 (32-byte hash size)
    #[cfg(feature = "sha2")]
    #[mh(code = 0x12, hasher = crate::Sha2_256, digest = crate::Sha2Digest<crate::U32>)]
    Sha2_256,
    /// SHA-512 (64-byte hash size)
    #[cfg(feature = "sha2")]
    #[mh(code = 0x13, hasher = crate::Sha2_512, digest = crate::Sha2Digest<crate::U64>)]
    Sha2_512,
    /// SHA3-224 (28-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x17, hasher = crate::Sha3_224, digest = crate::Sha3Digest<crate::U28>)]
    Sha3_224,
    /// SHA3-256 (32-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x16, hasher = crate::Sha3_256, digest = crate::Sha3Digest<crate::U32>)]
    Sha3_256,
    /// SHA3-384 (48-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x15, hasher = crate::Sha3_384, digest = crate::Sha3Digest<crate::U48>)]
    Sha3_384,
    /// SHA3-512 (64-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x14, hasher = crate::Sha3_512, digest = crate::Sha3Digest<crate::U64>)]
    Sha3_512,
    /// Keccak-224 (28-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x1a, hasher = crate::Keccak224, digest = crate::KeccakDigest<crate::U28>)]
    Keccak224,
    /// Keccak-256 (32-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x1b, hasher = crate::Keccak256, digest = crate::KeccakDigest<crate::U32>)]
    Keccak256,
    /// Keccak-384 (48-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x1c, hasher = crate::Keccak384, digest = crate::KeccakDigest<crate::U48>)]
    Keccak384,
    /// Keccak-512 (64-byte hash size)
    #[cfg(feature = "sha3")]
    #[mh(code = 0x1d, hasher = crate::Keccak512, digest = crate::KeccakDigest<crate::U64>)]
    Keccak512,
    /// BLAKE2b-256 (32-byte hash size)
    #[cfg(feature = "blake2b")]
    #[mh(code = 0xb220, hasher = crate::Blake2b256, digest = crate::Blake2bDigest<crate::U32>)]
    Blake2b256,
    /// BLAKE2b-512 (64-byte hash size)
    #[cfg(feature = "blake2b")]
    #[mh(code = 0xb240, hasher = crate::Blake2b512, digest = crate::Blake2bDigest<crate::U64>)]
    Blake2b512,
    /// BLAKE2s-128 (16-byte hash size)
    #[cfg(feature = "blake2s")]
    #[mh(code = 0xb250, hasher = crate::Blake2s128, digest = crate::Blake2sDigest<crate::U16>)]
    Blake2s128,
    /// BLAKE2s-256 (32-byte hash size)
    #[cfg(feature = "blake2s")]
    #[mh(code = 0xb260, hasher = crate::Blake2s256, digest = crate::Blake2sDigest<crate::U32>)]
    Blake2s256,
    /// BLAKE3-256 (32-byte hash size)
    #[cfg(feature = "blake3")]
    #[mh(code = 0x1e, hasher = crate::Blake3_256, digest = crate::Blake3Digest<crate::U32>)]
    Blake3_256,

    // The following hashes are not cryptographically secure hashes and are not enabled by default
    /// Identity hash (max. 64 bytes)
    #[cfg(feature = "identity")]
    #[mh(code = 0x00, hasher = crate::IdentityHasher::<crate::U64>, digest = crate::IdentityDigest<crate::U64>)]
    Identity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Hasher;
    use crate::hasher_impl::sha3::{Sha3_256, Sha3_512};
    use crate::multihash::MultihashDigest;

    #[test]
    fn test_hasher_256() {
        let digest = Sha3_256::digest(b"hello world");
        let hash = Code::multihash_from_digest(&digest);
        let hash2 = Code::Sha3_256.digest(b"hello world");
        assert_eq!(hash.code(), u64::from(Code::Sha3_256));
        assert_eq!(hash.size(), 32);
        assert_eq!(hash.digest(), digest.as_ref());
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hasher_512() {
        let digest = Sha3_512::digest(b"hello world");
        let hash = Code::multihash_from_digest(&digest);
        let hash2 = Code::Sha3_512.digest(b"hello world");
        assert_eq!(hash.code(), u64::from(Code::Sha3_512));
        assert_eq!(hash.size(), 64);
        assert_eq!(hash.digest(), digest.as_ref());
        assert_eq!(hash, hash2);
    }
}
