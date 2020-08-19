use crate::hasher::Hasher;
use crate::multihash::MultihashDigest;
use tiny_multihash_derive::Multihash;

/// Multihash code for Identity.
pub const IDENTITY: u64 = 0x00;
/// Multihash code for SHA1.
pub const SHA1: u64 = 0x11;
/// Multihash code for SHA2-256.
pub const SHA2_256: u64 = 0x12;
/// Multihash code for SHA2-512.
pub const SHA2_512: u64 = 0x13;
/// Multihash code for SHA3-224.
pub const SHA3_224: u64 = 0x17;
/// Multihash code for SHA3-256.
pub const SHA3_256: u64 = 0x16;
/// Multihash code for SHA3-384.
pub const SHA3_384: u64 = 0x15;
/// Multihash code for SHA3-512.
pub const SHA3_512: u64 = 0x14;
/// Multihash code for KECCAK-224.
pub const KECCAK_224: u64 = 0x1a;
/// Multihash code for KECCAK-256.
pub const KECCAK_256: u64 = 0x1b;
/// Multihash code for KECCAK-384.
pub const KECCAK_384: u64 = 0x1c;
/// Multihash code for KECCAK-512.
pub const KECCAK_512: u64 = 0x1d;
/// Multihash code for BLAKE2b-256.
pub const BLAKE2B_256: u64 = 0xb220;
/// Multihash code for BLAKE2b-512.
pub const BLAKE2B_512: u64 = 0xb240;
/// Multihash code for BLAKE2s-128.
pub const BLAKE2S_128: u64 = 0xb250;
/// Multihash code for BLAKE2s-256.
pub const BLAKE2S_256: u64 = 0xb260;
/// Multihash code for STROBE-256.
pub const STROBE_256: u64 = 0xa0;
/// Multihash code for STROBE-512.
pub const STROBE_512: u64 = 0xa1;

/// Default Multihash implementation.
///
/// This is a default set of hashing algorithms. Usually applications would use their own subset of
/// algorithms. See the [`Multihash` derive] for more information.
///
/// [`Multihash` derive]: crate::derive
#[derive(Clone, Debug, Eq, Multihash, PartialEq)]
pub enum Multihash {
    /// Multihash array for hash function.
    #[mh(code = self::IDENTITY, hasher = crate::Identity256)]
    Identity256(crate::IdentityDigest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = self::SHA1, hasher = crate::Sha1)]
    Sha1(crate::Sha1Digest<crate::U20>),
    /// Multihash array for hash function.
    #[mh(code = self::SHA2_256, hasher = crate::Sha2_256)]
    Sha2_256(crate::Sha2Digest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = self::SHA2_512, hasher = crate::Sha2_512)]
    Sha2_512(crate::Sha2Digest<crate::U64>),
    /// Multihash array for hash function.
    #[mh(code = self::SHA3_224, hasher = crate::Sha3_224)]
    Sha3_224(crate::Sha3Digest<crate::U28>),
    /// Multihash array for hash function.
    #[mh(code = self::SHA3_256, hasher = crate::Sha3_256)]
    Sha3_256(crate::Sha3Digest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = self::SHA3_384, hasher = crate::Sha3_384)]
    Sha3_384(crate::Sha3Digest<crate::U48>),
    /// Multihash array for hash function.
    #[mh(code = self::SHA3_512, hasher = crate::Sha3_512)]
    Sha3_512(crate::Sha3Digest<crate::U64>),
    /// Multihash array for hash function.
    #[mh(code = self::KECCAK_224, hasher = crate::Keccak224)]
    Keccak224(crate::KeccakDigest<crate::U28>),
    /// Multihash array for hash function.
    #[mh(code = self::KECCAK_256, hasher = crate::Keccak256)]
    Keccak256(crate::KeccakDigest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = self::KECCAK_384, hasher = crate::Keccak384)]
    Keccak384(crate::KeccakDigest<crate::U48>),
    /// Multihash array for hash function.
    #[mh(code = self::KECCAK_512, hasher = crate::Keccak512)]
    Keccak512(crate::KeccakDigest<crate::U64>),
    /// Multihash array for hash function.
    #[mh(code = self::BLAKE2B_256, hasher = crate::Blake2b256)]
    Blake2b256(crate::Blake2bDigest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = self::BLAKE2B_512, hasher = crate::Blake2b512)]
    Blake2b512(crate::Blake2bDigest<crate::U64>),
    /// Multihash array for hash function.
    #[mh(code = self::BLAKE2S_128, hasher = crate::Blake2s128)]
    Blake2s128(crate::Blake2sDigest<crate::U16>),
    /// Multihash array for hash function.
    #[mh(code = self::BLAKE2S_256, hasher = crate::Blake2s256)]
    Blake2s256(crate::Blake2sDigest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = self::STROBE_256, hasher = crate::Strobe256)]
    Strobe256(crate::StrobeDigest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = self::STROBE_512, hasher = crate::Strobe512)]
    Strobe512(crate::StrobeDigest<crate::U64>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Hasher;
    use crate::hasher_impl::strobe::{Strobe256, Strobe512};
    use crate::multihash::MultihashDigest;

    #[test]
    fn test_hasher_256() {
        let digest = Strobe256::digest(b"hello world");
        let hash = Multihash::from(digest.clone());
        let hash2 = Multihash::new(STROBE_256, b"hello world").unwrap();
        assert_eq!(hash.code(), STROBE_256);
        assert_eq!(hash.size(), 32);
        assert_eq!(hash.digest(), digest.as_ref());
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hasher_512() {
        let digest = Strobe512::digest(b"hello world");
        let hash = Multihash::from(digest.clone());
        let hash2 = Multihash::new(STROBE_512, b"hello world").unwrap();
        assert_eq!(hash.code(), STROBE_512);
        assert_eq!(hash.size(), 64);
        assert_eq!(hash.digest(), digest.as_ref());
        assert_eq!(hash, hash2);
    }
}
