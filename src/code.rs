use digest::{BlockInput, Digest, Input, Reset};
use multihash_derive::MultihashDigest;

use crate::digests::Multihash;
use crate::errors::Error;
use crate::multihash_digest::MultihashDigest;

#[derive(Clone, Debug, PartialEq, MultihashDigest)]
#[repr(u32)]
pub enum Code {
    #[Size = "20"]
    #[Digest = "sha1::Sha1"]
    Sha1 = 0x11,

    #[Size = "32"]
    #[Digest = "sha2::Sha256"]
    Sha2_256 = 0x12,

    #[Size = "64"]
    #[Digest = "sha2::Sha512"]
    Sha2_512 = 0x13,

    #[Size = "28"]
    #[Digest = "sha3::Sha3_224"]
    Sha3_224 = 0x17,

    #[Size = "32"]
    #[Digest = "sha3::Sha3_256"]
    Sha3_256 = 0x16,

    #[Size = "48"]
    #[Digest = "sha3::Sha3_384"]
    Sha3_384 = 0x15,

    #[Size = "64"]
    #[Digest = "sha3::Sha3_512"]
    Sha3_512 = 0x14,

    #[Size = "28"]
    #[Digest = "sha3::Keccak224"]
    Keccak224 = 0x1A,

    #[Size = "32"]
    #[Digest = "sha3::Keccak256"]
    Keccak256 = 0x1B,

    #[Size = "48"]
    #[Digest = "sha3::Keccak384"]
    Keccak384 = 0x1C,

    #[Size = "64"]
    #[Digest = "sha3::Keccak512"]
    Keccak512 = 0x1D,

    #[Size = "64"]
    #[Digest = "blake2::Blake2b"]
    Blake2b = 0xb240,

    #[Size = "32"]
    #[Digest = "blake2::Blake2s"]
    Blake2s = 0xb260,

    #[Size = "16"]
    #[Digest = "crate::fasthash::Murmur3_128X64"]
    Murmur3_128X64 = 0x22,

    #[Size = "4"]
    #[Digest = "crate::fasthash::Murmur3_32"]
    Murmur3_32 = 0x23,
}
