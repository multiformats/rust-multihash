use blake2b_simd::Params as Blake2b;
use blake2s_simd::Params as Blake2s;
use digest::Digest;
use sha1::Sha1 as Sha1Hasher;
use sha2::{Sha256, Sha512};
use tiny_keccak::{Hasher, Keccak, Sha3};

use crate::digests::{wrap, Multihash, MultihashDigest};

#[derive(Clone, Debug, PartialEq)]
pub enum Code {
    /// Identity (Raw binary )
    Identity,
    /// SHA-1 (20-byte hash size)
    Sha1,
    /// SHA-256 (32-byte hash size)
    Sha2_256,
    /// SHA-512 (64-byte hash size)
    Sha2_512,
    /// SHA3-224 (28-byte hash size)
    Sha3_224,
    /// SHA3-256 (32-byte hash size)
    Sha3_256,
    /// SHA3-384 (48-byte hash size)
    Sha3_384,
    /// SHA3-512 (64-byte hash size)
    Sha3_512,
    /// Keccak-224 (28-byte hash size)
    Keccak224,
    /// Keccak-256 (32-byte hash size)
    Keccak256,
    /// Keccak-384 (48-byte hash size)
    Keccak384,
    /// Keccak-512 (64-byte hash size)
    Keccak512,
    /// BLAKE2b-256 (32-byte hash size)
    Blake2b256,
    /// BLAKE2b-512 (64-byte hash size)
    Blake2b512,
    /// BLAKE2s-128 (16-byte hash size)
    Blake2s128,
    /// BLAKE2s-256 (32-byte hash size)
    Blake2s256,
    /// Make it possible to use a custom code that is not part of the enum yet
    Custom(u64),
}

impl Code {
    /// Return the code as integer value.
    pub fn to_u64(&self) -> u64 {
        match *self {
            Self::Custom(code) => code,
            Self::Identity => 0x00,
            Self::Sha1 => 0x11,
            Self::Sha2_256 => 0x12,
            Self::Sha2_512 => 0x13,
            Self::Sha3_224 => 0x17,
            Self::Sha3_256 => 0x16,
            Self::Sha3_384 => 0x15,
            Self::Sha3_512 => 0x14,
            Self::Keccak224 => 0x1a,
            Self::Keccak256 => 0x1b,
            Self::Keccak384 => 0x1c,
            Self::Keccak512 => 0x1d,
            Self::Blake2b256 => 0xb220,
            Self::Blake2b512 => 0xb240,
            Self::Blake2s128 => 0xb250,
            Self::Blake2s256 => 0xb260,
        }
    }

    /// Return the `Code` based on the integer value. If the code is unknown/not implemented yet
    /// then it returns a `Code::Custom`.
    /// implementes with that value.
    pub fn from_u64(code: u64) -> Self {
        match code {
            0x00 => Code::Identity,
            0x11 => Code::Sha1,
            0x12 => Code::Sha2_256,
            0x13 => Code::Sha2_512,
            0x14 => Code::Sha3_512,
            0x15 => Code::Sha3_384,
            0x16 => Code::Sha3_256,
            0x17 => Code::Sha3_224,
            0x1A => Code::Keccak224,
            0x1B => Code::Keccak256,
            0x1C => Code::Keccak384,
            0x1D => Code::Keccak512,
            0xB220 => Code::Blake2b256,
            0xB240 => Code::Blake2b512,
            0xB250 => Code::Blake2s128,
            0xB260 => Code::Blake2s256,
            _ => Code::Custom(code),
        }
    }

    /// Return the hasher that is used to create a hash with this code.
    ///
    /// If a custom code is used, `None` is returned.
    pub fn hasher(&self) -> Option<Box<dyn MultihashDigest>> {
        match *self {
            Self::Custom(_) => None,
            Self::Identity => Some(Box::new(Identity)),
            Self::Sha1 => Some(Box::new(Sha1)),
            Self::Sha2_256 => Some(Box::new(Sha2_256)),
            Self::Sha2_512 => Some(Box::new(Sha2_512)),
            Self::Sha3_224 => Some(Box::new(Sha3_224)),
            Self::Sha3_256 => Some(Box::new(Sha3_256)),
            Self::Sha3_384 => Some(Box::new(Sha3_384)),
            Self::Sha3_512 => Some(Box::new(Sha3_512)),
            Self::Keccak224 => Some(Box::new(Keccak224)),
            Self::Keccak256 => Some(Box::new(Keccak256)),
            Self::Keccak384 => Some(Box::new(Keccak384)),
            Self::Keccak512 => Some(Box::new(Keccak512)),
            Self::Blake2b256 => Some(Box::new(Blake2b256)),
            Self::Blake2b512 => Some(Box::new(Blake2b512)),
            Self::Blake2s128 => Some(Box::new(Blake2s128)),
            Self::Blake2s256 => Some(Box::new(Blake2s256)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Identity;
impl MultihashDigest for Identity {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Identity {
    pub const CODE: Code = Code::Identity;
    pub fn digest(data: &[u8]) -> Multihash {
        if (data.len() as u64) >= u64::from(std::u32::MAX) {
            panic!("Input data for identity hash is too large, it needs to be less the 2^32.")
        }
        wrap(&Self::CODE, &data)
    }
}

#[derive(Clone, Debug)]
pub struct Sha1;
impl MultihashDigest for Sha1 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Sha1 {
    pub const CODE: Code = Code::Sha1;
    pub fn digest(data: &[u8]) -> Multihash {
        let digest = Sha1Hasher::from(&data).digest().bytes();
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha2_256;
impl MultihashDigest for Sha2_256 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Sha2_256 {
    pub const CODE: Code = Code::Sha2_256;
    pub fn digest(data: &[u8]) -> Multihash {
        let digest = Sha256::digest(&data);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha2_512;
impl MultihashDigest for Sha2_512 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Sha2_512 {
    pub const CODE: Code = Code::Sha2_512;
    pub fn digest(data: &[u8]) -> Multihash {
        let digest = Sha512::digest(&data);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha3_224;
impl MultihashDigest for Sha3_224 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Sha3_224 {
    pub const CODE: Code = Code::Sha3_224;
    pub fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 28];
        let mut sha3 = Sha3::v224();
        sha3.update(&data);
        sha3.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha3_256;
impl MultihashDigest for Sha3_256 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Sha3_256 {
    pub const CODE: Code = Code::Sha3_256;
    pub fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 32];
        let mut sha3 = Sha3::v256();
        sha3.update(&data);
        sha3.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha3_384;
impl MultihashDigest for Sha3_384 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Sha3_384 {
    pub const CODE: Code = Code::Sha3_384;
    pub fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 48];
        let mut sha3 = Sha3::v384();
        sha3.update(&data);
        sha3.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha3_512;
impl MultihashDigest for Sha3_512 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Sha3_512 {
    pub const CODE: Code = Code::Sha3_512;
    pub fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 64];
        let mut sha3 = Sha3::v512();
        sha3.update(&data);
        sha3.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Keccak224;
impl MultihashDigest for Keccak224 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Keccak224 {
    pub const CODE: Code = Code::Keccak224;
    pub fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 28];
        let mut keccak = Keccak::v224();
        keccak.update(&data);
        keccak.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Keccak256;
impl MultihashDigest for Keccak256 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Keccak256 {
    pub const CODE: Code = Code::Keccak256;
    pub fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 32];
        let mut keccak = Keccak::v256();
        keccak.update(&data);
        keccak.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Keccak384;
impl MultihashDigest for Keccak384 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Keccak384 {
    pub const CODE: Code = Code::Keccak384;
    pub fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 48];
        let mut keccak = Keccak::v384();
        keccak.update(&data);
        keccak.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Keccak512;
impl MultihashDigest for Keccak512 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Keccak512 {
    pub const CODE: Code = Code::Keccak512;
    pub fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 64];
        let mut keccak = Keccak::v512();
        keccak.update(&data);
        keccak.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Blake2b256;
impl MultihashDigest for Blake2b256 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Blake2b256 {
    pub const CODE: Code = Code::Blake2b256;
    pub fn digest(data: &[u8]) -> Multihash {
        let digest = Blake2b::new()
            .hash_length(32)
            .to_state()
            .update(&data)
            .finalize();
        wrap(&Self::CODE, &digest.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Blake2b512;
impl MultihashDigest for Blake2b512 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Blake2b512 {
    pub const CODE: Code = Code::Blake2b512;
    pub fn digest(data: &[u8]) -> Multihash {
        let digest = Blake2b::new()
            .hash_length(64)
            .to_state()
            .update(&data)
            .finalize();
        wrap(&Self::CODE, &digest.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Blake2s128;
impl MultihashDigest for Blake2s128 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Blake2s128 {
    pub const CODE: Code = Code::Blake2s128;
    pub fn digest(data: &[u8]) -> Multihash {
        let digest = Blake2s::new()
            .hash_length(16)
            .to_state()
            .update(&data)
            .finalize();
        wrap(&Self::CODE, &digest.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Blake2s256;
impl MultihashDigest for Blake2s256 {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}
impl Blake2s256 {
    pub const CODE: Code = Code::Blake2s256;
    pub fn digest(data: &[u8]) -> Multihash {
        let digest = Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(&data)
            .finalize();
        wrap(&Self::CODE, &digest.as_bytes())
    }
}
